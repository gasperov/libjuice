/**
 * Copyright (c) 2022 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "conn_thread.h"
#include "agent.h"
#include "log.h"
#include "socket.h"
#include "tcp.h"
#include "thread.h"
#include "udp.h"

#include <assert.h>
#include <string.h>

#define BUFFER_SIZE 4096

typedef struct conn_impl {
	thread_t thread;
	socket_t sock;
	tcp_conn_t turn_tcp;
	mutex_t mutex;
	mutex_t send_mutex;
	int send_ds;
	timestamp_t next_timestamp;
	bool stopped;
} conn_impl_t;

typedef void (*tcp_on_state_change_t)(juice_agent_t *agent, tcp_conn_t *tc, tcp_state_t state);

static void change_tcp_conn_state(juice_agent_t *agent, tcp_conn_t *tc,
                                  tcp_state_t state, const char *label,
                                  tcp_on_state_change_t on_change) {
	if (tc->state != state) {
		JLOG_INFO("%s state changed to %s", label, tcp_state_to_string(state));
		tc->state = state;
		if (on_change)
			on_change(agent, tc, state);
	}
}

static void change_tcp_conn_fail(juice_agent_t *agent, tcp_conn_t *tc,
                                 const char *label, tcp_on_state_change_t on_change) {
	JLOG_INFO("%s connection closing socket and marking failed", label);
	if (tc->sock != INVALID_SOCKET) {
		closesocket(tc->sock);
		tc->sock = INVALID_SOCKET;
	}
	memset(&tc->write_context, 0, sizeof(tcp_ice_write_context_t));
	memset(&tc->read_context, 0, sizeof(tcp_ice_read_context_t));
	memset(&tc->stun_write_context, 0, sizeof(tcp_stun_write_context_t));
	memset(&tc->stun_read_context, 0, sizeof(tcp_stun_read_context_t));
	change_tcp_conn_state(agent, tc, TCP_STATE_FAILED, label, on_change);
}

static void turn_tcp_on_state_change(juice_agent_t *agent, tcp_conn_t *tc, tcp_state_t state) {
	(void)tc;
	JLOG_INFO("TURN TCP on_state_change callback: state=%s", tcp_state_to_string(state));
	if (state == TCP_STATE_CONNECTED || state == TCP_STATE_FAILED) {
		conn_impl_t *conn_impl = agent->conn_impl;
		conn_impl->next_timestamp = current_timestamp();
		JLOG_INFO("TURN TCP re-armed next_timestamp for bookkeeping");
	}
}

static void tcp_conn_connect(juice_agent_t *agent, tcp_conn_t *tc,
                             const addr_record_t *dst, const char *label,
                             bool override_socktype_dgram,
                             tcp_on_state_change_t on_change) {
	if (tc->sock == INVALID_SOCKET) {
		char dst_str[ADDR_MAX_STRING_LEN];
		addr_record_to_string(dst, dst_str, ADDR_MAX_STRING_LEN);
		JLOG_INFO("Attempting %s connection to %s", label, dst_str);
		tc->sock = tcp_create_socket(dst);
		if (tc->sock == INVALID_SOCKET) {
			JLOG_WARN("%s socket creation failed for %s", label, dst_str);
			return;
		}
		memcpy(&tc->dst, dst, sizeof(tc->dst));
		if (override_socktype_dgram)
			tc->dst.socktype = SOCK_DGRAM;
		change_tcp_conn_state(agent, tc, TCP_STATE_CONNECTING, label, on_change);
	}
}

int conn_thread_run(juice_agent_t *agent);
int conn_thread_prepare(juice_agent_t *agent, struct pollfd *pfd, int pfd_size, timestamp_t *next_timestamp);
int conn_thread_process(juice_agent_t *agent, struct pollfd *pfd, int pfd_count);
int conn_thread_recv(socket_t sock, char *buffer, size_t size, addr_record_t *src);

static thread_return_t THREAD_CALL conn_thread_entry(void *arg) {
	thread_set_name_self("juice agent");
	juice_agent_t *agent = (juice_agent_t *)arg;
	conn_thread_run(agent);
	return (thread_return_t)0;
}

int conn_thread_prepare(juice_agent_t *agent, struct pollfd *pfd, int pfd_size, timestamp_t *next_timestamp) {
	conn_impl_t *conn_impl = agent->conn_impl;
	mutex_lock(&conn_impl->mutex);
	if (conn_impl->stopped) {
		mutex_unlock(&conn_impl->mutex);
		return 0;
	}

	int count = 0;
	pfd[count].fd = conn_impl->sock;
	pfd[count].events = POLLIN;
	count++;

	if (conn_impl->turn_tcp.sock != INVALID_SOCKET && count < pfd_size) {
		pfd[count].fd = conn_impl->turn_tcp.sock;
		if (conn_impl->turn_tcp.state == TCP_STATE_CONNECTING) {
			pfd[count].events = POLLOUT;
		} else {
			pfd[count].events = POLLIN;
			if(conn_impl->turn_tcp.stun_write_context.pending)
				pfd[count].events |= POLLOUT;
		}
		count++;
	}

	*next_timestamp = conn_impl->next_timestamp;

	mutex_unlock(&conn_impl->mutex);
	return count;
}

int conn_thread_process(juice_agent_t *agent, struct pollfd *pfd, int pfd_count) {
	conn_impl_t *conn_impl = agent->conn_impl;
	mutex_lock(&conn_impl->mutex);
	if (conn_impl->stopped) {
		mutex_unlock(&conn_impl->mutex);
		return -1;
	}

	// Process UDP socket
	if (pfd[0].revents & POLLNVAL || pfd[0].revents & POLLERR) {
		JLOG_ERROR("Error when polling socket");
		agent_conn_fail(agent);
		mutex_unlock(&conn_impl->mutex);
		return -1;
	}

	bool did_receive = false;

	if (pfd[0].revents & POLLIN) {
		char buffer[BUFFER_SIZE];
		addr_record_t src;
		int ret;
		while ((ret = conn_thread_recv(conn_impl->sock, buffer, BUFFER_SIZE, &src)) > 0) {
			if (agent_conn_recv(agent, buffer, (size_t)ret, &src) != 0) {
				JLOG_WARN("Agent receive failed");
				mutex_unlock(&conn_impl->mutex);
				return -1;
			}
		}

		if (ret < 0) {
			agent_conn_fail(agent);
			mutex_unlock(&conn_impl->mutex);
			return -1;
		}

		did_receive = true;
	}

	// Process TURN TCP socket
	if (pfd_count > 1 && conn_impl->turn_tcp.sock != INVALID_SOCKET) {
		struct pollfd *turn_tcp_pfd = &pfd[1];

		if (turn_tcp_pfd->revents & POLLNVAL) {
			JLOG_WARN("Invalid TURN TCP socket");
		} else if (turn_tcp_pfd->revents & POLLERR ||
		           (turn_tcp_pfd->revents & POLLHUP && !(turn_tcp_pfd->revents & POLLIN))) {
			JLOG_INFO("TURN TCP connection got POLLERR/POLLHUP (revents=0x%x)", turn_tcp_pfd->revents);
			change_tcp_conn_fail(agent, &conn_impl->turn_tcp, "TURN TCP", turn_tcp_on_state_change);
		} else {
			if (turn_tcp_pfd->revents & POLLOUT) {
				if (conn_impl->turn_tcp.state == TCP_STATE_CONNECTING) {
					int err = 0;
					socklen_t errlen = sizeof(err);
					if (getsockopt(conn_impl->turn_tcp.sock, SOL_SOCKET, SO_ERROR,
					               (char *)&err, &errlen) != 0 || err != 0) {
						JLOG_INFO("TURN TCP connection failed on SO_ERROR, errno=%d", err);
						change_tcp_conn_fail(agent, &conn_impl->turn_tcp, "TURN TCP", turn_tcp_on_state_change);
					} else {
						BOOL bDelay = FALSE; // FALSE disables Nagle (enables NODELAY)
						setsockopt(conn_impl->turn_tcp.sock, IPPROTO_TCP, TCP_NODELAY, (char*)&bDelay, sizeof(BOOL));

						JLOG_INFO("TURN TCP connection established (POLLOUT with no error)");
						change_tcp_conn_state(agent, &conn_impl->turn_tcp, TCP_STATE_CONNECTED, "TURN TCP", turn_tcp_on_state_change);
					}
				} else {
					tcp_stun_write_context_t *context = &conn_impl->turn_tcp.stun_write_context;
					if(context->pending) {
						int ret = tcp_stun_write(conn_impl->turn_tcp.sock, NULL, 0, context);
						if (ret < 0 && ret != -SEAGAIN && ret != -SEWOULDBLOCK) {
							JLOG_WARN("TURN TCP send failed, errno=%d", -ret);
							change_tcp_conn_fail(agent, &conn_impl->turn_tcp, "TURN TCP", turn_tcp_on_state_change);
						}
					}
				}
			}

			if (turn_tcp_pfd->revents & POLLIN) {
				int ret = 0;
				int left = 1000;
				while (left--) {
					tcp_stun_read_context_t *context = &conn_impl->turn_tcp.stun_read_context;
					if ((ret = tcp_stun_read(conn_impl->turn_tcp.sock, context)) < 0) {
						break;
					}

					if (agent_conn_recv(agent, context->buffer, (size_t)ret,
					                    &conn_impl->turn_tcp.dst) != 0) {
						JLOG_WARN("Agent receive failed");
						mutex_unlock(&conn_impl->mutex);
						return -1;
					}
				}

				if (ret == -SEAGAIN || ret == -SEWOULDBLOCK) {
					JLOG_VERBOSE("No more TURN TCP datagrams to receive");
				} else if (ret <= 0) {
					if (ret == 0) JLOG_DEBUG("TURN TCP connection closed");
					else JLOG_DEBUG("TURN TCP connection failed");
					change_tcp_conn_fail(agent, &conn_impl->turn_tcp, "TURN TCP", turn_tcp_on_state_change);
				}

				did_receive = true;
			}
		}
	}

	if (did_receive) {
		if (agent_conn_update(agent, &conn_impl->next_timestamp) != 0) {
			JLOG_WARN("Agent update failed");
			mutex_unlock(&conn_impl->mutex);
			return -1;
		}
	} else if (conn_impl->next_timestamp <= current_timestamp()) {
		if (agent_conn_update(agent, &conn_impl->next_timestamp) != 0) {
			JLOG_WARN("Agent update failed");
			mutex_unlock(&conn_impl->mutex);
			return -1;
		}
	}

	mutex_unlock(&conn_impl->mutex);
	return 0;
}

int conn_thread_recv(socket_t sock, char *buffer, size_t size, addr_record_t *src) {
	JLOG_VERBOSE("Receiving datagram");
	int len;
	while ((len = udp_recvfrom(sock, buffer, size, src)) == 0) {
		// Empty datagram (used to interrupt)
	}

	if (len < 0) {
		if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK) {
			JLOG_VERBOSE("No more datagrams to receive");
			return 0;
		}
		JLOG_ERROR("recvfrom failed, errno=%d", sockerrno);
		return -1;
	}

	addr_unmap_inet6_v4mapped((struct sockaddr *)&src->addr, &src->len);
	return len; // len > 0
}

int conn_thread_run(juice_agent_t *agent) {
	struct pollfd pfd[2]; // UDP + optional TURN TCP
	timestamp_t next_timestamp;
	int pfd_count;
	while ((pfd_count = conn_thread_prepare(agent, pfd, 2, &next_timestamp)) > 0) {
		timediff_t timediff = next_timestamp - current_timestamp();
		if (timediff < 0)
			timediff = 0;

		JLOG_VERBOSE("Entering poll on %d sockets for %d ms", pfd_count, (int)timediff);
		int ret = poll(pfd, (nfds_t)pfd_count, (int)timediff);
		JLOG_VERBOSE("Leaving poll");
		if (ret < 0) {
			if (sockerrno == SEINTR || sockerrno == SEAGAIN) {
				JLOG_VERBOSE("poll interrupted");
				continue;
			} else {
				JLOG_FATAL("poll failed, errno=%d", sockerrno);
				break;
			}
		}

		if (conn_thread_process(agent, pfd, pfd_count) < 0)
			break;
	}

	JLOG_DEBUG("Leaving connection thread");
	return 0;
}

int conn_thread_init(juice_agent_t *agent, conn_registry_t *registry, udp_socket_config_t *config) {
	(void)registry;

	conn_impl_t *conn_impl = calloc(1, sizeof(conn_impl_t));
	if (!conn_impl) {
		JLOG_FATAL("Memory allocation failed for connection impl");
		return -1;
	}

	conn_impl->sock = udp_create_socket(config);
	if (conn_impl->sock == INVALID_SOCKET) {
		JLOG_ERROR("UDP socket creation failed");
		free(conn_impl);
		return -1;
	}

	tcp_conn_init(&conn_impl->turn_tcp);

	mutex_init(&conn_impl->mutex, MUTEX_RECURSIVE); // Recursive to allow calls from user callbacks
	mutex_init(&conn_impl->send_mutex, 0);

	agent->conn_impl = conn_impl;

	JLOG_DEBUG("Starting connection thread");
	int ret = thread_init(&conn_impl->thread, conn_thread_entry, agent);
	if (ret) {
		JLOG_FATAL("Thread creation failed, error=%d", ret);
		free(conn_impl);
		agent->conn_impl = NULL;
		return -1;
	}

	return 0;
}

void conn_thread_cleanup(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;

	mutex_lock(&conn_impl->mutex);
	conn_impl->stopped = true;
	mutex_unlock(&conn_impl->mutex);

	conn_thread_interrupt(agent);

	JLOG_VERBOSE("Waiting for connection thread");
	thread_join(conn_impl->thread, NULL);

	closesocket(conn_impl->sock);
	if (conn_impl->turn_tcp.sock != INVALID_SOCKET)
		closesocket(conn_impl->turn_tcp.sock);
	mutex_destroy(&conn_impl->mutex);
	mutex_destroy(&conn_impl->send_mutex);
	free(agent->conn_impl);
	agent->conn_impl = NULL;
}

void conn_thread_lock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	mutex_lock(&conn_impl->mutex);
}

void conn_thread_unlock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	mutex_unlock(&conn_impl->mutex);
}

int conn_thread_interrupt(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;

	mutex_lock(&conn_impl->mutex);
	conn_impl->next_timestamp = current_timestamp();
	mutex_unlock(&conn_impl->mutex);

	JLOG_VERBOSE("Interrupting connection thread");

	mutex_lock(&conn_impl->send_mutex);
	char dummy = 0; // Some C libraries might error out on NULL pointers
	if (udp_sendto_self(conn_impl->sock, &dummy, 0) < 0) {
		if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK) {
			JLOG_WARN("Failed to interrupt poll by triggering socket, errno=%d", sockerrno);
		}
		mutex_unlock(&conn_impl->send_mutex);
		return -1;
	}

	mutex_unlock(&conn_impl->send_mutex);
	return 0;
}

int conn_thread_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
                     int ds, bool use_turn_tcp) {
	conn_impl_t *conn_impl = agent->conn_impl;

	if (use_turn_tcp) {
		mutex_lock(&conn_impl->send_mutex);

		if (conn_impl->turn_tcp.state != TCP_STATE_CONNECTED) {
			mutex_unlock(&conn_impl->send_mutex);
			return -SEAGAIN;
		}

		JLOG_VERBOSE("Sending STUN message via TURN TCP, size=%d", (int)size);

		int ret;
		tcp_stun_write_context_t *context = &conn_impl->turn_tcp.stun_write_context;
		if (!context->pending) {
			ret = tcp_stun_write(conn_impl->turn_tcp.sock, data, size, context);
			if (context->pending && (ret == SEAGAIN || ret == SEWOULDBLOCK))
				ret = (int)size; // message is buffered, consider it sent
		} else {
			// another message is buffered, drop
			ret = -SEAGAIN;
		}

		if (ret < 0) {
			if (ret == -SEAGAIN || ret == -SEWOULDBLOCK)
				JLOG_INFO("TURN TCP send failed, buffer is full");
			else
				JLOG_WARN("TURN TCP send failed, errno=%d", -ret);
		}

		mutex_unlock(&conn_impl->send_mutex);
		return ret;
	}

	mutex_lock(&conn_impl->send_mutex);

	if (conn_impl->send_ds >= 0 && conn_impl->send_ds != ds) {
		JLOG_VERBOSE("Setting Differentiated Services field to 0x%X", ds);
		if (udp_set_diffserv(conn_impl->sock, ds) == 0)
			conn_impl->send_ds = ds;
		else
			conn_impl->send_ds = -1; // disable for next time
	}

	JLOG_VERBOSE("Sending datagram, size=%d", size);

	int ret = udp_sendto(conn_impl->sock, data, size, dst);
	if (ret < 0) {
		ret = -sockerrno;
		if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
			JLOG_INFO("Send failed, buffer is full");
		else if (sockerrno == SEMSGSIZE)
			JLOG_WARN("Send failed, datagram is too large");
		else
			JLOG_WARN("Send failed, errno=%d", sockerrno);
	}

	mutex_unlock(&conn_impl->send_mutex);
	return ret;
}

int conn_thread_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	conn_impl_t *conn_impl = agent->conn_impl;

	return udp_get_addrs(conn_impl->sock, records, size);
}

void conn_thread_turn_tcp_connect(juice_agent_t *agent, const addr_record_t *dst) {
	conn_impl_t *conn_impl = agent->conn_impl;

	mutex_lock(&conn_impl->mutex);
	mutex_lock(&conn_impl->send_mutex);
	tcp_conn_connect(agent, &conn_impl->turn_tcp, dst, "TURN TCP", true, turn_tcp_on_state_change);
	mutex_unlock(&conn_impl->send_mutex);
	mutex_unlock(&conn_impl->mutex);
}

bool conn_thread_turn_tcp_connected(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	return conn_impl->turn_tcp.state == TCP_STATE_CONNECTED;
}
