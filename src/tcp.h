/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_TCP_H
#define JUICE_TCP_H

#include "addr.h"
#include "juice.h"
#include "socket.h"
#include "timestamp.h"
#include "tls_schannel.h"

typedef enum tcp_state {
	TCP_STATE_DISCONNECTED,
	TCP_STATE_CONNECTING,
	TCP_STATE_TLS_HANDSHAKING,
	TCP_STATE_CONNECTED,
	TCP_STATE_FAILED
} tcp_state_t;

// Limit for the TCP connect plus any TLS handshake, as a silent peer triggers no socket event
#define TCP_CONNECT_TIMEOUT 8000 // msecs

socket_t tcp_create_socket(const addr_record_t *dst);

// Same as BUFFER_SIZE in agent.c and conn_poll.c, so anything the UDP relay path carries fits
#define TCP_BUFFER_SIZE 4096

// Room for a TLS record header and trailer around a full buffer (AES-GCM needs about 29 bytes)
#define TLS_RECORD_OVERHEAD_RESERVE 128
#define TCP_CONTEXT_BUFFER_SIZE (TCP_BUFFER_SIZE + TLS_RECORD_OVERHEAD_RESERVE)

// Header sizes; bytes 2-3 hold the length of what follows the header in both
#define STUN_HEADER_SIZE 20
#define CHANNEL_DATA_HEADER_SIZE 4

typedef struct tcp_write_context {
	char buffer[TCP_CONTEXT_BUFFER_SIZE];
	uint16_t length;      // plaintext size, returned to the caller on completion
	uint16_t send_length; // bytes actually on the wire: == length, or the TLS ciphertext size
	uint16_t bytes_written;
	bool pending;
} tcp_write_context_t;

typedef struct tcp_read_context {
	char buffer[TCP_BUFFER_SIZE];
	// Full message length, which can exceed 16 bits; bytes past TCP_BUFFER_SIZE are discarded
	uint32_t length;
	uint32_t bytes_read; // 0 if finished
	uint16_t header; // 2-byte length prefix (ICE framing only)
	bool pending;
} tcp_read_context_t;

// 2-byte length prefix used for ICE-TCP
int tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context);
int tcp_ice_read(socket_t sock, tcp_read_context_t *context);

// Self-delimiting STUN/ChannelData framing for TURN-TCP, over TLS (TURNS) when tls is set
int tcp_stun_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context,
                   tls_client_t *tls);
int tcp_stun_read(socket_t sock, tcp_read_context_t *context, tls_client_t *tls);

typedef enum tcp_framing {
	TCP_FRAMING_ICE,      // 2-byte length prefix (ICE-TCP)
	TCP_FRAMING_STUN,     // self-delimiting STUN/ChannelData (TURN-TCP)
	TCP_FRAMING_STUN_TLS, // self-delimiting STUN/ChannelData over TLS (TURNS)
} tcp_framing_t;

typedef struct tcp_conn {
	socket_t sock;
	tcp_framing_t framing;
	tcp_write_context_t write;
	tcp_read_context_t read;
	addr_record_t dst;
	tcp_state_t state;
	tls_client_t *tls; // NULL unless framing == TCP_FRAMING_STUN_TLS
	timestamp_t connect_deadline; // valid while state is CONNECTING or TLS_HANDSHAKING
	bool read_pending;
} tcp_conn_t;

const char *tcp_state_to_string(tcp_state_t state);
const char *tcp_framing_to_string(tcp_framing_t framing);
void tcp_conn_init(tcp_conn_t *tc, tcp_framing_t framing);
void tcp_conn_reset(tcp_conn_t *tc);

// Send a message, or continue a pending one if data is NULL, with the connection's framing
int tcp_conn_write(tcp_conn_t *tc, const char *data, size_t size);
// Read the next message into tc->read.buffer with the connection's framing
int tcp_conn_read(tcp_conn_t *tc);

// Export for tests
JUICE_EXPORT void _juice_tcp_conn_init(tcp_conn_t *tc, tcp_framing_t framing);
JUICE_EXPORT int _juice_tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context);
JUICE_EXPORT int _juice_tcp_ice_read(socket_t sock, tcp_read_context_t *context);
JUICE_EXPORT int _juice_tcp_stun_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context);
JUICE_EXPORT int _juice_tcp_stun_read(socket_t sock, tcp_read_context_t *context);

#endif
