/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
#else
#include <unistd.h> // for sleep
#endif

typedef struct peer {
	const char *name;
	juice_agent_t *agent;
	struct peer *remote;
	bool sent;
	bool received;
	bool destroyed;
	int late_callbacks; // callbacks after juice_destroy() returned, must stay 0
} peer_t;

static peer_t peer1;
static peer_t peer2;

static void destroy_if_done(peer_t *peer, juice_agent_t *agent) {
	if (!peer->sent || !peer->received || peer->destroyed)
		return;

	peer->agent = NULL;
	juice_destroy(agent);
	peer->destroyed = true;
	printf("Destroyed %s from its own callback\n", peer->name);
}

static bool is_late_callback(peer_t *peer) {
	if (!peer->destroyed)
		return false;

	++peer->late_callbacks;
	printf("Callback for %s after juice_destroy() returned\n", peer->name);
	return true;
}

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	peer_t *peer = user_ptr;
	if (is_late_callback(peer))
		return;

	printf("State %s: %s\n", peer->name, juice_state_to_string(state));
	if (state == JUICE_STATE_CONNECTED && !peer->sent) {
		const char *message = "Hello";
		juice_send(agent, message, strlen(message));
		peer->sent = true;
		destroy_if_done(peer, agent);
	}
}

static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	peer_t *peer = user_ptr;
	if (is_late_callback(peer))
		return;

	if (peer->remote->agent)
		juice_add_remote_candidate(peer->remote->agent, sdp);
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)data;
	(void)size;
	peer_t *peer = user_ptr;
	if (is_late_callback(peer))
		return;

	peer->received = true;
	destroy_if_done(peer, agent);
}

static void init_config(juice_config_t *config, juice_concurrency_mode_t mode, uint16_t port) {
	memset(config, 0, sizeof(*config));
	config->concurrency_mode = mode;
	config->local_port_range_begin = port;
	config->local_port_range_end = port;
}

static juice_agent_t *create_peer_agent(peer_t *peer, juice_concurrency_mode_t mode,
                                        uint16_t port) {
	juice_config_t config;
	init_config(&config, mode, port);
	config.cb_state_changed = on_state_changed;
	config.cb_candidate = on_candidate;
	config.cb_recv = on_recv;
	config.user_ptr = peer;
	return juice_create(&config);
}

static int run(const char *label, juice_concurrency_mode_t mode1, juice_concurrency_mode_t mode2,
               uint16_t port2) {
	printf("Destroy from callback, %s\n", label);

	memset(&peer1, 0, sizeof(peer1));
	memset(&peer2, 0, sizeof(peer2));
	peer1.name = "1";
	peer2.name = "2";
	peer1.remote = &peer2;
	peer2.remote = &peer1;

	peer1.agent = create_peer_agent(&peer1, mode1, 0);
	peer2.agent = create_peer_agent(&peer2, mode2, port2);
	if (!peer1.agent || !peer2.agent) {
		printf("Failure: could not create agents (%s)\n", label);
		return -1;
	}

	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(peer1.agent, sdp1, JUICE_MAX_SDP_STRING_LEN);
	juice_set_remote_description(peer2.agent, sdp1);

	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(peer2.agent, sdp2, JUICE_MAX_SDP_STRING_LEN);
	juice_set_remote_description(peer1.agent, sdp2);

	juice_gather_candidates(peer1.agent);
	juice_gather_candidates(peer2.agent);

	for (int i = 0; i < 10 && !(peer1.destroyed && peer2.destroyed); ++i)
		sleep(1);

	if (!peer1.destroyed || !peer2.destroyed) {
		printf("Failure: agents were not destroyed from their callbacks (%s)\n", label);
		return -1;
	}

	sleep(1);

	if (peer1.late_callbacks || peer2.late_callbacks) {
		printf("Failure: callbacks after juice_destroy() returned (%s)\n", label);
		return -1;
	}

	juice_config_t config;
	init_config(&config, mode2, port2);
	juice_agent_t *agent = juice_create(&config);
	if (!agent || juice_gather_candidates(agent) != JUICE_ERR_SUCCESS) {
		printf("Failure: could not use a new agent after destroying the last one (%s)\n", label);
		juice_destroy(agent);
		return -1;
	}
	juice_destroy(agent);
	return 0;
}

// Destroy from a callback fired while gathering: inside juice_gather_candidates() on the caller's
// thread, or on the resolver thread when every server hostname fails to resolve (that thread
// used to be joined from itself).
typedef enum { ON_GATHERING_STATE, ON_CANDIDATE, ON_GATHERING_DONE } trigger_t;

static trigger_t gather_trigger;
static volatile bool gather_destroyed;
static volatile int gather_late_callbacks;

static void gather_destroy_on(juice_agent_t *agent, bool triggered) {
	if (gather_destroyed) {
		++gather_late_callbacks;
		return;
	}
	if (triggered) {
		juice_destroy(agent);
		gather_destroyed = true;
		printf("Destroyed agent from a gathering callback\n");
	}
}

static void gather_on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	(void)user_ptr;
	bool triggered = gather_trigger == ON_GATHERING_STATE && state == JUICE_STATE_GATHERING;
	gather_destroy_on(agent, triggered);
}

static void gather_on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)sdp;
	(void)user_ptr;
	gather_destroy_on(agent, gather_trigger == ON_CANDIDATE);
}

static void gather_on_gathering_done(juice_agent_t *agent, void *user_ptr) {
	(void)user_ptr;
	gather_destroy_on(agent, gather_trigger == ON_GATHERING_DONE);
}

typedef struct gather_case {
	const char *name;
	const char *stun_host;
	trigger_t trigger;
} gather_case_t;

typedef struct mode_case {
	const char *name;
	juice_concurrency_mode_t mode;
	uint16_t port;
} mode_case_t;

static int run_gather(const gather_case_t *gc, const mode_case_t *mc) {
	printf("Destroy from a gathering callback, %s, %s\n", gc->name, mc->name);

	gather_trigger = gc->trigger;
	gather_destroyed = false;
	gather_late_callbacks = 0;

	juice_config_t config;
	init_config(&config, mc->mode, mc->port);
	config.stun_server_host = gc->stun_host;
	config.stun_server_port = 3478;
	config.cb_state_changed = gather_on_state_changed;
	config.cb_candidate = gather_on_candidate;
	config.cb_gathering_done = gather_on_gathering_done;

	juice_agent_t *agent = juice_create(&config);
	if (!agent) {
		printf("Failure: could not create agent\n");
		return -1;
	}
	if (juice_gather_candidates(agent) != JUICE_ERR_SUCCESS) {
		printf("Failure: juice_gather_candidates() failed\n");
		return -1;
	}

	for (int i = 0; i < 15 && !gather_destroyed; ++i)
		sleep(1);

	if (!gather_destroyed) {
		printf("Failure: juice_destroy() did not return\n");
		return -1;
	}

	sleep(1); // let the deferred destruction finish

	if (gather_late_callbacks) {
		printf("Failure: callbacks after juice_destroy() returned\n");
		return -1;
	}
	return 0;
}

int test_destroy_from_callback(void) {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	if (run("poll", JUICE_CONCURRENCY_MODE_POLL, JUICE_CONCURRENCY_MODE_POLL, 0) ||
	    run("thread", JUICE_CONCURRENCY_MODE_THREAD, JUICE_CONCURRENCY_MODE_THREAD, 0) ||
	    run("mux", JUICE_CONCURRENCY_MODE_POLL, JUICE_CONCURRENCY_MODE_MUX, 60000)) {
		printf("Failure\n");
		return -1;
	}

	static const gather_case_t gather_cases[] = {
	    // nonexistent.invalid never resolves (RFC 6761)
	    {"gathering done on the resolver thread", "nonexistent.invalid", ON_GATHERING_DONE},
	    {"gathering done in juice_gather_candidates()", NULL, ON_GATHERING_DONE},
	    {"host candidate", NULL, ON_CANDIDATE},
	    {"gathering state", NULL, ON_GATHERING_STATE},
	};
	static const mode_case_t mode_cases[] = {
	    {"poll", JUICE_CONCURRENCY_MODE_POLL, 0},
	    {"thread", JUICE_CONCURRENCY_MODE_THREAD, 0},
	    {"mux", JUICE_CONCURRENCY_MODE_MUX, 60002},
	};
	for (size_t g = 0; g < sizeof(gather_cases) / sizeof(gather_cases[0]); ++g) {
		for (size_t m = 0; m < sizeof(mode_cases) / sizeof(mode_cases[0]); ++m) {
			if (run_gather(gather_cases + g, mode_cases + m)) {
				printf("Failure\n");
				return -1;
			}
		}
	}

	printf("Success\n");
	return 0;
}
