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

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	peer_t *peer = user_ptr;
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
	if (peer->remote->agent)
		juice_add_remote_candidate(peer->remote->agent, sdp);
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)data;
	(void)size;
	peer_t *peer = user_ptr;
	peer->received = true;
	destroy_if_done(peer, agent);
}

static juice_agent_t *create_agent(peer_t *peer) {
	juice_config_t config;
	memset(&config, 0, sizeof(config));
	config.cb_state_changed = on_state_changed;
	config.cb_candidate = on_candidate;
	config.cb_recv = on_recv;
	config.user_ptr = peer;
	return juice_create(&config);
}

int test_destroy_from_callback(void) {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	memset(&peer1, 0, sizeof(peer1));
	memset(&peer2, 0, sizeof(peer2));
	peer1.name = "1";
	peer2.name = "2";
	peer1.remote = &peer2;
	peer2.remote = &peer1;

	peer1.agent = create_agent(&peer1);
	peer2.agent = create_agent(&peer2);
	if (!peer1.agent || !peer2.agent) {
		printf("Failure\n");
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
		printf("Failure: agents were not destroyed from their callbacks\n");
		return -1;
	}

	sleep(1);

	juice_config_t config;
	memset(&config, 0, sizeof(config));
	juice_agent_t *agent = juice_create(&config);
	if (!agent || juice_gather_candidates(agent) != JUICE_ERR_SUCCESS) {
		printf("Failure: could not use a new agent after destroying the last one\n");
		juice_destroy(agent);
		return -1;
	}
	juice_destroy(agent);

	printf("Success\n");
	return 0;
}
