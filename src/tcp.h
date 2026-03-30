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

#include <string.h>

typedef enum tcp_state {
	TCP_STATE_DISCONNECTED,
	TCP_STATE_CONNECTING,
	TCP_STATE_CONNECTED,
	TCP_STATE_FAILED
} tcp_state_t;

socket_t tcp_create_socket(const addr_record_t *dst);

#define TCP_ICE_BUFFER_SIZE 2048

// RFC 4571 framing contexts (2-byte length prefix + payload) — used for ICE-TCP
typedef struct tcp_ice_write_context {
	char buffer[TCP_ICE_BUFFER_SIZE];
	uint16_t length;
	uint16_t bytes_written;
	bool pending;
} tcp_ice_write_context_t;

typedef struct tcp_ice_read_context {
	char buffer[TCP_ICE_BUFFER_SIZE];
	uint16_t length;
	uint16_t bytes_read; // 0 if finished
	uint16_t header;
	bool pending;
} tcp_ice_read_context_t;

int tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_ice_write_context_t *context);
int tcp_ice_read(socket_t sock, tcp_ice_read_context_t *context);

// Raw STUN/ChannelData framing contexts (no length prefix, self-delimiting) — used for TURN-TCP
// STUN messages: 20-byte header, length at bytes 2-3 (payload only, total = 20 + length)
// ChannelData:    4-byte header, length at bytes 2-3 (payload only, total = 4 + length)
// Disambiguated by first byte: 0x00-0x3F = STUN, 0x40-0x4F = ChannelData
#define STUN_HEADER_SIZE 20
#define CHANNEL_DATA_HEADER_SIZE 4

typedef struct tcp_stun_write_context {
	char buffer[TCP_ICE_BUFFER_SIZE];
	uint16_t length;
	uint16_t bytes_written;
	bool pending;
} tcp_stun_write_context_t;

typedef struct tcp_stun_read_context {
	char buffer[TCP_ICE_BUFFER_SIZE];
	uint16_t length;       // total message length (header + payload)
	uint16_t bytes_read;
	bool pending;
} tcp_stun_read_context_t;

int tcp_stun_write(socket_t sock, const char *data, size_t size, tcp_stun_write_context_t *context);
int tcp_stun_read(socket_t sock, tcp_stun_read_context_t *context);

typedef struct tcp_conn {
	socket_t sock;
	tcp_ice_write_context_t write_context;
	tcp_ice_read_context_t read_context;
	tcp_stun_write_context_t stun_write_context;
	tcp_stun_read_context_t stun_read_context;
	addr_record_t dst;
	tcp_state_t state;
} tcp_conn_t;

static inline void tcp_conn_init(tcp_conn_t *tc) {
	tc->sock = INVALID_SOCKET;
	tc->state = TCP_STATE_DISCONNECTED;
	memset(&tc->write_context, 0, sizeof(tcp_ice_write_context_t));
	memset(&tc->read_context, 0, sizeof(tcp_ice_read_context_t));
	memset(&tc->stun_write_context, 0, sizeof(tcp_stun_write_context_t));
	memset(&tc->stun_read_context, 0, sizeof(tcp_stun_read_context_t));
}

const char *tcp_state_to_string(tcp_state_t state);

// Export for tests
JUICE_EXPORT int _juice_tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_ice_write_context_t *context);
JUICE_EXPORT int _juice_tcp_ice_read(socket_t sock, tcp_ice_read_context_t *context);

#endif
