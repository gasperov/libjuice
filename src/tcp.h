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
#include "tls_schannel.h"

typedef enum tcp_state {
	TCP_STATE_DISCONNECTED,
	TCP_STATE_CONNECTING,
	TCP_STATE_TLS_HANDSHAKING,
	TCP_STATE_CONNECTED,
	TCP_STATE_FAILED
} tcp_state_t;

socket_t tcp_create_socket(const addr_record_t *dst);

#define TCP_BUFFER_SIZE 2048

// Extra room reserved in the buffers below for a TLS record header+trailer when framing runs
// over TLS (TURNS), so a max-size plaintext message's ciphertext still fits in place. Real
// overhead (queried from cbHeader/cbTrailer after the handshake) is a fraction of this for the
// AEAD cipher suites Windows negotiates by default (e.g. AES-GCM: ~29 bytes); this is just a
// safe fixed upper bound so the struct layout doesn't depend on what gets negotiated at runtime.
#define TLS_RECORD_OVERHEAD_RESERVE 128
#define TCP_CONTEXT_BUFFER_SIZE (TCP_BUFFER_SIZE + TLS_RECORD_OVERHEAD_RESERVE)

// STUN messages: 20-byte header, length at bytes 2-3 (payload only, total = 20 + length)
// ChannelData:    4-byte header, length at bytes 2-3 (payload only, total = 4 + length)
// Disambiguated using the same checks as the UDP path: is_channel_data() (turn.h) and
// is_stun_datagram() (stun.h), not a locally redefined byte range.
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
	// 32-bit: STUN/ChannelData framing (TURN-TCP) allows a total message length up to
	// STUN_HEADER_SIZE + UINT16_MAX = 65555, which does not fit in 16 bits. Only bytes up to
	// TCP_BUFFER_SIZE are ever kept; anything beyond that is drained and discarded, but the
	// full length must still be tracked accurately so the next frame stays in sync.
	uint32_t length;
	uint32_t bytes_read; // 0 if finished
	uint16_t header; // 2-byte length prefix (ICE framing only)
	bool pending;
} tcp_read_context_t;

// 2-byte length prefix used for ICE-TCP
int tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context);
int tcp_ice_read(socket_t sock, tcp_read_context_t *context);

// Self-delimiting STUN/ChannelData framing used for TURN-TCP. tls is NULL for plain TURN-TCP;
// when set, I/O goes through it instead of the raw socket (TURNS).
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
} tcp_conn_t;

const char *tcp_state_to_string(tcp_state_t state);
const char *tcp_framing_to_string(tcp_framing_t framing);
void tcp_conn_init(tcp_conn_t *tc, tcp_framing_t framing);
void tcp_conn_reset(tcp_conn_t *tc);

// Export for tests
JUICE_EXPORT void _juice_tcp_conn_init(tcp_conn_t *tc, tcp_framing_t framing);
JUICE_EXPORT int _juice_tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context);
JUICE_EXPORT int _juice_tcp_ice_read(socket_t sock, tcp_read_context_t *context);
JUICE_EXPORT int _juice_tcp_stun_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context);
JUICE_EXPORT int _juice_tcp_stun_read(socket_t sock, tcp_read_context_t *context);

#endif
