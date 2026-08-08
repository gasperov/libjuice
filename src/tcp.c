/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "tcp.h"
#include "log.h"
#include "stun.h"
#include "turn.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define BUFFER_SIZE 1024

socket_t tcp_create_socket(const addr_record_t *dst) {
	socket_t sock = socket(dst->addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		JLOG_WARN("TCP socket creation failed, errno=%d", sockerrno);
		return INVALID_SOCKET;
	}

	int nodelay = 1;
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay))) {
		JLOG_WARN("Setting TCP_NODELAY on TCP socket failed, errno=%d", sockerrno);
	}

	// Set buffer size up to 1 MiB for performance, matching udp.c
	const sockopt_t buffer_size = 1 * 1024 * 1024;
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&buffer_size, sizeof(buffer_size));
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char *)&buffer_size, sizeof(buffer_size));

	ctl_t nbio = 1;
	if (ioctlsocket(sock, FIONBIO, &nbio)) {
		JLOG_ERROR("Setting non-blocking mode on TCP socket failed, errno=%d", sockerrno);
		goto error;
	}

	int ret = connect(sock, (const struct sockaddr *)&dst->addr, dst->len);
	if (ret != 0 && sockerrno != SEINPROGRESS && sockerrno != SEWOULDBLOCK) {
		JLOG_WARN("TCP connection failed, errno=%d", sockerrno);
		goto error;
	}

	JLOG_DEBUG("TCP socket created, non-blocking connect initiated");
	return sock;

error:
	if (sock != INVALID_SOCKET)
		closesocket(sock);

	return INVALID_SOCKET;
}

// Write datagram to TCP socket with RFC4571 framing
int tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context) {
#if defined(__APPLE__) || defined(_WIN32)
	int flags = 0;
#else
	int flags = MSG_NOSIGNAL;
#endif

	if (data) {
		if (context->pending)
			return -SEAGAIN;

		if (size > TCP_BUFFER_SIZE)
			return -SEMSGSIZE;

		memcpy(context->buffer, data, size);
		context->length = (uint16_t)size;
		context->bytes_written = 0;
		context->pending = true;
	}

	while(context->pending && context->bytes_written < 2 + context->length) {
		int len;
		if (context->bytes_written < 2) {
			uint16_t header = htons(context->length);
			len = send(sock, (const char *)&header + context->bytes_written, 2 - context->bytes_written, flags);
		} else { // bytes_written >= 2
			len = send(sock, context->buffer + (context->bytes_written - 2), context->length - (context->bytes_written - 2), flags);
		}

		if (len < 0)
			return len;

		context->bytes_written += len;
	}

	context->pending = false;
	return (int)context->length;
}

// Read datagram from TCP socket with RFC4571 framing (discard empty datagrams)
int tcp_ice_read(socket_t sock, tcp_read_context_t *context) {
#if defined(__APPLE__) || defined(_WIN32)
	int flags = 0;
#else
	int flags = MSG_NOSIGNAL;
#endif

	if (!context->pending) {
		context->length = 0;
		context->bytes_read = 0;
		context->pending = true;
	}

	int len;
	while (context->bytes_read < 2 + context->length) {
		if (context->bytes_read < 2) {
			len = recv(sock, (char *)&context->header + context->bytes_read, 2 - context->bytes_read, flags);
		} else { // bytes_read >= 2
			if (context->bytes_read < 2 + TCP_BUFFER_SIZE) {
				uint32_t length = context->length;
				if (length > TCP_BUFFER_SIZE)
					length = TCP_BUFFER_SIZE;

				len = recv(sock, context->buffer + (context->bytes_read - 2), length - (context->bytes_read - 2), flags);
			} else {
				char buffer[BUFFER_SIZE];
				size_t size = context->length - (context->bytes_read - 2);
				if (size > BUFFER_SIZE)
					size = BUFFER_SIZE;

				len = recv(sock, buffer, (socklen_t)size, flags);
			}
		}

		if (len < 0) {
			if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
				JLOG_DEBUG("TCP recv failed, errno=%d", sockerrno);

			return -sockerrno;
		}

		if (len == 0)
			return 0; // closed

		context->bytes_read += len;

		if (context->bytes_read == 2) {
			// Header complete: decode the RFC4571 length
			context->length = ntohs(context->header);
			if (context->length == 0)
				context->bytes_read = 0; // discard empty datagram, restart on next frame
		}
	}

	context->pending = false;
	assert(context->length > 0);
	return (int)context->length;
}

// Write raw STUN or ChannelData message to TCP socket (no RFC 4571 framing).
// ChannelData is padded to 4-byte boundary per RFC 8656 Section 12.5.
int tcp_stun_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context,
                   tls_client_t *tls) {
#if defined(__APPLE__) || defined(_WIN32)
	int flags = 0;
#else
	int flags = MSG_NOSIGNAL;
#endif

	if (data) {
		if (context->pending)
			return -SEAGAIN;

		if (size > TCP_BUFFER_SIZE)
			return -SEMSGSIZE;

		memcpy(context->buffer, data, size);
		uint16_t wire_size = (uint16_t)size;

		// Pad ChannelData to 4-byte boundary for TCP (RFC 8656 Section 12.5)
		if (is_channel_data(data, size)) {
			uint16_t padded = (wire_size + 3) & ~3u;
			if (padded > TCP_BUFFER_SIZE)
				return -SEMSGSIZE;
			// Zero-fill padding bytes
			while (wire_size < padded)
				context->buffer[wire_size++] = 0;
		}

		context->length = wire_size;
		context->send_length = wire_size;

		if (tls) {
			int enc = tls_encode(tls, context->buffer, sizeof(context->buffer), wire_size);
			if (enc < 0)
				return enc;
			context->send_length = (uint16_t)enc; // ciphertext now occupies buffer[0..enc)
		}

		context->bytes_written = 0;
		context->pending = true;
	}

	while (context->pending && context->bytes_written < context->send_length) {
		int len = send(sock, context->buffer + context->bytes_written,
		               context->send_length - context->bytes_written, flags);
		if (len < 0) {
			if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
				JLOG_DEBUG("TCP send failed, errno=%d", sockerrno);
			return -sockerrno;
		}

		context->bytes_written += (uint16_t)len;
	}

	context->pending = false;
	return (int)context->length;
}

// recv()-compatible contract (>0 bytes copied, 0 on orderly close, negative incl. -SEAGAIN),
// backed by TLS instead of the raw socket. A single STUN/ChannelData message can need bytes from
// more than one TLS record, and a single decoded record can hold more plaintext than the current
// message still needs, so the cipher state's buf holds, in order: [0..plain_len) plaintext
// already decoded but not yet delivered, then [plain_len..len) raw ciphertext not yet decoded.
static int tcp_stun_tls_recv(tls_client_t *tls, socket_t sock, char *dst, uint32_t cap) {
	tls_cipher_state_t *cs = tls_client_cipher_state(tls);

	for (;;) {
		if (cs->plain_len > 0) {
			uint32_t n = cs->plain_len < cap ? cs->plain_len : cap;
			memcpy(dst, cs->buf, n);
			uint32_t remainder = cs->len - n;
			if (remainder > 0)
				memmove(cs->buf, cs->buf + n, remainder);
			cs->plain_len -= n;
			cs->len -= n;
			return (int)n;
		}

		if (cs->len > 0) {
			char *pt;
			size_t pt_len, consumed;
			int ret = tls_decode(tls, cs->buf, cs->len, &pt, &pt_len, &consumed);
			if (ret < 0)
				return -SECONNRESET;
			if (ret == 1) {
				size_t extra = cs->len - consumed;
				// pt aliases cs->buf, after the record's header: close that gap, then close the
				// gap left by the consumed header+trailer for any leftover ciphertext too.
				if (pt_len > 0)
					memmove(cs->buf, pt, pt_len);
				if (extra > 0)
					memmove(cs->buf + pt_len, cs->buf + consumed, extra);
				if (pt_len == 0 && extra == 0)
					return 0; // peer's close_notify: reported as a valid, empty record
				cs->plain_len = (uint32_t)pt_len;
				cs->len = (uint32_t)(pt_len + extra);
				continue; // deliver from the newly decoded plaintext above
			}
			// ret == 0: not a complete record yet, read more below
		}

		if (cs->len >= sizeof(cs->buf)) {
			JLOG_WARN("TLS record exceeds internal buffer");
			return -SECONNRESET;
		}
		int n = recv(sock, cs->buf + cs->len, (int)(sizeof(cs->buf) - cs->len), 0);
		if (n < 0) {
			if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
				return -SEAGAIN;
			return -sockerrno;
		}
		if (n == 0)
			return 0; // closed
		cs->len += (uint32_t)n;
	}
}

// Read raw STUN or ChannelData message from TCP socket (self-delimiting).
// ChannelData is identified by is_channel_data() (same check as the UDP path, turn.c). A STUN
// message can only be confirmed once its full 20-byte header has arrived, since that requires
// validating the magic cookie via is_stun_datagram() (stun.c) rather than just the top-2-bits
// heuristic used below to size the frame while it is still being read.
int tcp_stun_read(socket_t sock, tcp_read_context_t *context, tls_client_t *tls) {
#if defined(__APPLE__) || defined(_WIN32)
	int flags = 0;
#else
	int flags = MSG_NOSIGNAL;
#endif

	if (!context->pending) {
		context->length = CHANNEL_DATA_HEADER_SIZE; // read min header (4 bytes) to disambiguate
		context->bytes_read = 0;
		context->pending = true;
	}

	while (context->bytes_read < context->length) {
		char buffer[BUFFER_SIZE];
		uint32_t remaining = context->length - context->bytes_read;
		char *dst;
		if (context->bytes_read < TCP_BUFFER_SIZE) {
			uint32_t cap = TCP_BUFFER_SIZE - context->bytes_read;
			if (remaining > cap)
				remaining = cap;
			dst = context->buffer + context->bytes_read;
		} else {
			// Message larger than the buffer: drain the excess to stay framed (too long messages
			// are truncated, like datagram sockets)
			if (remaining > BUFFER_SIZE)
				remaining = BUFFER_SIZE;
			dst = buffer;
		}

		int len = tls ? tcp_stun_tls_recv(tls, sock, dst, remaining)
		             : recv(sock, dst, remaining, flags);
		if (len < 0) {
			if (tls)
				return len; // already a signed error code, not a raw sockerrno to translate
			if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
				JLOG_DEBUG("TCP recv failed, errno=%d", sockerrno);
			return -sockerrno;
		}
		if (len == 0)
			return 0; // closed

		context->bytes_read += (uint32_t)len;

		// Once the minimum header is available, determine the full message length
		if (context->bytes_read >= CHANNEL_DATA_HEADER_SIZE &&
		    context->length == CHANNEL_DATA_HEADER_SIZE) {
			uint16_t payload_len;
			memcpy(&payload_len, context->buffer + 2, sizeof(uint16_t));
			payload_len = ntohs(payload_len);

			// Total length in 32 bits: STUN tops out at 20 + 65535 = 65555 and ChannelData
			// (padded) at 4 + 65536 = 65540, both of which exceed UINT16_MAX, so this cannot be
			// tracked in a 16-bit counter. context->length/bytes_read are 32-bit for this reason;
			// bytes beyond TCP_BUFFER_SIZE are still just drained and discarded above, like a
			// datagram socket truncating an oversized read, rather than desyncing framing or
			// tearing down the connection over a message that is merely large.
			uint32_t total;
			if (is_channel_data(context->buffer, context->bytes_read)) {
				total = (uint32_t)CHANNEL_DATA_HEADER_SIZE + (((uint32_t)payload_len + 3) & ~3u);
			} else if ((context->buffer[0] & 0xC0) == 0) {
				// RFC 8489: top 2 bits zero is necessary but not sufficient for STUN; the magic
				// cookie is checked against is_stun_datagram() below once the full header is in.
				total = (uint32_t)STUN_HEADER_SIZE + payload_len;
			} else {
				return -SECONNRESET; // neither STUN nor ChannelData: invalid framing
			}

			context->length = total;
		}
	}

	uint32_t avail = context->length > TCP_BUFFER_SIZE ? TCP_BUFFER_SIZE : context->length;
	if (!is_channel_data(context->buffer, avail) && !is_stun_datagram(context->buffer, context->length))
		return -SECONNRESET; // top-2-bits looked STUN-shaped but the magic cookie/length doesn't match

	context->pending = false;
	return (int)avail;
}

const char *tcp_state_to_string(tcp_state_t state) {
	switch (state) {
	case TCP_STATE_DISCONNECTED:     return "disconnected";
	case TCP_STATE_CONNECTING:       return "connecting";
	case TCP_STATE_TLS_HANDSHAKING:  return "tls_handshaking";
	case TCP_STATE_CONNECTED:        return "connected";
	case TCP_STATE_FAILED:           return "failed";
	default:                         return "unknown";
	}
}

const char *tcp_framing_to_string(tcp_framing_t framing) {
	switch (framing) {
	case TCP_FRAMING_ICE:      return "ICE-TCP";
	case TCP_FRAMING_STUN:     return "TURN-TCP";
	case TCP_FRAMING_STUN_TLS: return "TURNS";
	default:                   return "unknown";
	}
}

// Assumes no meaningful prior state (fresh calloc, or a slot already cleared by
// tcp_conn_reset()): does not free an existing tc->tls, so this is safe to call on an
// uninitialized tcp_conn_t (as the test helpers do), unlike tcp_conn_reset() below.
void tcp_conn_init(tcp_conn_t *tc, tcp_framing_t framing) {
	tc->sock = INVALID_SOCKET;
	tc->state = TCP_STATE_DISCONNECTED;
	tc->framing = framing;
	tc->tls = NULL;
	memset(&tc->dst, 0, sizeof(tc->dst));
	memset(&tc->write, 0, sizeof(tc->write));
	memset(&tc->read,  0, sizeof(tc->read));
}

void tcp_conn_reset(tcp_conn_t *tc) {
	tls_client_destroy(tc->tls);
	tc->tls = NULL;
	memset(&tc->write, 0, sizeof(tc->write));
	memset(&tc->read,  0, sizeof(tc->read));
}

JUICE_EXPORT int _juice_tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context) {
	return tcp_ice_write(sock, data, size, context);
}

JUICE_EXPORT int _juice_tcp_ice_read(socket_t sock, tcp_read_context_t *context) {
	return tcp_ice_read(sock, context);
}

JUICE_EXPORT int _juice_tcp_stun_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context) {
	return tcp_stun_write(sock, data, size, context, NULL);
}

JUICE_EXPORT int _juice_tcp_stun_read(socket_t sock, tcp_read_context_t *context) {
	return tcp_stun_read(sock, context, NULL);
}

JUICE_EXPORT void _juice_tcp_conn_init(tcp_conn_t *tc, tcp_framing_t framing) {
	tcp_conn_init(tc, framing);
}
