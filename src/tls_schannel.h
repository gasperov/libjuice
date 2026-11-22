/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_TLS_SCHANNEL_H
#define JUICE_TLS_SCHANNEL_H

#include "juice.h"
#include "socket.h"

#include <stdbool.h>
#include <stdint.h>

// Declared unconditionally (opaque) so callers can hold a tls_client_t* on any platform without
// preprocessor conditionals; only tls_client_create() can produce a non-NULL one, and it only
// exists when SChannel support is actually compiled in.
typedef struct tls_client tls_client_t;

#if defined(_WIN32) && defined(USE_SCHANNEL)

// hostname is used for SNI and certificate validation; copied internally.
tls_client_t *tls_client_create(const char *hostname, bool insecure_skip_verify);
void tls_client_destroy(tls_client_t *tls);

// Drives the handshake using non-blocking I/O on sock. Returns 1 once complete, 0 if it needs
// another poll() readiness event to make progress, -1 on fatal error.
int tls_client_handshake(tls_client_t *tls, socket_t sock);

// Encrypts buf[0..plain_size) in place into one TLS record. Returns the record size, which may
// be up to buf_capacity, or a negative value on error.
int tls_encode(tls_client_t *tls, char *buf, size_t buf_capacity, size_t plain_size);

// Like recv() on sock, but returns decrypted data: the number of bytes copied to dst (at most
// cap), 0 once the peer closed, or a negative error (-SEAGAIN when nothing is available yet).
int tls_client_recv(tls_client_t *tls, socket_t sock, char *dst, size_t cap);

// True while a partially-sent handshake token is pending flush, i.e. the handshake needs the
// socket to become writable; otherwise it is waiting to read the server's next flight.
bool tls_client_wants_write(const tls_client_t *tls);

// Internal adapter returns bytes sent or a negative socket error. Passing it per call lets
// tests exercise the production flush loop without relying on OS buffer sizes or timing.
typedef int (*tls_send_func_t)(void *user_ptr, const char *buf, size_t len);
static inline int tls_send_partial_with(tls_send_func_t send_func, void *user_ptr,
                                        const char *buf, size_t len, size_t *off) {
	while (*off < len) {
		int n = send_func(user_ptr, buf + *off, len - *off);
		if (n == -SEAGAIN || n == -SEWOULDBLOCK)
			return 0;
		if (n <= 0)
			return -1;
		*off += (size_t)n;
	}
	return 1;
}

// Export for tests. Sends buf[*off..len), advancing *off as bytes go out. Returns 1 once *off
// reaches len, 0 if the socket would still block (progress so far already recorded in *off, so
// a later call with the same buf/len/off resumes correctly), <0 on fatal error. No allocation.
JUICE_EXPORT int _juice_tls_send_partial(socket_t sock, const char *buf, size_t len, size_t *off);

#else

// Unreachable in practice: with no tls_client_create() on this build, tls is always NULL and
// callers branch on that before reaching these. Stubs exist so call sites don't need #ifdef.
static inline int tls_client_handshake(tls_client_t *tls, socket_t sock) {
	(void)tls; (void)sock;
	return -1;
}
static inline int tls_encode(tls_client_t *tls, char *buf, size_t buf_capacity, size_t plain_size) {
	(void)tls; (void)buf; (void)buf_capacity; (void)plain_size;
	return -1;
}
static inline int tls_client_recv(tls_client_t *tls, socket_t sock, char *dst, size_t cap) {
	(void)tls; (void)sock; (void)dst; (void)cap;
	return -1;
}
static inline void tls_client_destroy(tls_client_t *tls) { (void)tls; }
static inline bool tls_client_wants_write(const tls_client_t *tls) {
	(void)tls;
	return false;
}

#endif // _WIN32 && USE_SCHANNEL

#endif
