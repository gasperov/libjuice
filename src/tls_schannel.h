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

// Opaque on every platform; only non-NULL when created with SChannel support
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

// True while the handshake waits to finish sending, so it needs the socket to become writable
bool tls_client_wants_write(const tls_client_t *tls);

// Export for tests: sends buf[*off..len), advancing *off. Returns 1 once done, 0 if the socket
// would block (call again with the same arguments), or -1 on error.
JUICE_EXPORT int _juice_tls_send_partial(socket_t sock, const char *buf, size_t len, size_t *off);

#else

// Without SChannel tls is always NULL, so these are never reached; they spare call sites #ifdefs
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
