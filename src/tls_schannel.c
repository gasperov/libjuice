/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "tls_schannel.h"

#if defined(_WIN32) && defined(USE_SCHANNEL)

#include "log.h"

#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>

#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

// Room for the largest STUN message (20-byte header + 65535) plus TLS record overhead. The
// handshake uses the same buffer to accumulate the server's messages.
#define TLS_CIPHER_BUFFER_SIZE (65555 + 256)

// Received bytes: [off, off + len) is ciphertext not decoded yet, [plain_off, plain_off +
// plain_len) is decrypted data not delivered yet. Decrypted data is always delivered before more
// is received, so moving the ciphertext to the front never overwrites it.
typedef struct tls_cipher_state {
	char buf[TLS_CIPHER_BUFFER_SIZE];
	uint32_t off;
	uint32_t len;
	uint32_t plain_off;
	uint32_t plain_len;
} tls_cipher_state_t;

struct tls_client {
	CredHandle cred;
	CtxtHandle ctx;

	bool cred_valid;
	bool ctx_valid;
	bool handshake_done;
	bool insecure_skip_verify;

	SecPkgContext_StreamSizes sizes; // valid once handshake_done

	tls_cipher_state_t cipher;

	// Handshake token not fully sent yet. A blocked send resumes here, since calling
	// InitializeSecurityContextW again would produce a different token. out_final is set when it
	// is the last one (status SEC_E_OK).
	char *out_buf; // SChannel-allocated (FreeContextBuffer), NULL if nothing pending
	size_t out_off;
	size_t out_len;
	bool out_final;

	wchar_t *hostname;
};

tls_client_t *tls_client_create(const char *hostname, bool insecure_skip_verify) {
	tls_client_t *tls = calloc(1, sizeof(tls_client_t));
	if (!tls)
		return NULL;

	int wlen = MultiByteToWideChar(CP_UTF8, 0, hostname, -1, NULL, 0);
	if (wlen <= 0) {
		free(tls);
		return NULL;
	}
	tls->hostname = malloc((size_t)wlen * sizeof(wchar_t));
	if (!tls->hostname) {
		free(tls);
		return NULL;
	}
	MultiByteToWideChar(CP_UTF8, 0, hostname, -1, tls->hostname, wlen);

	tls->insecure_skip_verify = insecure_skip_verify;
	return tls;
}

void tls_client_destroy(tls_client_t *tls) {
	if (!tls)
		return;
	if (tls->ctx_valid)
		DeleteSecurityContext(&tls->ctx);
	if (tls->cred_valid)
		FreeCredentialsHandle(&tls->cred);
	if (tls->out_buf)
		FreeContextBuffer(tls->out_buf);
	free(tls->hostname);
	free(tls);
}

bool tls_client_wants_write(const tls_client_t *tls) {
	return tls->out_buf != NULL;
}

// Sends buf[*off..len), advancing *off. Returns 1 once done, 0 if the socket would block (call
// again with the same arguments), or -1 on error.
static int tls_send_partial(socket_t sock, const char *buf, size_t len, size_t *off) {
	while (*off < len) {
		int n = send(sock, buf + *off, (int)(len - *off), 0);
		if (n < 0)
			return sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK ? 0 : -1;
		if (n == 0)
			return -1;
		*off += (size_t)n;
	}
	return 1;
}

// Sends the pending handshake token, if any, and frees it once sent or on error. Returns like
// tls_send_partial().
static int tls_flush_pending_output(tls_client_t *tls, socket_t sock) {
	if (!tls->out_buf)
		return 1;
	int ret = tls_send_partial(sock, tls->out_buf, tls->out_len, &tls->out_off);
	if (ret != 0) {
		FreeContextBuffer(tls->out_buf);
		tls->out_buf = NULL;
	}
	return ret;
}

JUICE_EXPORT int _juice_tls_send_partial(socket_t sock, const char *buf, size_t len, size_t *off) {
	return tls_send_partial(sock, buf, len, off);
}

int tls_client_handshake(tls_client_t *tls, socket_t sock) {
	if (tls->handshake_done)
		return 1;

	if (!tls->cred_valid) {
		SCHANNEL_CRED cred;
		memset(&cred, 0, sizeof(cred));
		cred.dwVersion = SCHANNEL_CRED_VERSION;
		// SCHANNEL_CRED cannot enable TLS 1.3; requesting it makes AcquireCredentialsHandle
		// fail with SEC_E_ALGORITHM_MISMATCH on some Windows builds.
		cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
		cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | (tls->insecure_skip_verify
		                                                 ? SCH_CRED_MANUAL_CRED_VALIDATION
		                                                 : SCH_CRED_AUTO_CRED_VALIDATION);

		TimeStamp expiry;
		SECURITY_STATUS status =
		    AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL,
		                              &cred, NULL, NULL, &tls->cred, &expiry);
		if (status != SEC_E_OK) {
			JLOG_WARN("AcquireCredentialsHandle failed, status=0x%lx", (unsigned long)status);
			return -1;
		}
		tls->cred_valid = true;
	}

	// Finish sending a token left over from the previous call first
	if (tls->out_buf) {
		int flushed = tls_flush_pending_output(tls, sock);
		if (flushed < 0)
			return -1;
		if (flushed == 0)
			return 0;
		if (tls->out_final) {
			if (QueryContextAttributesW(&tls->ctx, SECPKG_ATTR_STREAM_SIZES, &tls->sizes) !=
			    SEC_E_OK) {
				JLOG_WARN("Failed to query TLS stream sizes after handshake");
				return -1;
			}
			tls->handshake_done = true;
			return 1;
		}
		// Otherwise continue the handshake below
	}

	const DWORD flags_in = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
	                       ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

	// Received handshake messages accumulate in tls->cipher, where the data phase continues
	for (;;) {
		SecBuffer in_buffers[2];
		in_buffers[0].BufferType = SECBUFFER_TOKEN;
		in_buffers[0].pvBuffer = tls->ctx_valid ? tls->cipher.buf : NULL;
		in_buffers[0].cbBuffer = tls->ctx_valid ? (unsigned long)tls->cipher.len : 0;
		in_buffers[1].BufferType = SECBUFFER_EMPTY;
		in_buffers[1].pvBuffer = NULL;
		in_buffers[1].cbBuffer = 0;
		SecBufferDesc in_desc = {SECBUFFER_VERSION, 2, in_buffers};

		SecBuffer out_buffers[1];
		out_buffers[0].BufferType = SECBUFFER_TOKEN;
		out_buffers[0].pvBuffer = NULL;
		out_buffers[0].cbBuffer = 0;
		SecBufferDesc out_desc = {SECBUFFER_VERSION, 1, out_buffers};

		DWORD flags_out = 0;
		SECURITY_STATUS status = InitializeSecurityContextW(
		    &tls->cred, tls->ctx_valid ? &tls->ctx : NULL, tls->hostname, flags_in, 0,
		    SECURITY_NATIVE_DREP, tls->ctx_valid ? &in_desc : NULL, 0, &tls->ctx, &out_desc,
		    &flags_out, NULL);
		tls->ctx_valid = true;

		// Keep unconsumed bytes (the next message, or application data after the last one) before
		// sending anything, so a blocked send loses nothing
		if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
			if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
				memmove(tls->cipher.buf, tls->cipher.buf + (tls->cipher.len - in_buffers[1].cbBuffer),
				        in_buffers[1].cbBuffer);
				tls->cipher.len = in_buffers[1].cbBuffer;
			} else {
				tls->cipher.len = 0;
			}
		}

		// Send any token, even with a failure status (e.g. an alert), before handling the status
		if (out_buffers[0].cbBuffer && out_buffers[0].pvBuffer) {
			tls->out_buf = (char *)out_buffers[0].pvBuffer;
			tls->out_off = 0;
			tls->out_len = out_buffers[0].cbBuffer;
			tls->out_final = (status == SEC_E_OK);
			int flushed = tls_flush_pending_output(tls, sock);
			if (flushed < 0)
				return -1;
			if (flushed == 0)
				return 0;
		}

		if (status == SEC_E_OK) {
			// Bytes left in tls->cipher after the handshake are application data, which
			// tls_client_recv() decodes first
			if (QueryContextAttributesW(&tls->ctx, SECPKG_ATTR_STREAM_SIZES, &tls->sizes) !=
			    SEC_E_OK) {
				JLOG_WARN("Failed to query TLS stream sizes after handshake");
				return -1;
			}
			tls->handshake_done = true;
			return 1;
		}

		if (status == SEC_I_CONTINUE_NEEDED)
			continue;

		if (status == SEC_E_INCOMPLETE_MESSAGE) {
			if (tls->cipher.len >= sizeof(tls->cipher.buf)) {
				JLOG_WARN("TLS handshake message exceeds internal buffer");
				return -1;
			}
			int n = recv(sock, tls->cipher.buf + tls->cipher.len,
			             (int)(sizeof(tls->cipher.buf) - tls->cipher.len), 0);
			if (n < 0) {
				if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
					return 0;
				return -1;
			}
			if (n == 0)
				return -1;
			tls->cipher.len += (uint32_t)n;
			continue;
		}

		JLOG_WARN("TLS handshake failed, status=0x%lx", (unsigned long)status);
		return -1;
	}
}

// Encrypts buf[0..plain_size) in place: the plaintext is shifted right to make room for the
// record header, then EncryptMessage fills the header/trailer around it. On success the whole
// record (header+data+trailer) occupies buf[0..return value), ready to send() as-is.
int tls_encode(tls_client_t *tls, char *buf, size_t buf_capacity, size_t plain_size) {
	size_t header = tls->sizes.cbHeader;
	size_t trailer = tls->sizes.cbTrailer;
	if (plain_size > tls->sizes.cbMaximumMessage || header + plain_size + trailer > buf_capacity)
		return -SEMSGSIZE;

	memmove(buf + header, buf, plain_size);

	SecBuffer buffers[4];
	buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
	buffers[0].pvBuffer = buf;
	buffers[0].cbBuffer = (unsigned long)header;
	buffers[1].BufferType = SECBUFFER_DATA;
	buffers[1].pvBuffer = buf + header;
	buffers[1].cbBuffer = (unsigned long)plain_size;
	buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
	buffers[2].pvBuffer = buf + header + plain_size;
	buffers[2].cbBuffer = (unsigned long)trailer;
	buffers[3].BufferType = SECBUFFER_EMPTY;
	buffers[3].pvBuffer = NULL;
	buffers[3].cbBuffer = 0;
	SecBufferDesc desc = {SECBUFFER_VERSION, 4, buffers};

	SECURITY_STATUS status = EncryptMessage(&tls->ctx, 0, &desc, 0);
	if (status != SEC_E_OK) {
		JLOG_WARN("TLS encrypt failed, status=0x%lx", (unsigned long)status);
		return -1;
	}

	return (int)(buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer);
}

// Decrypts one TLS record from buf[0..len) in place. On success (1), *out_plaintext points
// within buf (no copy) and *out_plaintext_len is its size; *out_consumed is how many bytes of
// buf that record occupied (EXTRA, if any, is always the trailing buf[*out_consumed..len)).
// Returns 2 on the peer's close_notify, 0 if buf does not yet hold a complete record, <0 on
// fatal error.
static int tls_decode(tls_client_t *tls, char *buf, size_t len, char **out_plaintext,
                      size_t *out_plaintext_len, size_t *out_consumed) {
	if (len == 0)
		return 0;

	SecBuffer buffers[4];
	buffers[0].BufferType = SECBUFFER_DATA;
	buffers[0].pvBuffer = buf;
	buffers[0].cbBuffer = (unsigned long)len;
	for (int i = 1; i < 4; ++i) {
		buffers[i].BufferType = SECBUFFER_EMPTY;
		buffers[i].pvBuffer = NULL;
		buffers[i].cbBuffer = 0;
	}
	SecBufferDesc desc = {SECBUFFER_VERSION, 4, buffers};

	SECURITY_STATUS status = DecryptMessage(&tls->ctx, &desc, 0, NULL);

	if (status == SEC_E_INCOMPLETE_MESSAGE)
		return 0;

	if (status == SEC_I_CONTEXT_EXPIRED) {
		*out_plaintext = NULL;
		*out_plaintext_len = 0;
		*out_consumed = len;
		return 2; // peer sent close_notify
	}

	if (status == SEC_I_RENEGOTIATE) {
		JLOG_WARN("TLS peer requested renegotiation, not supported");
		return -1;
	}

	if (status != SEC_E_OK) {
		JLOG_WARN("TLS decrypt failed, status=0x%lx", (unsigned long)status);
		return -1;
	}

	char *data_ptr = NULL;
	unsigned long data_len = 0;
	unsigned long extra = 0;
	for (int i = 0; i < 4; ++i) {
		if (buffers[i].BufferType == SECBUFFER_DATA) {
			data_ptr = (char *)buffers[i].pvBuffer;
			data_len = buffers[i].cbBuffer;
		} else if (buffers[i].BufferType == SECBUFFER_EXTRA) {
			extra = buffers[i].cbBuffer;
		}
	}

	*out_plaintext = data_ptr;
	*out_plaintext_len = data_len;
	*out_consumed = len - extra;
	return 1;
}

int tls_client_recv(tls_client_t *tls, socket_t sock, char *dst, size_t cap) {
	tls_cipher_state_t *cs = &tls->cipher;

	for (;;) {
		if (cs->plain_len > 0) {
			uint32_t n = cs->plain_len < cap ? cs->plain_len : (uint32_t)cap;
			memcpy(dst, cs->buf + cs->plain_off, n);
			cs->plain_off += n;
			cs->plain_len -= n;
			return (int)n;
		}

		if (cs->len > 0) {
			char *pt;
			size_t pt_len, consumed;
			int ret = tls_decode(tls, cs->buf + cs->off, cs->len, &pt, &pt_len, &consumed);
			if (ret < 0)
				return -SECONNRESET;
			if (ret == 2)
				return 0; // peer's close_notify
			if (ret == 1) {
				// Decrypted in place: the plaintext lies within buf, and what follows the
				// consumed record is the start of the next one
				if (pt_len > 0)
					cs->plain_off = (uint32_t)(pt - cs->buf);
				cs->plain_len = (uint32_t)pt_len;
				cs->off += (uint32_t)consumed;
				cs->len -= (uint32_t)consumed;
				continue;
			}
			// ret == 0: the record is incomplete, receive more
		}

		uint32_t tail_free = (uint32_t)sizeof(cs->buf) - cs->off - cs->len;
		if (tail_free == 0) {
			if (cs->off == 0) {
				JLOG_WARN("TLS record exceeds internal buffer");
				return -SECONNRESET;
			}
			memmove(cs->buf, cs->buf + cs->off, cs->len);
			cs->off = 0;
			tail_free = (uint32_t)sizeof(cs->buf) - cs->len;
		}

		int n = recv(sock, cs->buf + cs->off + cs->len, (int)tail_free, 0);
		if (n < 0) {
			int ret = sockerrno;
			if (ret == SEAGAIN || ret == SEWOULDBLOCK)
				return -SEAGAIN;
			return -ret;
		}
		if (n == 0)
			return 0; // closed
		cs->len += (uint32_t)n;
	}
}

#endif // _WIN32 && USE_SCHANNEL
