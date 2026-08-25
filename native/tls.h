/* coil-tls C ABI — rustls 0.23 cdylib for coil FFI (`dload("tls")`). */

#ifndef COIL_TLS_H
#define COIL_TLS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * err_out: optional. On error (and on WouldBlock), written to a static
 * NUL-terminated IoErrorTag name matching coil-lang:
 *   Handshake, Certificate, TimedOut, WouldBlock, InvalidInput,
 *   AlreadyClosed, Truncated, Other, plus the rest of IoErrorTag
 *   (NotFound, PermissionDenied, …).
 * On success, written to NULL.
 *
 * enable returns a session pointer (opaque, > 0) or 0 on hard failure.
 * WouldBlock during handshake still returns the session; the caller parks
 * the fd (COI-116) and continues via coil_tls_read / coil_tls_write.
 * Do not call enable again for the same handshake.
 *
 * timeout_ms <= 0 means no handshake deadline.
 * Empty ca_pem / ca_path / alpn / client_ca_pem means unset.
 * verify: 0 = skip trust/name checks, 1 = webpki roots (+ extras).
 *
 * The fd is never closed by this library. Set O_NONBLOCK; WouldBlock is a
 * tagged error, not a hang. Handshake is not offloaded to a thread.
 */

int64_t coil_tls_client_enable(
    int64_t fd,
    const char *host,
    int64_t verify,
    const char *ca_pem,
    const char *ca_path,
    int64_t timeout_ms,
    const char *alpn,
    const char **err_out
);

int64_t coil_tls_server_enable(
    int64_t fd,
    const char *cert_pem,
    const char *key_pem,
    int64_t timeout_ms,
    const char *client_ca_pem,
    const char *alpn,
    const char **err_out
);

/* Returns nbytes, 0 on clean EOF, -1 on error (see err_out). */
int64_t coil_tls_read(
    int64_t session,
    int64_t fd,
    uint8_t *buf,
    int64_t len,
    const char **err_out
);

int64_t coil_tls_write(
    int64_t session,
    int64_t fd,
    const uint8_t *buf,
    int64_t len,
    const char **err_out
);

/* Writes negotiated ALPN into out (not NUL-terminated). Returns nbytes
 * copied, 0 if none, -1 if session is invalid. If out is NULL or out_len
 * is 0, returns the ALPN byte length without copying so the caller can
 * size a buffer. */
int64_t coil_tls_alpn(int64_t session, uint8_t *out, int64_t out_len);

/* close_notify (best effort) then free. */
void coil_tls_disable(int64_t session, int64_t fd, const char **err_out);

void coil_tls_free(int64_t session);

/* Last IoErrorTag name on this thread, or empty. Used when err_out is NULL. */
const char *coil_tls_last_error(void);

/* Borrow a NUL-terminated C string for Coil `-> string` (null becomes ""). */
const char *coil_tls_cstr(const char *p);

#ifdef __cplusplus
}
#endif

#endif
