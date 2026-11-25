# API

Module: `use tls::{client, server, TlsStream};` (package name `tls` from `coil.toml`). How to depend: [consume.md](consume.md).

## TlsStream

`client::enable` / `server::enable` take a connected TCP `Stream`, run the handshake and return a `TlsStream` over it. Leave the TCP stream to the `TlsStream` from then on: reading or writing it directly breaks the session.

`TlsStream` implements `io::Read`, `io::Write` and `io::Close`, so generic code bounded by them, and the stdlib's `io::sync` helpers and `io::buffered` `Reader` / `Writer`, take it:

| Call | Does |
|------|------|
| `s.read(buf)` | decrypted bytes into the front of `buf`: `Ok(Some(n))`, `Ok(None)` at the peer's close_notify, `Err(IoError::WouldBlock)` when nothing is ready |
| `s.write(buf)` | how many bytes of `buf` the session took, or `Err(IoError::WouldBlock)` |
| `s.wait_readable()` / `s.wait_writable()` | wait until a retry can make progress: for the socket to take writes when the session holds records to send, else for data |
| `s.close()` | close_notify, frees the session, closes the socket |
| `s.alpn()` | the negotiated ALPN protocol, or `""` |
| `s.disable()` | close_notify, frees the session, returns the TCP `Stream` (still open) |
| `s.tcp()` | the TCP `Stream` under the session |

After `close` or `disable`, every call is `IoError::AlreadyClosed` (`TlsError::Io(IoError::AlreadyClosed)` for `alpn` and `disable`). Dropping a `TlsStream` frees the session without close_notify. A TLS failure in `read` / `write` is `IoError::Protocol`.

The handshake does not block the thread: on `WouldBlock` it waits as `wait_readable` does. Do not handshake on a blocking thread.

## Types

```coil
class ClientOpts {
    verify: bool,
    ca_pem: Option<string>,
    ca_path: Option<string>,
    timeout_ms: int,
    alpn: string,
}

class ServerOpts {
    cert_pem: string,
    key_pem: string,
    timeout_ms: int,
    client_ca_pem: string,
    alpn: string,
}
```

Call sites pass `new ClientOpts(...)` / `new ServerOpts(...)`. Handles are not thread-sendable.

## Functions

| Function | Description |
|----------|-------------|
| `client::enable(stream, host, opts)` | Client handshake. Returns a `TlsStream`. |
| `server::enable(stream, opts)` | Server handshake. Returns a `TlsStream`. |

All return `Result<_, TlsError>`. `timeout_ms <= 0` means no handshake deadline. Extra `ca_pem` / `ca_path` **append** to webpki roots when `verify` is true. Empty `client_ca_pem` means no mTLS. `alpn` is `""`, `"h2"`, `"http/1.1"`, or a comma list.

A non-TCP Stream (for example a file from `open`) is `TlsError::Io(IoError::InvalidInput)`.

## Errors

`tls::error::TlsError` (derives `Show` and `Eq`):

| Variant | When |
|---|---|
| `Certificate` | the peer's certificate (or the configured one) was rejected |
| `Handshake` | the TLS handshake or record layer failed |
| `Io(IoError)` | the socket failed, or the input was invalid (a non-TCP Stream, a bad PEM) |

`IoError` itself has no TLS variants: a `TlsStream`'s `read` / `write` report `IoError::Protocol` on a TLS failure.

## C ABI (`tls::abi`)

Symbols live in `native/tls.h` and are called through the `extern "tls"` block: `coil_tls_client_enable`, `coil_tls_server_enable`, `coil_tls_read`, `coil_tls_write`, `coil_tls_wants_write`, `coil_tls_alpn_cstr`, `coil_tls_disable`, `coil_tls_free`. Buffers go as `Bytes` / `ConstBytes`; userland passes `err_out` as `0` and reads `coil_tls_last_error`. `coil_tls_disable` is close_notify only (the session stays valid); `coil_tls_free` frees it. The `Session` class there is for the package's own tests: `Session.drop` frees a pointer it still holds.
