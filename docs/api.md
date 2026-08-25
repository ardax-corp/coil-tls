# API

Module: `use tls::{client, server, alpn_protocol, Session};` (package name `tls` from `coil.toml`).

Locked design: [coil-tls design (v1)](https://linear.app/ardax/document/coil-tls-design-v1-d4fd96ddc404).

## In-place upgrade

`client::enable` / `server::enable` return a `Session` whose `ptr` is the native session pointer. coil-lang leftover stores that pointer on the existing `ObjStream` (`StreamKind::Tls`). Do not wrap a second Stream type.

Until that leftover lands, pass the TCP **fd** (`int`) that the Stream owns. `stream_read` / `stream_write` / close will dispatch through `coil_tls_read` / `coil_tls_write` / `coil_tls_disable` once the VM leftover is in.

## Types

```coil
class Session { ptr: int }

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

`Session.drop` calls `coil_tls_free`. Prefer `disable` so `close_notify` is sent. Until Finalizers ([COI-30](https://linear.app/ardax/issue/COI-30)) are guaranteed everywhere, call `disable` or `drop` yourself.

Handles are not thread-sendable.

## Functions

| Function | Description |
|----------|-------------|
| `client::enable(fd, host, opts)` | Client handshake. Returns `Session`. |
| `client::disable(session, fd)` | `close_notify` + free; resume plaintext on the same fd |
| `server::enable(fd, opts)` | Server handshake |
| `server::disable(session, fd)` | Same teardown as client disable |
| `alpn_protocol(session)` | Negotiated ALPN, or `""` |

All return `Result<_, IoError>`. `timeout_ms <= 0` means no handshake deadline. Extra `ca_pem` / `ca_path` **append** to webpki roots when `verify` is true. Empty `client_ca_pem` means no mTLS. `alpn` is `""`, `"h2"`, `"http/1.1"`, or a comma list.

`WouldBlock` means the fd is not ready. The VM parks it ([COI-116](https://linear.app/ardax/issue/COI-116)). Do not retry `enable` for the same handshake; continue with read/write on the returned session.

## C ABI

Declared in `extern "tls"` / `native/tls.h`. Symbols: `coil_tls_client_enable`, `coil_tls_server_enable`, `coil_tls_read`, `coil_tls_write`, `coil_tls_alpn`, `coil_tls_disable`, `coil_tls_free`. rustls is not called from `.hy`.
