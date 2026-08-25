# API

Module: `use tls::{client, server, alpn_protocol};` (package name `tls` from `coil.toml`).

Locked design: [coil-tls design (v1)](https://linear.app/ardax/document/coil-tls-design-v1-d4fd96ddc404).

## In-place upgrade

`client::enable` / `server::enable` take a TCP `Stream` and return that same `Stream` with TLS attached (`StreamKind::Tls`). coil-http keeps `enable(stream, host, opts) -> Result<Stream, IoError>`. Do not wrap a second Stream type. Do not use `enable(fd) -> Session` as the HTTP-facing API.

Attachment is leftover HostInvoke (`tls_client_enable` / `tls_server_enable` / disable / `tls_alpn_protocol`, ids 25–28 and 121). The native dloads `coil_tls_*`, stores the session pointer on `ObjStream`, parks WouldBlock on `reactor_wait_fd_no_help` ([COI-116](https://linear.app/ardax/issue/COI-116)), and does not retry enable. `stream_read` / `stream_write` / close then go through `coil_tls_*`.

C ABI `Session` helpers are `tls::abi`. They talk `coil_tls_*` and do **not** attach `StreamKind::Tls`.

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

Call sites may pass a record with the same fields (coil-http does). Handles are not thread-sendable.

## Functions

| Function | Description |
|----------|-------------|
| `client::enable(stream, host, opts)` | Client handshake. Returns the same `Stream`. |
| `client::disable(stream)` | `close_notify` + free; resume plaintext on the same Stream |
| `server::enable(stream, opts)` | Server handshake |
| `server::disable(stream)` | Same teardown as client disable |
| `alpn_protocol(stream)` | Negotiated ALPN, or `""` |

All return `Result<_, IoError>`. `timeout_ms <= 0` means no handshake deadline. Extra `ca_pem` / `ca_path` **append** to webpki roots when `verify` is true. Empty `client_ca_pem` means no mTLS. `alpn` is `""`, `"h2"`, `"http/1.1"`, or a comma list.

A non-TCP Stream (for example a file from `open`) is `InvalidInput`. `WouldBlock` during enable is parked by leftover HostInvoke; the call returns `Ok(Stream)`. Do not retry `enable` for the same handshake; continue with read/write.

## C ABI (`tls::abi`)

Declared in `extern "tls"` / `native/tls.h`. Symbols: `coil_tls_client_enable`, `coil_tls_server_enable`, `coil_tls_read`, `coil_tls_write`, `coil_tls_alpn`, `coil_tls_disable`, `coil_tls_free`. rustls is not called from `.hy`. `err_out` is a pointer slot, not literal `0`. `coil_tls_disable` is close_notify only (session stays valid). `coil_tls_free` is Drop. `tls::abi::disable` does not free or zero `Session.ptr`.
