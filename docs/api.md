# API

Module: `use tls::{client, server, alpn_protocol};` (package name `tls` from `coil.toml`). How to depend: [consume.md](consume.md).

Locked design: [coil-tls design (v1)](https://linear.app/ardax/document/coil-tls-design-v1-d4fd96ddc404).

## In-place upgrade

`client::enable` / `server::enable` take a TCP `Stream` and return that same `Stream` with TLS attached via generic `Stream.attach`. coil-http keeps `enable(stream, host, opts) -> Result<Stream, IoError>`. Do not wrap a second Stream type. Do not use `enable(fd) -> Session` as the HTTP-facing API.

Enable is dload create (`coil_tls_*_enable`, Stream marshals to fd) + `s.attach(session, read, write, shutdown, free)` + empty `write`/`read` until Ready. `WouldBlock` parks with `s.park()` (`reactor_wait_fd_no_help`, COI-116). Do not retry `enable` for the same handshake. After attach, `s.read()` / `s.write()` / Drop go through the C vtable. This package does not import leftover `io::__tls`.

C ABI `Session` helpers are `tls::abi`. They talk `coil_tls_*` and do **not** attach. After attach, the Stream owns free; `Session.drop` of a released pointer is a no-op. `Session.drop` before attach still calls `coil_tls_free`.

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
| `client::enable(stream, host, opts)` | Client handshake. Returns the same `Stream`. |
| `client::disable(stream)` | `close_notify` only; Stream Drop still owns free |
| `server::enable(stream, opts)` | Server handshake |
| `server::disable(stream)` | Same teardown as client disable |
| `alpn_protocol(stream)` | Negotiated ALPN, or `""` |

All return `Result<_, IoError>`. `timeout_ms <= 0` means no handshake deadline. Extra `ca_pem` / `ca_path` **append** to webpki roots when `verify` is true. Empty `client_ca_pem` means no mTLS. `alpn` is `""`, `"h2"`, `"http/1.1"`, or a comma list.

A non-TCP Stream (for example a file from `open`) is `InvalidInput`. Successful empty write means handshake is done; empty read/write still pump handshake.

## C ABI (`tls::abi`)

Symbols live in `native/tls.h` and are reached with `dload` / `invoke` (not `extern "tls"`: worker VMs skip `ffi_init`). Leftover-shaped: `coil_tls_client_enable`, `coil_tls_server_enable`, `coil_tls_read`, `coil_tls_write`, `coil_tls_alpn`, `coil_tls_disable`, `coil_tls_free`. Attach-shaped wrappers (`coil_tls_stream_read` / `write` / `shutdown` / `free`) take the session pointer only; fd is stored in the session. `*_fn()` return those addresses for `Stream.attach`. rustls is not called from `.hy`. Userland passes `err_out` as `0` and reads `coil_tls_last_error` / `coil_tls_alpn_cstr`. `coil_tls_disable` is close_notify only (session stays valid). `coil_tls_free` is Drop. `tls::abi::disable` does not free or zero `Session.ptr`.
