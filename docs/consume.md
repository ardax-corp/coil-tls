# Consuming coil-tls

## Sibling checkout (until spool)

In your project's `coil.toml`:

```toml
[module]
roots = ["./src", "../coil-tls/src"]

[ffi]
search_paths = ["../coil-tls/native"]
```

Build the native library (from this package root):

```bash
make -C native artifact
```

`libtls.so` (or `.dylib` / `tls.dll`) must sit on `[ffi] search_paths` so leftover HostInvoke can `dload("tls")`. `roots` must include this package's `src/` so `use tls::{client, server}` resolves here, not a missing virtual module.

Then:

```coil
use tls::client::{enable, disable};
use tls::server::{enable as server_enable, disable as server_disable};
use tls::{alpn_protocol};

let s = enable(tcp, "example.com", {
    verify: true,
    ca_pem: Option::None,
    ca_path: Option::None,
    timeout_ms: 0,
    alpn: "",
})?;
```

## Spool (future)

```toml
[dependencies]
tls = { git = "https://github.com/ardax-corp/coil-tls.git", version = "^0.1" }

[module]
roots = ["./src", "./.spool/deps/tls/src"]

[ffi]
search_paths = ["./.spool/deps/tls/native"]
```

## Migrating from virtual `io::net::tls`

| Before (coil-lang builtin) | After (coil-tls) |
|----------------------------|------------------|
| `use io::net::tls::client::{enable, disable}` | `use tls::client::{enable, disable}` |
| `use io::net::tls::server::{enable, disable}` | `use tls::server::{enable, disable}` |
| `use io::net::tls::{alpn_protocol}` | `use tls::{alpn_protocol}` |
| Host rustls on `ObjStream` | leftover HostInvoke attaches a `coil_tls_*` session pointer on the same `Stream` |

coil-http keeps `enable(stream, host, opts) -> Result<Stream, IoError>`.

## Leftover HostInvoke

`tls::client::enable` is a thin wrapper around leftover HostInvoke `tls_client_enable` (same for server enable/disable and `alpn_protocol`). That is what stores `StreamKind::Tls` on `ObjStream`. Talking only `coil_tls_*` and returning a `Session` does not attach, so later `stream_read` / `stream_write` stay plaintext TCP.

Coil userland emits `HostInvoke` only when the compiler still has a binding (virtual module `IoFn` / `HostFn`, not `extern` / `dload`). There is no `native fn` syntax.

On current coil-lang, that binding is virtual `io::net::tls::{client,server}` (surface `enable` → registry `tls_client_enable`, ids 25–28 and 121). This package imports that path and re-exports it as `tls::client::enable` so coil-http can `use tls::…`.

[coil-lang #199](https://github.com/ardax-corp/coil-lang/pull/199) deletes virtual `use tls` / `use io::net::tls` while keeping leftover HostInvoke bodies. After that lands, this wrapper cannot compile unless #199 exports leftover under a name that is **not** `tls` / `io::net::tls` (or restores leftover `IoBuiltin` exports). The fix for that compile break is on coil-lang, not a second Stream type here.
