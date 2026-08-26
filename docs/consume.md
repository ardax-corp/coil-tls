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

`libtls.so` (or `.dylib` / `tls.dll`) must sit on `[ffi] search_paths` so `dload("tls")` resolves. `roots` must include this package's `src/` so `use tls::{client, server}` resolves here.

Needs coil-lang with `Stream.attach` / `Stream.park` ([coil-lang #204](https://github.com/ardax-corp/coil-lang/pull/204) until that lands on main).

Then:

```coil
use tls::client::{enable, disable, ClientOpts};
use tls::server::{enable as server_enable, disable as server_disable, ServerOpts};
use tls::{alpn_protocol};

let s = enable(tcp, "example.com", new ClientOpts(true, Option::None, Option::None, 0, ""))?;
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
| Host rustls on `ObjStream` | `Stream.attach` with `coil_tls_*` session pointer on the same `Stream` |

coil-http keeps `use tls::{client, server}::enable`. Pass `ClientOpts` / `ServerOpts` (not leftover anonymous records).

Enable is dload create + `s.attach` + `s.park` on WouldBlock. Do not import leftover `io::__tls` from application code or from this package.
