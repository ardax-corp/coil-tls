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

Then:

```coil
use tls::client::{enable, disable, ClientOpts};
use tls::server::{enable as server_enable, disable as server_disable, ServerOpts};
use tls::{alpn_protocol};
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
| Host rustls on `ObjStream` | Session ptr on `ObjStream`; rustls only in `libtls` |

coil-http keeps the same `enable(stream, host, opts)` call shape once coil-lang leftover attaches the session pointer to `Stream`. Until then this package's `enable` takes the TCP fd.
