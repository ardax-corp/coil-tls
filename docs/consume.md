# Consuming coil-tls

This package is `tls`. `use tls::{client, server}` and `use tls::{alpn_protocol}` resolve from this repo's `src/`. rustls lives in `libtls.so` / `.dylib` / `tls.dll`. `client::enable` / `server::enable` call `dload("tls")` inside the package. Put the built library on the FFI search path (`--ffi-search-path`). Needs coil-lang with `Stream.attach` / `Stream.park` ([coil-lang #204](https://github.com/ardax-corp/coil-lang/pull/204)).

API: [api.md](api.md). Handshake demo: [examples/loopback.hy](../examples/loopback.hy).

## Sibling checkout

Clone this repo next to your project and build the native library from this package root:

```bash
make -C native artifact
```

`make artifact` copies `libtls.so` (or `.dylib` / `tls.dll`) into `native/`. coil reads no `coil.toml` and no `coil.lock`, so pass everything as flags:

```bash
coil --root ../coil-tls/src --ffi-search-path ../coil-tls/native \
  --allow-dload tls --dload-trusted tls --allow-attach --allow-net main.hy
```

`--dload-pin tls=<sha256 of libtls.so>` instead of `--dload-trusted tls` pins the build. `enable` needs `--allow-attach` (`Stream.attach`). Opening the TCP stream needs `--allow-net`.

Then:

```coil
use tls::client::{enable, disable, ClientOpts};
use tls::server::{enable as server_enable, disable as server_disable, ServerOpts};
use tls::{alpn_protocol};

let s = enable(tcp, "example.com", new ClientOpts(true, Option::None, Option::None, 0, ""))?;
```

## With spool

```bash
spool add tls --git https://github.com/ardax-corp/coil-tls.git --rev <commit SHA>
```

This repo has no tags, so pin a commit with `--rev`. spool records the dep, writes `coil.lock` (`rev` + `content_hash`), links `.spool/deps/tls` to the checkout's `src/`, and passes `--root` for it. spool does not build or fetch `libtls`; build it in a checkout (above) and grant it in the consumer `coil.toml`:

```toml
[module]
roots = ["./src", ".spool/deps/tls"]

[permissions]
net = true
attach = true

[ffi]
search_paths = ["../coil-tls/native"]
allow = ["tls"]

[dependencies]
tls = { git = "https://github.com/ardax-corp/coil-tls.git", rev = "<commit SHA>", trusted = true }
```

The extra root is needed because `tls::client` / `tls::server` live in `src/tls/`: through the `.spool/deps` root alone, `use tls::client::{…}` looks for `src/client.hy` and fails. `trusted = true` gives `--dload-trusted tls`. A `[[package.native]]` row with `sha256` under the `tls` package in `coil.lock` gives `--dload-pin tls=SHA256` instead.

## Migrating from virtual `io::net::tls`

| Before (coil-lang builtin) | After (coil-tls) |
|----------------------------|------------------|
| `use io::net::tls::client::{enable, disable}` | `use tls::client::{enable, disable}` |
| `use io::net::tls::server::{enable, disable}` | `use tls::server::{enable, disable}` |
| `use io::net::tls::{alpn_protocol}` | `use tls::{alpn_protocol}` |
| Host rustls on `ObjStream` | `Stream.attach` with `coil_tls_*` session pointer on the same `Stream` |

coil-http keeps `use tls::{client, server}::enable`. Pass `ClientOpts` / `ServerOpts` (not leftover anonymous records).

Enable is dload create + `s.attach` + `s.park` on WouldBlock. Do not import leftover `io::__tls` from application code or from this package.
