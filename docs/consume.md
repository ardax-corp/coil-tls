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

`coil package` pins the library it embeds a lock for, so it also needs one `--ffi-native` row for the `tls` stem:

```bash
coil package --root ../coil-tls/src --allow-dload tls --dload-trusted tls --allow-attach --allow-net \
  --ffi-native name=tls,version=0.1.0,path=../coil-tls/native -o app main.hy
```

The packaged app looks for `libtls.so` in the natives cache, beside `app` or in its `lib/`. The package loads the library only as `dload("tls")`, never by path, so that one row is all `coil package` needs ([#17](https://github.com/ardax-corp/coil-tls/issues/17)).

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

This repo has no tags, so pin a commit with `--rev`. spool records the dep, writes `coil.lock` (`rev` + `content_hash`), links `.spool/deps/tls` to the checkout's `src/`, and passes that `src/` as a root. It also reads this repo's own `coil.toml` and resolves it against the checkout (spool#38): `[ffi] search_paths = ["./native"]` becomes `--ffi-search-path <checkout>/native`, and the `[[ffi.native]]` row for `tls` goes to `coil package`.

spool does not build or fetch `libtls`. Build it once in the checkout (untracked files do not change its tree id):

```bash
make -C "$(dirname "$(readlink -f .spool/deps/tls)")/native" artifact
```

Then grant it in the consumer `coil.toml`:

```toml
[module]
roots = ["./src"]

[permissions]
net = true
attach = true

[ffi]
allow = ["tls"]

[dependencies]
tls = { git = "https://github.com/ardax-corp/coil-tls.git", rev = "<commit SHA>", trusted = true }
```

`spool test` loads `<checkout>/native/libtls.so`. `spool build` / `spool run` package it (the pin is its sha256) and copy it into the natives cache, so `target/<name>` runs from any directory. `trusted = true` gives `--dload-trusted tls`. A `[[package.native]]` row with `sha256` under the `tls` package in `coil.lock` gives `--dload-pin tls=SHA256` instead.

A build elsewhere still works: put its directory in the consumer's own `[ffi] search_paths` (`["../coil-tls/native"]`). The consumer's paths come first, so that file is the one tested and packaged.

## Migrating from virtual `io::net::tls`

| Before (coil-lang builtin) | After (coil-tls) |
|----------------------------|------------------|
| `use io::net::tls::client::{enable, disable}` | `use tls::client::{enable, disable}` |
| `use io::net::tls::server::{enable, disable}` | `use tls::server::{enable, disable}` |
| `use io::net::tls::{alpn_protocol}` | `use tls::{alpn_protocol}` |
| Host rustls on `ObjStream` | `Stream.attach` with `coil_tls_*` session pointer on the same `Stream` |

coil-http keeps `use tls::{client, server}::enable`. Pass `ClientOpts` / `ServerOpts` (not leftover anonymous records).

Enable is dload create + `s.attach` + `s.park` on WouldBlock. Do not import leftover `io::__tls` from application code or from this package.
