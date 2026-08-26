# Consuming coil-tls

This package is `tls`. `use tls::{client, server}` and `use tls::{alpn_protocol}` resolve from this repo's `src/`. rustls lives in `libtls.so` / `.dylib` / `tls.dll`. `client::enable` / `server::enable` call `dload("tls")` inside the package. Put the built library on `[ffi] search_paths`. Needs coil-lang with `Stream.attach` / `Stream.park` ([coil-lang #204](https://github.com/ardax-corp/coil-lang/pull/204) until that lands on main).

Coil-to-Coil deps will be spool-owned once a public `spool` CLI exists. Until [COI-219](https://linear.app/ardax/issue/COI-219) the pin is `coil.lock` `rev` + `content_hash`. A git dep still needs `{ git, version }` so `coil.toml` parses (E0900). `version` is a parser field, not a tag. Native libs stay on `[ffi] search_paths` until [COI-60](https://linear.app/ardax/issue/COI-60).

API: [api.md](api.md). Handshake demo: [examples/loopback.hy](../examples/loopback.hy).

## Sibling checkout

In the consumer `coil.toml`:

```toml
[module]
roots = ["./src", "../coil-tls/src"]

[ffi]
search_paths = ["../coil-tls/native"]
```

Build the native library from this package root:

```bash
make -C native artifact
```

`libtls.so` (or `.dylib` / `tls.dll`) must sit on `[ffi] search_paths` so `dload("tls")` resolves. `roots` must include this package's `src/` so `use tls::{client, server}` resolves here.

Then:

```coil
use tls::client::{enable, disable, ClientOpts};
use tls::server::{enable as server_enable, disable as server_disable, ServerOpts};
use tls::{alpn_protocol};

let s = enable(tcp, "example.com", new ClientOpts(true, Option::None, Option::None, 0, ""))?;
```

## coil.lock pin (until spool)

Git deps still need `{ git, version }` or coil-lang reports E0900. `version` is a parser field, not a tag. This repo has no tags. Do not run `spool add tls`. There is no public spool CLI.

Until [COI-219](https://linear.app/ardax/issue/COI-219) the pin is `coil.lock` `rev` + `content_hash`. The compiler does not read `coil.lock` and does not inject roots. Native libs stay on `[ffi] search_paths` until [COI-60](https://linear.app/ardax/issue/COI-60).

```toml
[dependencies]
tls = { git = "https://github.com/ardax-corp/coil-tls.git", version = "^0.1" }

[module]
roots = ["./src", "./.spool/deps/tls/src"]

[ffi]
search_paths = ["./.spool/deps/tls/native"]
```

`^0.1` does not resolve a tag. It is there so `coil.toml` parses. Pin the commit in `coil.lock` with `git`, `rev`, and `content_hash`. Omit `tag`.

```
# spool lockfile v1
[[package]]
name = 'tls'
git = 'https://github.com/ardax-corp/coil-tls.git'
rev = '053bf366b346304f4e9be3b8a0ffabb5d2d41f56'
content_hash = 'f3dfe09e8feb1edb85f6beb7f8981c7fab2b59bf'
```

`rev` is the commit. `content_hash` is that commit's git tree (`git rev-parse 'HEAD^{tree}'`). Replace both when you move the pin. The values above are `main` at `053bf36` (enable via `Stream.attach`). They are an example, not a release.

Clone that rev onto the path listed in `roots`. `.spool/deps/tls` is the layout spool will use later:

```bash
git clone https://github.com/ardax-corp/coil-tls.git .spool/deps/tls
git -C .spool/deps/tls checkout --detach 053bf366b346304f4e9be3b8a0ffabb5d2d41f56
test "$(git -C .spool/deps/tls rev-parse 'HEAD^{tree}')" = f3dfe09e8feb1edb85f6beb7f8981c7fab2b59bf
make -C .spool/deps/tls/native artifact
```

`make artifact` copies `libtls.so` (or `.dylib` / `tls.dll`) into that `native/` dir. Leave it on `[ffi] search_paths`. Spool will not fetch the cdylib until [COI-60](https://linear.app/ardax/issue/COI-60).

## Migrating from virtual `io::net::tls`

| Before (coil-lang builtin) | After (coil-tls) |
|----------------------------|------------------|
| `use io::net::tls::client::{enable, disable}` | `use tls::client::{enable, disable}` |
| `use io::net::tls::server::{enable, disable}` | `use tls::server::{enable, disable}` |
| `use io::net::tls::{alpn_protocol}` | `use tls::{alpn_protocol}` |
| Host rustls on `ObjStream` | `Stream.attach` with `coil_tls_*` session pointer on the same `Stream` |

coil-http keeps `use tls::{client, server}::enable`. Pass `ClientOpts` / `ServerOpts` (not leftover anonymous records).

Enable is dload create + `s.attach` + `s.park` on WouldBlock. Do not import leftover `io::__tls` from application code or from this package.
