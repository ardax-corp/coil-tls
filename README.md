# coil-tls

TLS for [coil](https://github.com/ardax-corp/coil-lang) streams. `tls::client::enable` and `tls::server::enable` upgrade a TCP `Stream` to TLS in place, so the same stream's `read` / `write` are then encrypted; `tls::alpn_protocol` reads the negotiated protocol. rustls lives in a Rust cdylib (`libtls.so` / `.dylib` / `.dll`) loaded with `dload("tls")`, not in the interpreter.

Package name is `tls`, so `use tls::{client, server}` and `use tls::alpn_protocol` keep working after the virtual `io::net::tls` module is removed.

## Layout

| Path | Role |
|------|------|
| `src/tls/client.coil` | `tls::client`: `enable(Stream, host, ClientOpts)` / `disable(Stream)`, the client handshake |
| `src/tls/server.coil` | `tls::server`: `enable(Stream, ServerOpts)` / `disable(Stream)`, the server handshake |
| `src/tls.coil` | `tls`: `alpn_protocol(Stream)` |
| `src/tls/error.coil` | `tls::error`: `TlsError`, the error of every call |
| `src/tls/abi.coil` | package-internal C ABI `Session` helpers (`coil_tls_*`); not the public API |
| `native/` | rustls 0.23 cdylib, leftover-shaped `coil_tls_*` plus attach hooks |
| `docs/` | API and consume notes |

Handshake stays non-blocking. One rustls step per call, then `Stream.park` on WouldBlock. Do not handshake on a blocking thread.

Needs [coil-lang #204](https://github.com/ardax-corp/coil-lang/pull/204) (`Stream.attach` / `Stream.park`; leftover TLS deleted).

## Example

An HTTPS request (`main.coil`):

```coil
use io::{IoError};
use io::net::tcp::{connect};
use io::sync::{write_all, read_to_end, println};
use string::{format, from_bytes, to_bytes};
use tls::client::{enable, ClientOpts};
use tls::error::{TlsError};

fn io_err(IoError e) -> TlsError {
    return TlsError::Io(e);
}

// GET / over HTTPS; the raw response bytes.
fn fetch(string host) -> Result<Vec<byte>, TlsError> {
    let tcp = connect(host, 443).map_err(io_err)?;
    let s = enable(tcp, host, new ClientOpts(true, None, None, 10000, "http/1.1"))?;
    write_all(s, to_bytes("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")).map_err(io_err)?;
    return read_to_end(s).map_err(io_err)?;
}

fn main() {
    match fetch("example.com") {
        Ok(body) => println(from_bytes(body).unwrap_or("(not UTF-8)"))?,
        Err(e) => println(format("TLS failed: %v", e))?,
    };
}
```

With this repo and [coil-stdlib](https://github.com/ardax-corp/coil-stdlib) cloned next to your project and libtls built (below):

```bash
coil --root ../coil-tls/src --root ../coil-stdlib/src --ffi-search-path ../coil-tls/native \
  --allow-dload tls --dload-trusted tls --allow-attach --allow-net main.coil
```

A client and server handshake over loopback is in [examples/loopback.coil](examples/loopback.coil).

## Build

```bash
make -C native artifact   # cargo build --release, then copies libtls.so (or .dylib / tls.dll) into native/
make -C native test       # the native library's own tests
```

`--ffi-search-path ./native` then resolves `dload("tls")`. Prebuilt libraries for Linux, macOS and Windows are on the [`edge` release](https://github.com/ardax-corp/coil-tls/releases/tag/edge): unpack `coil-tls-native-<triple>.tar.gz` in the checkout root to get `native/libtls.*` (`SHA256SUMS` lists each library for `--dload-pin`).

## Test

```bash
coil test --allow-attach --allow-write --allow-dload tls --dload-pin tls=$(sha256sum native/libtls.so | cut -d' ' -f1) \
  --ffi-search-path native --root ../coil-stdlib/src   # tests and doc examples
```

Consume with `spool add tls --git https://github.com/ardax-corp/coil-tls.git --rev <commit SHA>` (no tags yet), or a sibling checkout plus `--root`, `--ffi-search-path`, `--allow-dload tls`, `--dload-trusted tls` (or `--dload-pin`) and `--allow-attach`; `coil package` also needs `--ffi-native name=tls,version=0.1.0,path=<native dir>`. spool reads this repo's `[ffi] search_paths` and `[[ffi.native]]` from its checkout, but does not build `libtls`. See [docs/consume.md](docs/consume.md).

## License

MIT — see [LICENSE](LICENSE).
