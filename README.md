# coil-tls

TLS for [coil](https://github.com/ardax-corp/coil-lang) streams. `tls::client::enable` and `tls::server::enable` run a handshake on a TCP `Stream` and return a `tls::TlsStream`, which implements `io::Read`, `io::Write` and `io::Close`: anything bounded by those traits (`io::sync::write_all`, `io::buffered::Reader`, an HTTP connection) takes it as it takes a `Stream`. `s.alpn()` reads the negotiated protocol and `s.disable()` hands back the TCP stream. rustls lives in a Rust cdylib (`libtls.so` / `.dylib` / `.dll`) called through an `extern "tls"` block, not built into coil.

## Layout

| Path | Role |
|------|------|
| `src/tls/client.coil` | `tls::client`: `enable(Stream, host, ClientOpts) -> TlsStream`, the client handshake |
| `src/tls/server.coil` | `tls::server`: `enable(Stream, ServerOpts) -> TlsStream`, the server handshake |
| `src/tls/stream.coil` | `tls::stream::TlsStream` (also `tls::TlsStream`): `Read`, `Write`, `Close`, `alpn()`, `disable()` |
| `src/tls/error.coil` | `tls::error`: `TlsError`, the error of every call |
| `src/tls/abi.coil` | package-internal C ABI helpers (`coil_tls_*`); not the public API |
| `native/` | rustls 0.23 cdylib, `coil_tls_*` (`native/tls.h`) |
| `docs/` | API and consume notes |

Nothing blocks the thread. `read` and `write` return `IoError::WouldBlock` when the socket is not ready, and `wait_readable` / `wait_writable` wait the way the session needs (a read can need to send a record first), which lets other tasks run. The handshake waits the same way.

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
    let body = read_to_end(s).map_err(io_err)?;
    s.close().map_err(io_err)?;
    return body;
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
  --allow-dload tls --dload-trusted tls --allow-net main.coil
```

A client and server handshake over loopback is in [examples/loopback.coil](examples/loopback.coil).

## Build

```bash
make -C native artifact   # cargo build --release, then copies libtls.so (or .dylib / tls.dll) into native/
make -C native test       # the native library's own tests
```

`--ffi-search-path ./native` then finds the `extern "tls"` library. Prebuilt libraries for Linux, macOS and Windows are on the [`edge` release](https://github.com/ardax-corp/coil-tls/releases/tag/edge): unpack `coil-tls-native-<triple>.tar.gz` in the checkout root to get `native/libtls.*` (`SHA256SUMS` lists each library for `--dload-pin`).

## Test

```bash
coil test --allow-write --allow-net --allow-dload tls --dload-pin tls=$(sha256sum native/libtls.so | cut -d' ' -f1) \
  --ffi-search-path native --root ../coil-stdlib/src   # tests and doc examples
```

Consume with `spool add tls --git https://github.com/ardax-corp/coil-tls.git --rev <commit SHA>` (no tags yet), or a sibling checkout plus `--root`, `--ffi-search-path`, `--allow-dload tls`, and `--dload-trusted tls` (or `--dload-pin`); `coil package` also needs `--ffi-native name=tls,version=0.1.0,path=<native dir>`. spool reads this repo's `[ffi] search_paths` and `[[ffi.native]]` from its checkout, but does not build `libtls`. See [docs/consume.md](docs/consume.md).

## License

MIT — see [LICENSE](LICENSE).
