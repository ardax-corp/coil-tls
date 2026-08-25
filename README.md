# coil-tls

Userland TLS for [coil](https://github.com/ardax-corp/coil-lang). rustls lives in a Rust cdylib (`libtls.so` / `.dylib` / `.dll`) loaded with `dload("tls")` / `extern "tls"`, not in the interpreter.

Package name is `tls`, so `use tls::{client, server}` and `use tls::alpn_protocol` keep working after the virtual `io::net::tls` module is removed.

Locked design: [coil-tls design (v1)](https://linear.app/ardax/document/coil-tls-design-v1-d4fd96ddc404) (accepted [COI-205](https://linear.app/ardax/issue/COI-205)).

## Layout

| Path | Role |
|------|------|
| `src/tls/client.hy` | `enable(Stream, host, opts) -> Result<Stream, IoError>` via leftover HostInvoke |
| `src/tls/server.hy` | `enable(Stream, opts)` / `disable(Stream)` |
| `src/tls.hy` | `alpn_protocol(Stream)` |
| `src/tls/abi.hy` | C ABI `Session` helpers (`coil_tls_*`); not the HTTP-facing API |
| `native/` | rustls 0.23 cdylib, C ABI `coil_tls_*` |
| `docs/` | API and consume notes |

Handshake stays non-blocking. Leftover HostInvoke does one rustls step, attaches the session, and parks WouldBlock on the VM ([COI-116](https://linear.app/ardax/issue/COI-116)). Do not handshake on a blocking thread.

## Build

```bash
cargo test --manifest-path native/Cargo.toml
cargo build --release --manifest-path native/Cargo.toml
# copy native/target/release/libtls.so (or .dylib / tls.dll) to native/
# so [ffi] search_paths = ["./native"] resolves dload("tls")
```

Sibling consume: `[module] roots` + `[ffi] search_paths` + built `libtls.so`. See [docs/consume.md](docs/consume.md).

## License

MIT — see [LICENSE](LICENSE).
