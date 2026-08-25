# coil-tls

Userland TLS for [coil](https://github.com/ardax-corp/coil-lang). rustls lives in a Rust cdylib (`libtls.so` / `.dylib` / `.dll`) loaded with `dload("tls")` / `extern "tls"`, not in the interpreter.

Package name is `tls`, so `use tls::{client, server}` and `use tls::alpn_protocol` keep working after the virtual `io::net::tls` module is removed.

Locked design: [coil-tls design (v1)](https://linear.app/ardax/document/coil-tls-design-v1-d4fd96ddc404) (accepted [COI-205](https://linear.app/ardax/issue/COI-205)).

## Layout

| Path | Role |
|------|------|
| `src/` | Coil userland (`client::enable` / `disable`, `server::enable` / `disable`, `alpn_protocol`) |
| `native/` | rustls 0.23 cdylib, C ABI `coil_tls_*` |
| `docs/` | API and consume notes |

Handshake stays non-blocking. One call does as much rustls work as the fd allows, then returns `WouldBlock` so the VM can park the fd ([COI-116](https://linear.app/ardax/issue/COI-116)). Do not handshake on a blocking thread.

The native session pointer is what `ObjStream` will store (`StreamKind::Tls`). This package does not invent a second Stream type.

## Build

```bash
cargo test --manifest-path native/Cargo.toml
cargo build --release --manifest-path native/Cargo.toml
# copy native/target/release/libtls.so (or .dylib / tls.dll) to native/
# so [ffi] search_paths = ["./native"] resolves dload("tls")
```

## License

MIT — see [LICENSE](LICENSE).
