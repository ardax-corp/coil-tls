// TLS for coil streams, backed by rustls in the native `libtls` library.
// `tls::client::enable` / `tls::server::enable` upgrade a TCP `Stream` to TLS
// in place, `alpn_protocol` (here) reads the negotiated protocol, and
// `tls::error::TlsError` is the error of all of them. Enable is dload create
// + Stream.attach + park; rustls stays in libtls.

use io::{Stream};
use tls::error::{TlsError};
use tls::abi::{session_for_stream, alpn_at};

/// The ALPN protocol negotiated on the TLS stream `s` (for example `"h2"`),
/// or `""` when the peers agreed on none.
///
/// Call it after `tls::client::enable` or `tls::server::enable` returned
/// the stream.
///
/// # Errors
///
/// `TlsError::Io(IoError::InvalidInput)` when `s` has no TLS session (TLS was
/// never enabled on it, or it is not a socket); `TlsError::Io(IoError::NotFound)`
/// when the native library cannot be loaded.
///
/// # Examples
///
/// ```no_run
/// use io::{Stream};
/// use tls::{alpn_protocol};
/// use tls::client::{enable, ClientOpts};
/// use tls::error::{TlsError};
///
/// // `tcp` is a connected socket, from `io::net::tcp::connect(host, 443)`.
/// fn speaks_h2(Stream tcp, string host) -> Result<bool, TlsError> {
///     let s = enable(tcp, host, new ClientOpts(true, None, None, 10000, "h2,http/1.1"))?;
///     return alpn_protocol(s)? == "h2";
/// }
/// # fn main() {}
/// ```
fn alpn_protocol(Stream s) -> Result<string, TlsError> {
    let ptr = session_for_stream(s);
    return alpn_at(ptr)?;
}
