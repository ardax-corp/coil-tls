// Server side of TLS: `enable` runs the server handshake on an accepted TCP
// `Stream` in place, with the certificate and key in `ServerOpts`; `disable`
// sends close_notify. Same dload + Stream.attach + park as the client.

use io::{Stream};
use tls::error::{TlsError};
use tls::abi::{create_server, attach_and_handshake, disable_stream};

/// How `enable` sets up a server session: the certificate and key to
/// present, the handshake deadline, client certificates and ALPN.
///
/// # Examples
///
/// ```
/// use tls::server::{ServerOpts};
/// # use tests::assert;
/// let cert = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n";
/// let key = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n";
/// // No client certificates; prefer HTTP/2, fall back to HTTP/1.1.
/// let opts = new ServerOpts(cert, key, 5000, "", "h2,http/1.1");
/// assert!(opts.client_ca_pem == "" && opts.alpn == "h2,http/1.1");
/// ```
class ServerOpts {
    /// The server's certificate chain as PEM text, leaf first.
    pub cert_pem: string,
    /// The private key of the leaf certificate as PEM text (PKCS#8, PKCS#1
    /// or SEC1).
    pub key_pem: string,
    /// The handshake deadline in milliseconds; `0` or less means none.
    pub timeout_ms: int,
    /// PEM root certificates that client certificates must chain to. Any
    /// value but `""` requires clients to present a certificate (mutual
    /// TLS); `""` asks for none.
    pub client_ca_pem: string,
    /// The ALPN protocols the server accepts, most preferred first, as a
    /// comma list (`"h2,http/1.1"`); `""` negotiates none.
    pub alpn: string,
}

/// Runs a TLS server handshake on the accepted TCP stream `s` and returns
/// the same `Stream`, now encrypted.
///
/// As with the client, the stream's `read`, `write` and close go through TLS
/// afterwards, and the handshake parks the task on `WouldBlock` instead of
/// blocking the thread. Read the negotiated protocol with
/// `tls::alpn_protocol`. The program needs `--allow-attach`, `--allow-dload
/// tls` and libtls on the FFI search path.
///
/// # Errors
///
/// - `TlsError::Io(IoError::InvalidInput)` for a certificate or key that does
///   not parse, a key that does not match, a bad `client_ca_pem`, or a stream
///   that is not a socket;
/// - `TlsError::Certificate` when a required client certificate is rejected;
/// - `TlsError::Handshake` for any other handshake failure or an alert;
/// - `TlsError::Io(e)` when the socket fails (`IoError::TimedOut` past
///   `timeout_ms`).
///
/// # Examples
///
/// Greeting one client on a listening socket:
///
/// ```no_run
/// use io::{IoError, Stream, close};
/// use io::sync::{accept_wait, write_all};
/// use string::{to_bytes};
/// use tls::server::{enable, ServerOpts};
/// use tls::error::{TlsError};
///
/// fn io_err(IoError e) -> TlsError {
///     return TlsError::Io(e);
/// }
///
/// // `listener` is from `io::net::tcp::listen("0.0.0.0", 8443)`; the PEM
/// // text from `io::file::read_text("cert.pem")` and so on.
/// fn greet_one(Stream listener, string cert, string key) -> Result<(), TlsError> {
///     let tcp = accept_wait(listener).map_err(io_err)?;
///     let s = enable(tcp, new ServerOpts(cert, key, 10000, "", ""))?;
///     write_all(s, to_bytes("hello over TLS\n")).map_err(io_err)?;
///     close(s).map_err(io_err)?;
///     return;
/// }
/// # fn main() {}
/// ```
fn enable(Stream s, ServerOpts opts) -> Result<Stream, TlsError> {
    let ptr = create_server(s, opts.cert_pem, opts.key_pem, opts.timeout_ms, opts.client_ca_pem, opts.alpn)?;
    return attach_and_handshake(s, ptr)?;
}

/// Sends TLS `close_notify` to the client and returns `s`, as
/// `tls::client::disable` does.
///
/// # Errors
///
/// `TlsError::Io(IoError::InvalidInput)` when `s` has no TLS session.
fn disable(Stream s) -> Result<Stream, TlsError> {
    return disable_stream(s)?;
}
