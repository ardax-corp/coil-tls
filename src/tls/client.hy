// Client side of TLS: `enable` upgrades a connected TCP `Stream` to TLS in
// place (the same Stream, not a second Stream type) and `disable` sends
// close_notify. Create via dload, then Stream.attach + park until the
// handshake is Ready.

use io::{Stream};
use tls::error::{TlsError};
use tls::abi::{create_client, attach_and_handshake, disable_stream};

/// How `enable` sets up a client session: certificate checks, extra trusted
/// roots, the handshake deadline and the ALPN protocols to offer.
///
/// # Examples
///
/// ```
/// use tls::client::{ClientOpts};
/// # use tests::assert;
/// // Check the server against the bundled roots, give the handshake 10 s,
/// // and offer HTTP/2 before HTTP/1.1.
/// let opts = new ClientOpts(true, Option::None, Option::None, 10000, "h2,http/1.1");
/// assert!(opts.verify && opts.ca_pem.is_none());
///
/// // Also trust a private CA, read from a PEM file.
/// let private = new ClientOpts(true, Option::None, Option::Some("ca.pem"), 0, "");
/// assert!(private.timeout_ms == 0);
/// ```
class ClientOpts {
    /// Check the server's certificate chain and that it names the host.
    /// `false` skips both (handshake signatures are still checked), which
    /// is only safe for tests against a self-signed server.
    pub verify: bool,
    /// Extra trusted root certificates, as PEM text, added to the bundled
    /// Mozilla roots when `verify` is `true`.
    pub ca_pem: Option<string>,
    /// A PEM file of extra trusted root certificates, added like `ca_pem`.
    pub ca_path: Option<string>,
    /// The handshake deadline in milliseconds; `0` or less means none.
    pub timeout_ms: int,
    /// The ALPN protocols to offer, most preferred first, as a comma list
    /// (`"h2,http/1.1"`); `""` offers none.
    pub alpn: string,
}

/// Runs a TLS client handshake on the connected TCP stream `s` and returns
/// the same `Stream`, now encrypted.
///
/// `host` is the server name sent in SNI and checked against the server's
/// certificate (a DNS name or an IP address). After `enable`, the stream's
/// `read`, `write` and close go through TLS. The handshake does not block
/// the thread: on `WouldBlock` it parks the task until the socket is ready,
/// so call it from a normal task, not a blocking thread. Do not call
/// `enable` twice on one stream.
///
/// The program needs `--allow-attach`, `--allow-dload tls` and libtls on
/// the FFI search path (see the package README).
///
/// # Errors
///
/// - `TlsError::Certificate` when the server's certificate is untrusted,
///   expired or for another name;
/// - `TlsError::Handshake` for any other handshake failure or an alert;
/// - `TlsError::Io(e)` when the socket fails (`IoError::TimedOut` past
///   `timeout_ms`), and `Io(IoError::InvalidInput)` for an empty or invalid
///   `host`, a bad `ca_pem`, or a stream that is not a socket.
///
/// # Examples
///
/// An HTTPS request over a socket the caller connected:
///
/// ```no_run
/// use io::{IoError, Stream};
/// use io::sync::{write_all, read_to_end};
/// use string::{to_bytes};
/// use tls::client::{enable, ClientOpts};
/// use tls::error::{TlsError};
///
/// fn io_err(IoError e) -> TlsError {
///     return TlsError::Io(e);
/// }
///
/// // `tcp` is a connected socket, from `io::net::tcp::connect(host, 443)`.
/// fn fetch(Stream tcp, string host) -> Result<Vec<byte>, TlsError> {
///     let s = enable(tcp, host, new ClientOpts(true, None, None, 10000, "http/1.1"))?;
///     let request = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
///     write_all(s, to_bytes(request)).map_err(io_err)?;
///     return read_to_end(s).map_err(io_err)?;
/// }
/// # fn main() {}
/// ```
fn enable(Stream s, string host, ClientOpts opts) -> Result<Stream, TlsError> {
    let ptr = create_client(s, host, opts.verify, opts.ca_pem, opts.ca_path, opts.timeout_ms, opts.alpn)?;
    return attach_and_handshake(s, ptr)?;
}

/// Sends TLS `close_notify` to the peer and returns `s`.
///
/// It only announces the end of the TLS session: the socket stays open and
/// the session is freed when the stream is closed or dropped.
///
/// # Errors
///
/// `TlsError::Io(IoError::InvalidInput)` when `s` has no TLS session.
// close_notify only. Stream Drop still owns free through the vtable.
fn disable(Stream s) -> Result<Stream, TlsError> {
    return disable_stream(s)?;
}
