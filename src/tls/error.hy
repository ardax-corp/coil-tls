// The error of the coil-tls API: a TLS failure of its own, or the
// stream's IoError. An argument the native side rejects (a bad host name or
// PEM, a stream that is not a socket) is `Io(IoError::InvalidInput)`.
use io::IoError;

/// The error of every `tls` call: a TLS failure of its own, or the
/// stream's `IoError`.
///
/// It derives `Show` and `Eq`. A TLS stream's own `read` and `write` keep
/// returning `IoError` (`IoError::Protocol` on a TLS failure).
///
/// # Examples
///
/// ```
/// use io::{IoError};
/// use tls::error::{TlsError};
/// # use tests::assert;
/// fn describe(TlsError e) -> string {
///     return match e {
///         TlsError::Certificate => "certificate rejected",
///         TlsError::Handshake => "handshake failed",
///         TlsError::Io(IoError::TimedOut) => "timed out",
///         TlsError::Io(_) => "connection failed",
///     };
/// }
///
/// fn main() {
///     assert!(describe(TlsError::Io(IoError::TimedOut)) == "timed out");
///     assert!(TlsError::Handshake != TlsError::Certificate);
/// }
/// ```
#[derive(Show, Eq)]
enum TlsError {
    /// The peer's certificate was rejected (untrusted, wrong name, missing).
    Certificate,
    /// The TLS handshake failed for any other reason, or the peer sent an alert.
    Handshake,
    /// The underlying stream failed, or an argument was rejected
    /// (`IoError::InvalidInput`: a bad host name or PEM, a stream that is not
    /// a socket).
    Io(IoError),
}

// A native tag name (`tls.h`) as a `TlsError`.
fn tls_error_from_name(string tag) -> TlsError {
    if tag == "Certificate" {
        return TlsError::Certificate;
    }
    if tag == "Handshake" {
        return TlsError::Handshake;
    }
    return TlsError::Io(io_error_from_name(tag));
}

// A native tag name as the `IoError` of a stream call.
fn io_error_from_name(string tag) -> IoError {
    if tag == "WouldBlock" {
        return IoError::WouldBlock;
    }
    if tag == "AlreadyClosed" {
        return IoError::AlreadyClosed;
    }
    if tag == "InvalidInput" {
        return IoError::InvalidInput;
    }
    if tag == "TimedOut" {
        return IoError::TimedOut;
    }
    if tag == "Truncated" {
        return IoError::Truncated;
    }
    if tag == "Certificate" || tag == "Handshake" {
        return IoError::Protocol;
    }
    if tag == "NotFound" {
        return IoError::NotFound;
    }
    if tag == "PermissionDenied" {
        return IoError::PermissionDenied;
    }
    return IoError::Other;
}
