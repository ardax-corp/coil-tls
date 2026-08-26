// coil-tls userland. HTTP-facing enable/disable/alpn take Stream.
// Enable is dload create + Stream.attach + park. rustls stays in libtls.so.

use io::{Stream, IoError};
use tls::abi::{session_for_stream, alpn_at};

fn alpn_protocol(Stream s) -> Result<string, IoError> {
    let ptr = session_for_stream(s);
    return alpn_at(ptr)?;
}
