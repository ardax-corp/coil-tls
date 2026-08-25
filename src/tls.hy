// coil-tls userland. HTTP-facing enable/disable/alpn take Stream and call
// leftover HostInvoke so ObjStream becomes StreamKind::Tls.
//
// C ABI Session helpers live in `tls::abi` (fd + session pointer). They are
// not what coil-http imports.

use io::{Stream, IoError};
use io::net::tls::alpn_protocol as leftover_alpn;

fn alpn_protocol(Stream s) -> Result<string, IoError> {
    return leftover_alpn(s);
}
