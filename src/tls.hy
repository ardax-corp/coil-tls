// coil-tls userland. HTTP-facing enable/disable/alpn take Stream and call
// leftover HostInvoke (`io::__tls`) so ObjStream becomes StreamKind::Tls.
//
// C ABI Session helpers live in `tls::abi` (fd + session pointer). They are
// not what coil-http imports.

use io::{Stream, IoError};
use io::__tls::alpn_protocol as leftover_tls_alpn_protocol;

fn alpn_protocol(Stream s) -> Result<string, IoError> {
    return leftover_tls_alpn_protocol(s)?;
}
