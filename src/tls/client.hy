// Client TLS. In-place TCP→TLS on the same Stream (not a second Stream type).
// Body is leftover HostInvoke `tls_client_enable` / `tls_client_disable`
// (compiler export: virtual `io::net::tls::client` today). That native
// dloads coil_tls_*, attach_enable_outcome, parks WouldBlock (COI-116).
// Do not call coil_tls_* here and return a Session — ObjStream would stay TCP.

use io::{Stream, IoError};
use io::net::tls::client::enable as leftover_tls_client_enable;
use io::net::tls::client::disable as leftover_tls_client_disable;

class ClientOpts {
    verify: bool,
    ca_pem: Option<string>,
    ca_path: Option<string>,
    timeout_ms: int,
    alpn: string,
}

fn enable<T>(Stream s, string host, T opts) -> Result<Stream, IoError> {
    return leftover_tls_client_enable(s, host, opts)?;
}

fn disable(Stream s) -> Result<Stream, IoError> {
    return leftover_tls_client_disable(s)?;
}
