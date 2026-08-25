// Server TLS. Same leftover HostInvoke attach as the client: first arg and
// return are Stream. Empty client_ca_pem means no mTLS.

use io::{Stream, IoError};
use io::net::tls::server::enable as leftover_tls_server_enable;
use io::net::tls::server::disable as leftover_tls_server_disable;

class ServerOpts {
    cert_pem: string,
    key_pem: string,
    timeout_ms: int,
    client_ca_pem: string,
    alpn: string,
}

fn enable<T>(Stream s, T opts) -> Result<Stream, IoError> {
    return leftover_tls_server_enable(s, opts)?;
}

fn disable(Stream s) -> Result<Stream, IoError> {
    return leftover_tls_server_disable(s)?;
}
