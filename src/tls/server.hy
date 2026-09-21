// Server TLS. Same dload + Stream.attach + park as the client.
// First arg and return are Stream. Empty client_ca_pem means no mTLS.

use io::{Stream, IoError};
use tls::abi::{create_server, attach_and_handshake, disable_stream};

class ServerOpts {
    pub cert_pem: string,
    pub key_pem: string,
    pub timeout_ms: int,
    pub client_ca_pem: string,
    pub alpn: string,
}

fn enable(Stream s, ServerOpts opts) -> Result<Stream, IoError> {
    let ptr = create_server(s, opts.cert_pem, opts.key_pem, opts.timeout_ms, opts.client_ca_pem, opts.alpn)?;
    return attach_and_handshake(s, ptr)?;
}

fn disable(Stream s) -> Result<Stream, IoError> {
    return disable_stream(s)?;
}
