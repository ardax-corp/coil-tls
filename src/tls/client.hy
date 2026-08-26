// Client TLS. In-place TCP→TLS on the same Stream (not a second Stream type).
// Create via dload, then Stream.attach + park until handshake Ready.

use io::{Stream, IoError};
use tls::abi::{create_client, attach_and_handshake, disable_stream};

class ClientOpts {
    verify: bool,
    ca_pem: Option<string>,
    ca_path: Option<string>,
    timeout_ms: int,
    alpn: string,
}

fn enable(Stream s, string host, ClientOpts opts) -> Result<Stream, IoError> {
    let ptr = create_client(s, host, opts.verify, opts.ca_pem, opts.ca_path, opts.timeout_ms, opts.alpn)?;
    return attach_and_handshake(s, ptr)?;
}

// close_notify only. Stream Drop still owns free through the vtable.
fn disable(Stream s) -> Result<Stream, IoError> {
    return disable_stream(s)?;
}
