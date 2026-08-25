// Server TLS. Same in-place upgrade as the client: Session.ptr is the native
// session ObjStream will store. Empty client_ca_pem means no mTLS.

use io::{IoError};
use tls::{Session, wrap_session};

class ServerOpts {
    cert_pem: string,
    key_pem: string,
    timeout_ms: int,
    client_ca_pem: string,
    alpn: string,
}

extern "tls" {
    fn coil_tls_server_enable(int fd, string cert_pem, string key_pem, int timeout_ms, string client_ca_pem, string alpn, int err_out) -> int;
    fn coil_tls_disable(int session, int fd, int err_out);
}

fn enable(int fd, ServerOpts opts) -> Result<Session, IoError> {
    let ptr = coil_tls_server_enable(fd, opts.cert_pem, opts.key_pem, opts.timeout_ms, opts.client_ca_pem, opts.alpn, 0);
    return wrap_session(ptr)?;
}

fn disable(Session s, int fd) -> Result<(), IoError> {
    if s.ptr == 0 {
        raise IoError::InvalidInput;
    }
    coil_tls_disable(s.ptr, fd, 0);
    s.ptr = 0;
    return ();
}
