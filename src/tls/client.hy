// Client TLS. enable upgrades a TCP fd in place: the Session.ptr is what
// ObjStream will store. Pass the same fd used by the Stream. WouldBlock means
// the VM should park the fd (COI-116) and continue via read/write, not enable again.

use io::{IoError};
use tls::{Session, wrap_session, option_string};

class ClientOpts {
    verify: bool,
    ca_pem: Option<string>,
    ca_path: Option<string>,
    timeout_ms: int,
    alpn: string,
}

extern "tls" {
    fn coil_tls_client_enable(int fd, string host, int verify, string ca_pem, string ca_path, int timeout_ms, string alpn, int err_out) -> int;
    fn coil_tls_disable(int session, int fd, int err_out);
}

fn verify_int(bool v) -> int {
    if v {
        return 1;
    }
    return 0;
}

fn enable(int fd, string host, ClientOpts opts) -> Result<Session, IoError> {
    let v = verify_int(opts.verify);
    let pem = option_string(opts.ca_pem);
    let path = option_string(opts.ca_path);
    let ptr = coil_tls_client_enable(fd, host, v, pem, path, opts.timeout_ms, opts.alpn, 0);
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
