// Lower-level C ABI around `coil_tls_*`. Session.ptr is the native session
// pointer leftover HostInvoke stores on ObjStream. Prefer `tls::client::enable`
// (Stream) for HTTP. This module does not attach StreamKind::Tls.

use io::{IoError};

extern "c" {
    fn calloc(int n, int sz) -> int;
    fn free(int p);
}

extern "tls" {
    fn coil_tls_client_enable(int fd, string host, int verify, string ca_pem, string ca_path, int timeout_ms, string alpn, int err_out) -> int;
    fn coil_tls_server_enable(int fd, string cert_pem, string key_pem, int timeout_ms, string client_ca_pem, string alpn, int err_out) -> int;
    fn coil_tls_read(int session, int fd, int buf, int len, int err_out) -> int;
    fn coil_tls_write(int session, int fd, int buf, int len, int err_out) -> int;
    fn coil_tls_alpn(int session, int out, int out_len) -> int;
    fn coil_tls_disable(int session, int fd, int err_out);
    fn coil_tls_last_error() -> string;
    fn coil_tls_cstr(int p) -> string;
    fn coil_tls_free(int session);
}

class Session {
    ptr: int,
}

impl Session {
    fn drop() {
        if self.ptr != 0 {
            coil_tls_free(self.ptr);
            self.ptr = 0;
        }
    }
}

fn option_string(Option<string> v) -> string {
    return match v {
        Option::None => "",
        Option::Some(s) => s,
    };
}

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
    if tag == "Certificate" {
        return IoError::Certificate;
    }
    if tag == "Handshake" {
        return IoError::Handshake;
    }
    if tag == "NotFound" {
        return IoError::NotFound;
    }
    if tag == "PermissionDenied" {
        return IoError::PermissionDenied;
    }
    return IoError::Other;
}

fn err_slot() -> int {
    return calloc(1, 8);
}

fn wrap_session(int ptr) -> Result<Session, IoError> {
    if ptr == 0 {
        let name = coil_tls_last_error();
        if name == "" {
            raise IoError::Other;
        }
        raise io_error_from_name(name);
    }
    return new Session(ptr);
}

fn verify_int(bool v) -> int {
    if v {
        return 1;
    }
    return 0;
}

fn client_enable(int fd, string host, bool verify, Option<string> ca_pem, Option<string> ca_path, int timeout_ms, string alpn) -> Result<Session, IoError> {
    let slot = err_slot();
    if slot == 0 {
        raise IoError::Other;
    }
    let ptr = coil_tls_client_enable(fd, host, verify_int(verify), option_string(ca_pem), option_string(ca_path), timeout_ms, alpn, slot);
    free(slot);
    return wrap_session(ptr)?;
}

fn server_enable(int fd, string cert_pem, string key_pem, int timeout_ms, string client_ca_pem, string alpn) -> Result<Session, IoError> {
    let slot = err_slot();
    if slot == 0 {
        raise IoError::Other;
    }
    let ptr = coil_tls_server_enable(fd, cert_pem, key_pem, timeout_ms, client_ca_pem, alpn, slot);
    free(slot);
    return wrap_session(ptr)?;
}

fn disable(Session s, int fd) -> Result<(), IoError> {
    if s.ptr == 0 {
        raise IoError::InvalidInput;
    }
    let slot = err_slot();
    if slot == 0 {
        raise IoError::Other;
    }
    coil_tls_disable(s.ptr, fd, slot);
    free(slot);
    s.ptr = 0;
    return ();
}

fn alpn_protocol(Session s) -> Result<string, IoError> {
    if s.ptr == 0 {
        raise IoError::InvalidInput;
    }
    let n = coil_tls_alpn(s.ptr, 0, 0);
    if n < 0 {
        raise IoError::InvalidInput;
    }
    if n == 0 {
        return "";
    }
    let buf = calloc(n + 1, 1);
    if buf == 0 {
        raise IoError::Other;
    }
    coil_tls_alpn(s.ptr, buf, n);
    let proto = coil_tls_cstr(buf);
    free(buf);
    return proto;
}
