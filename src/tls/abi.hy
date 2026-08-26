// Lower-level C ABI around `coil_tls_*`. Session.ptr is the native session
// pointer. After Stream.attach, the Stream owns free; Session.drop of a
// released ptr is a no-op. Prefer `tls::client::enable` for HTTP.
//
// No `extern "tls"` / `extern "c"`: worker VMs do not run ffi_init, so those
// handles are invalid. dload + invoke, with `./native/libtls.so` as fallback
// when spawn workers have empty FFI search paths.

use io::{Stream, IoError, write, read};
use ffi::{declare, dload, invoke, Error};
use ffi::types::{Int, String, Void};

class Session {
    ptr: int,
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

fn verify_int(bool v) -> int {
    if v {
        return 1;
    }
    return 0;
}

fn tls_lib() -> Result<int, IoError> {
    match dload("tls") {
        Result::Ok(h) => {
            return h;
        },
        Result::Err(_) => 0,
    };
    match dload("./native/libtls.so") {
        Result::Ok(h) => {
            return h;
        },
        Result::Err(_) => {
            raise IoError::NotFound;
        },
    };
}

fn native_last_error() -> Result<string, Error> {
    let lib = match dload("tls") {
        Result::Ok(h) => h,
        Result::Err(_) => {
            match dload("./native/libtls.so") {
                Result::Ok(h) => h,
                Result::Err(e) => { raise e; },
            }
        },
    };
    let last_fn = declare(lib, "coil_tls_last_error", (), String)?;
    return invoke(lib, last_fn, ())?;
}

fn alpn_string(int lib, int ptr) -> Result<string, Error> {
    let alpn_fn = declare(lib, "coil_tls_alpn_cstr", (Int,), String)?;
    return invoke(lib, alpn_fn, (ptr,))?;
}

fn hook_addr(int lib, string name) -> Result<int, IoError> {
    let id = match declare(lib, name, (), Int) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    return match invoke(lib, id, ()) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
}

fn native_free(int lib, int ptr) {
    let id = match declare(lib, "coil_tls_free", (Int,), Void) {
        Result::Ok(v) => v,
        Result::Err(_) => { return; },
    };
    match invoke(lib, id, (ptr,)) {
        Result::Ok(_) => 0,
        Result::Err(_) => 0,
    };
}

impl Session {
    fn drop() {
        if self.ptr != 0 {
            let p = self.ptr;
            self.ptr = 0;
            match dload("tls") {
                Result::Ok(lib) => {
                    match declare(lib, "coil_tls_free", (Int,), Void) {
                        Result::Ok(id) => {
                            match invoke(lib, id, (p,)) {
                                Result::Ok(_) => {},
                                Result::Err(_) => {},
                            };
                        },
                        Result::Err(_) => {},
                    };
                },
                Result::Err(_) => {},
            };
        }
    }

    fn release() -> int {
        let p = self.ptr;
        self.ptr = 0;
        return p;
    }
}

fn session_ptr_or_raise(int ptr) -> Result<int, IoError> {
    if ptr == 0 {
        let name = match native_last_error() {
            Result::Ok(s) => s,
            Result::Err(_) => "",
        };
        if name == "" {
            raise IoError::Other;
        }
        raise io_error_from_name(name);
    }
    return ptr;
}

fn wrap_session(int ptr) -> Result<Session, IoError> {
    let p = session_ptr_or_raise(ptr)?;
    return new Session(p);
}

fn enable_client_fd(int fd, string host, bool verify, Option<string> ca_pem, Option<string> ca_path, int timeout_ms, string alpn) -> Result<Session, IoError> {
    let lib = tls_lib()?;
    let id = match declare(lib, "coil_tls_client_enable", (Int, String, Int, String, String, Int, String, Int), Int) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    let ptr = match invoke(lib, id, (fd, host, verify_int(verify), option_string(ca_pem), option_string(ca_path), timeout_ms, alpn, 0)) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    return wrap_session(ptr)?;
}

fn enable_server_fd(int fd, string cert_pem, string key_pem, int timeout_ms, string client_ca_pem, string alpn) -> Result<Session, IoError> {
    let lib = tls_lib()?;
    let id = match declare(lib, "coil_tls_server_enable", (Int, String, String, Int, String, String, Int), Int) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    let ptr = match invoke(lib, id, (fd, cert_pem, key_pem, timeout_ms, client_ca_pem, alpn, 0)) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    return wrap_session(ptr)?;
}

fn create_client(Stream s, string host, bool verify, Option<string> ca_pem, Option<string> ca_path, int timeout_ms, string alpn) -> Result<int, IoError> {
    let lib = tls_lib()?;
    let id = match declare(lib, "coil_tls_client_enable", (Int, String, Int, String, String, Int, String, Int), Int) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    let ptr = match invoke(lib, id, (s, host, verify_int(verify), option_string(ca_pem), option_string(ca_path), timeout_ms, alpn, 0)) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    return session_ptr_or_raise(ptr)?;
}

fn create_server(Stream s, string cert_pem, string key_pem, int timeout_ms, string client_ca_pem, string alpn) -> Result<int, IoError> {
    let lib = tls_lib()?;
    let id = match declare(lib, "coil_tls_server_enable", (Int, String, String, Int, String, String, Int), Int) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    let ptr = match invoke(lib, id, (s, cert_pem, key_pem, timeout_ms, client_ca_pem, alpn, 0)) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    return session_ptr_or_raise(ptr)?;
}

fn disable(Session s, int fd) -> Result<(), IoError> {
    if s.ptr == 0 {
        raise IoError::InvalidInput;
    }
    let lib = tls_lib()?;
    let id = match declare(lib, "coil_tls_disable", (Int, Int, Int), Void) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    match invoke(lib, id, (s.ptr, fd, 0)) {
        Result::Ok(_) => 0,
        Result::Err(_) => { raise IoError::Other; },
    };
    return ();
}

fn alpn_at(int ptr) -> Result<string, IoError> {
    if ptr == 0 {
        raise IoError::InvalidInput;
    }
    let lib = tls_lib()?;
    return match alpn_string(lib, ptr) {
        Result::Ok(s) => s,
        Result::Err(_) => { raise IoError::Other; },
    };
}

fn alpn_protocol(Session s) -> Result<string, IoError> {
    return alpn_at(s.ptr)?;
}

fn session_for_stream(Stream s) -> int {
    let lib = match tls_lib() {
        Result::Ok(h) => h,
        Result::Err(_) => { return 0; },
    };
    let id = match declare(lib, "coil_tls_session_for_fd", (Int,), Int) {
        Result::Ok(v) => v,
        Result::Err(_) => { return 0; },
    };
    return match invoke(lib, id, (s,)) {
        Result::Ok(v) => v,
        Result::Err(_) => 0,
    };
}

fn disable_stream(Stream s) -> Result<Stream, IoError> {
    let lib = tls_lib()?;
    let lookup = match declare(lib, "coil_tls_session_for_fd", (Int,), Int) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    let ptr = match invoke(lib, lookup, (s,)) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    if ptr == 0 {
        raise IoError::InvalidInput;
    }
    let id = match declare(lib, "coil_tls_disable", (Int, Int, Int), Void) {
        Result::Ok(v) => v,
        Result::Err(_) => { raise IoError::Other; },
    };
    match invoke(lib, id, (ptr, s, 0)) {
        Result::Ok(_) => 0,
        Result::Err(_) => { raise IoError::Other; },
    };
    return s;
}

fn handshake_until_ready(Stream s) -> Result<Stream, IoError> {
    while true {
        let wbuf: Vec<byte> = Vec::new();
        match write(s, wbuf) {
            Result::Ok(_) => {
                return s;
            },
            Result::Err(e) => {
                if e != IoError::WouldBlock {
                    raise e;
                }
            },
        };
        let rbuf: Vec<byte> = Vec::new();
        match read(s, rbuf) {
            Result::Ok(_) => {
                return s;
            },
            Result::Err(e) => {
                if e != IoError::WouldBlock {
                    raise e;
                }
            },
        };
        s.park()?;
    }
}

fn attach_and_handshake(Stream s, int ptr) -> Result<Stream, IoError> {
    let lib = tls_lib()?;
    let read_fn = hook_addr(lib, "coil_tls_stream_read_fn")?;
    let write_fn = hook_addr(lib, "coil_tls_stream_write_fn")?;
    let shutdown_fn = hook_addr(lib, "coil_tls_stream_shutdown_fn")?;
    let free_fn = hook_addr(lib, "coil_tls_stream_free_fn")?;
    match s.attach(ptr, read_fn, write_fn, shutdown_fn, free_fn) {
        Result::Ok(attached) => {
            return handshake_until_ready(attached)?;
        },
        Result::Err(e) => {
            native_free(lib, ptr);
            raise e;
        },
    };
}
