// Userland enable smoke. Handshake round-trips stay in native tests.
// enable(Stream, host, opts) must typecheck; file Stream is InvalidInput
// (same as leftover HostInvoke). Do not wrap a second Stream type.
use io::{open, IoError};
use tls::client::{enable, disable};
use tls::server::{enable as server_enable};
use tls::{alpn_protocol};

test("client enable on a file Stream is InvalidInput") {
    let r = match open("/tmp/coil_tls_enable_file.bin", "w") {
        Result::Ok(s) => enable(s, "127.0.0.1", { verify: false, ca_pem: Option::None, ca_path: Option::None, timeout_ms: 0, alpn: "" }),
        Result::Err(_) => Result::Err(IoError::Other),
    };
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => e == IoError::InvalidInput,
    };
    assert(ok, "expected InvalidInput")?;
}

test("server enable on a file Stream is InvalidInput") {
    let r = match open("/tmp/coil_tls_enable_server_file.bin", "w") {
        Result::Ok(s) => server_enable(s, { cert_pem: "", key_pem: "", timeout_ms: 0, client_ca_pem: "", alpn: "" }),
        Result::Err(_) => Result::Err(IoError::Other),
    };
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => e == IoError::InvalidInput,
    };
    assert(ok, "expected InvalidInput")?;
}

test("alpn_protocol on a file Stream is InvalidInput") {
    let r = match open("/tmp/coil_tls_alpn_file.bin", "w") {
        Result::Ok(s) => alpn_protocol(s),
        Result::Err(_) => Result::Err(IoError::Other),
    };
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => e == IoError::InvalidInput,
    };
    assert(ok, "expected InvalidInput")?;
}

test("disable on a file Stream is InvalidInput") {
    let r = match open("/tmp/coil_tls_disable_file.bin", "w") {
        Result::Ok(s) => disable(s),
        Result::Err(_) => Result::Err(IoError::Other),
    };
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => e == IoError::InvalidInput,
    };
    assert(ok, "expected InvalidInput")?;
}
