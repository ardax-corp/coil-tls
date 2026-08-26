// Userland enable/disable/opts smoke. Handshake round-trips stay in examples/loopback.hy.
// enable(Stream, host, ClientOpts) must typecheck; file Stream is InvalidInput.
// Do not wrap a second Stream type. Do not import io::__tls.
use io::{open, IoError};
use tls::client::{enable, disable, ClientOpts};
use tls::server::{enable as server_enable, disable as server_disable, ServerOpts};
use tls::{alpn_protocol};

test("client enable on a file Stream is InvalidInput") {
    let r = match open("/tmp/coil_tls_enable_file.bin", "w") {
        Result::Ok(s) => enable(s, "127.0.0.1", new ClientOpts(false, Option::None, Option::None, 0, "")),
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
        Result::Ok(s) => server_enable(s, new ServerOpts("", "", 0, "", "")),
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

test("server disable on a file Stream is InvalidInput") {
    let r = match open("/tmp/coil_tls_server_disable_file.bin", "w") {
        Result::Ok(s) => server_disable(s),
        Result::Err(_) => Result::Err(IoError::Other),
    };
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => e == IoError::InvalidInput,
    };
    assert(ok, "expected InvalidInput")?;
}

test("client enable empty host is InvalidInput") {
    let r = match open("/tmp/coil_tls_enable_empty_host.bin", "w") {
        Result::Ok(s) => enable(s, "", new ClientOpts(false, Option::None, Option::None, 0, "")),
        Result::Err(_) => Result::Err(IoError::Other),
    };
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => e == IoError::InvalidInput,
    };
    assert(ok, "expected InvalidInput")?;
}

test("server enable bad pem is InvalidInput") {
    let r = match open("/tmp/coil_tls_enable_bad_pem.bin", "w") {
        Result::Ok(s) => server_enable(s, new ServerOpts("-----BEGIN CERTIFICATE-----\nnot-valid\n-----END CERTIFICATE-----\n", "-----BEGIN PRIVATE KEY-----\nalso-not\n-----END PRIVATE KEY-----\n", 0, "", "")),
        Result::Err(_) => Result::Err(IoError::Other),
    };
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => e == IoError::InvalidInput,
    };
    assert(ok, "expected InvalidInput")?;
}
