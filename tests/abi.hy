// Lower-level C ABI Session helpers. Not the HTTP-facing Stream API.
use io::{IoError};
use tls::abi::{client_enable, server_enable};

extern "c" {
    fn creat(string path, int mode) -> int;
    fn close(int fd) -> int;
}

fn is_invalid_or_other(IoError e) -> bool {
    if e == IoError::InvalidInput {
        return true;
    }
    if e == IoError::Other {
        return true;
    }
    return false;
}

fn is_cert_or_invalid(IoError e) -> bool {
    if e == IoError::Certificate {
        return true;
    }
    if e == IoError::InvalidInput {
        return true;
    }
    return false;
}

test("abi client enable on a file fd is Err") {
    let fd = creat("/tmp/coil_tls_abi_smoke.bin", 420);
    assert(fd >= 0, "creat")?;
    let r = client_enable(fd, "127.0.0.1", false, Option::None, Option::None, 0, "");
    close(fd);
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => is_invalid_or_other(e),
    };
    assert(ok, "expected InvalidInput or Other")?;
}

test("abi server enable empty cert is Err") {
    let r = server_enable(-1, "", "", 0, "", "");
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => is_cert_or_invalid(e),
    };
    assert(ok, "expected Certificate or InvalidInput")?;
}

test("abi server enable bad pem is Err") {
    let r = server_enable(-1, "-----BEGIN CERTIFICATE-----\nnot-valid\n-----END CERTIFICATE-----\n", "-----BEGIN PRIVATE KEY-----\nalso-not\n-----END PRIVATE KEY-----\n", 0, "", "");
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => is_cert_or_invalid(e),
    };
    assert(ok, "expected Certificate or InvalidInput")?;
}
