// Lower-level C ABI Session helpers. Not the HTTP-facing Stream API.
// File-fd coverage lives in native rust tests; a second extern "c" in this
// file stomps the libc handle used by tls::abi (calloc / free).
use io::{IoError};
use tls::abi::{server_enable};

fn is_cert_or_invalid(IoError e) -> bool {
    if e == IoError::Certificate {
        return true;
    }
    if e == IoError::InvalidInput {
        return true;
    }
    return false;
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
