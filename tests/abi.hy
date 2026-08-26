// Lower-level C ABI Session helpers. Not the HTTP-facing Stream API.
// File-fd coverage lives in native rust tests.
use io::{IoError};
use tls::abi::{enable_server_fd};

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
    let r = enable_server_fd(-1, "", "", 0, "", "");
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => is_cert_or_invalid(e),
    };
    assert(ok, "expected Certificate or InvalidInput")?;
}

test("abi server enable bad pem is Err") {
    let r = enable_server_fd(-1, "-----BEGIN CERTIFICATE-----\nnot-valid\n-----END CERTIFICATE-----\n", "-----BEGIN PRIVATE KEY-----\nalso-not\n-----END PRIVATE KEY-----\n", 0, "", "");
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => is_cert_or_invalid(e),
    };
    assert(ok, "expected Certificate or InvalidInput")?;
}
