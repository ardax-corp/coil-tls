// Userland enable smoke. Stream has no public fd, so handshake round-trips
// stay in native tests. Do not wrap a second Stream type.
use io::{IoError};
use tls::client::{enable, ClientOpts};
use tls::server::{enable as server_enable, ServerOpts};

extern "c" {
    fn creat(string path, int mode) -> int;
    fn close(int fd) -> int;
}

fn client_opts() -> ClientOpts {
    return new ClientOpts(false, Option::None, Option::None, 0, "");
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

test("client enable on a file fd is Err") {
    let fd = creat("/tmp/coil_tls_smoke.bin", 420);
    assert(fd >= 0, "creat")?;
    let r = enable(fd, "127.0.0.1", client_opts());
    close(fd);
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => is_invalid_or_other(e),
    };
    assert(ok, "expected InvalidInput or Other")?;
}

test("server enable empty cert is Err") {
    let opts = new ServerOpts("", "", 0, "", "");
    let r = server_enable(-1, opts);
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => is_cert_or_invalid(e),
    };
    assert(ok, "expected Certificate or InvalidInput")?;
}

test("server enable bad pem is Err") {
    let opts = new ServerOpts("-----BEGIN CERTIFICATE-----\nnot-valid\n-----END CERTIFICATE-----\n", "-----BEGIN PRIVATE KEY-----\nalso-not\n-----END PRIVATE KEY-----\n", 0, "", "");
    let r = server_enable(-1, opts);
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => is_cert_or_invalid(e),
    };
    assert(ok, "expected Certificate or InvalidInput")?;
}
