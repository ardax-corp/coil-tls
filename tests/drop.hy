// Session.drop calls coil_tls_free when ptr != 0. A live session pointer
// needs a TCP fd; Stream does not expose one, and a second extern "c" next
// to tls::abi stomps calloc/free. Native tests cover coil_tls_free(0) and
// free of real sessions. This file covers the ptr=0 path drop actually takes.
use gc::{collect};
use io::{IoError};
use tls::abi::{Session, disable};

test("session drop of ptr 0 is a no-op") {
    let s = new Session(0);
    s.drop();
    assert(s.ptr == 0)?;
}

test("session drop of ptr 0 is idempotent") {
    let s = new Session(0);
    s.drop();
    s.drop();
    assert(s.ptr == 0)?;
}

test("session drop after disable of ptr 0 is safe") {
    let s = new Session(0);
    let r = disable(s, -1);
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => e == IoError::InvalidInput,
    };
    assert(ok, "expected InvalidInput")?;
    s.drop();
    assert(s.ptr == 0)?;
}

fn ephemeral_session() {
    let s = new Session(0);
}

test("session drop of ptr 0 is safe across collect") {
    ephemeral_session();
    collect();
    assert(true)?;
}
