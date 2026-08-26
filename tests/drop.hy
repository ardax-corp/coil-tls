// Session.drop calls coil_tls_free when ptr != 0. disable is close_notify
// only and must not zero ptr (Drop still owns the session). release zeros
// ptr without free. A live session pointer needs a TCP fd; Stream does not
// expose one, and a second extern "c" next to tls::abi stomps calloc/free.
// Native tests cover disable-then-free of real sessions. This file covers
// the ptr=0 path drop and release actually take.
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

test("session release of ptr 0 zeros ptr") {
    let s = new Session(0);
    let p = s.release();
    assert(p == 0)?;
    assert(s.ptr == 0)?;
}

test("session drop after release of ptr 0 is a no-op") {
    let s = new Session(0);
    let p = s.release();
    assert(p == 0)?;
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
