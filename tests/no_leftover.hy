// Pin that userland enable is dload + Stream.attach, not leftover HostInvoke.
// This file typechecks and runs without `use io::__tls`.
use tls::client::{enable, ClientOpts};
use io::{open, IoError};

test("enable does not import leftover io::__tls") {
    let r = match open("/tmp/coil_tls_no_leftover.bin", "w") {
        Result::Ok(s) => enable(s, "127.0.0.1", new ClientOpts(false, Option::None, Option::None, 0, "")),
        Result::Err(_) => Result::Err(IoError::Other),
    };
    let ok = match r {
        Result::Ok(_) => false,
        Result::Err(e) => e == IoError::InvalidInput,
    };
    assert(ok, "expected InvalidInput without leftover")?;
}
