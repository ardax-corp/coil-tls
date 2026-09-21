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
    pub ptr: int,
}
