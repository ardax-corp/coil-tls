//! IoErrorTag names and discriminants, matching coil-lang `machine/src/io.rs`.

use std::ffi::CStr;
use std::io::ErrorKind;

/// Tag indices for coil `IoError`. Append-only; keep discriminants aligned.
#[repr(i64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ErrorTag {
    WouldBlock = 0,
    NotFound = 1,
    PermissionDenied = 2,
    AlreadyClosed = 3,
    InvalidInput = 4,
    Other = 5,
    NotADirectory = 6,
    AlreadyExists = 7,
    TimedOut = 8,
    Truncated = 9,
    Certificate = 10,
    Handshake = 11,
}

impl ErrorTag {
    pub fn as_cstr(self) -> &'static CStr {
        match self {
            Self::WouldBlock => c"WouldBlock",
            Self::NotFound => c"NotFound",
            Self::PermissionDenied => c"PermissionDenied",
            Self::AlreadyClosed => c"AlreadyClosed",
            Self::InvalidInput => c"InvalidInput",
            Self::Other => c"Other",
            Self::NotADirectory => c"NotADirectory",
            Self::AlreadyExists => c"AlreadyExists",
            Self::TimedOut => c"TimedOut",
            Self::Truncated => c"Truncated",
            Self::Certificate => c"Certificate",
            Self::Handshake => c"Handshake",
        }
    }

    pub fn from_kind(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::WouldBlock => Self::WouldBlock,
            ErrorKind::TimedOut => Self::TimedOut,
            ErrorKind::NotFound => Self::NotFound,
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            ErrorKind::InvalidInput => Self::InvalidInput,
            ErrorKind::NotADirectory => Self::NotADirectory,
            ErrorKind::AlreadyExists => Self::AlreadyExists,
            ErrorKind::UnexpectedEof => Self::Truncated,
            _ => Self::Other,
        }
    }
}

pub fn map_io(e: std::io::Error) -> ErrorTag {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::Interrupted => ErrorTag::WouldBlock,
        other => ErrorTag::from_kind(other),
    }
}

pub fn map_tls_err(e: rustls::Error) -> ErrorTag {
    match e {
        rustls::Error::NoCertificatesPresented
        | rustls::Error::UnsupportedNameType
        | rustls::Error::InvalidCertificate(_) => ErrorTag::Certificate,
        _ => ErrorTag::Handshake,
    }
}

pub unsafe fn write_err(err_out: *mut *const std::os::raw::c_char, tag: ErrorTag) {
    if !err_out.is_null() {
        *err_out = tag.as_cstr().as_ptr();
    }
}

pub unsafe fn write_ok(err_out: *mut *const std::os::raw::c_char) {
    if !err_out.is_null() {
        *err_out = std::ptr::null();
    }
}
