//! Borrow a VM-owned socket fd without closing it.

use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::net::TcpStream;

/// `TcpStream` wrapper that does not close the fd on drop.
pub struct BorrowedTcp {
    inner: ManuallyDrop<TcpStream>,
}

impl BorrowedTcp {
    /// Wrap `fd` without taking ownership. Caller keeps the fd open.
    pub unsafe fn from_raw(fd: i64) -> Self {
        #[cfg(unix)]
        {
            use std::os::fd::{FromRawFd, RawFd};
            Self {
                inner: ManuallyDrop::new(TcpStream::from_raw_fd(fd as RawFd)),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::{FromRawSocket, RawSocket};
            Self {
                inner: ManuallyDrop::new(TcpStream::from_raw_socket(fd as RawSocket)),
            }
        }
    }

    pub fn set_nonblocking(&self, nb: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nb)
    }
}

impl Read for BorrowedTcp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for BorrowedTcp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
