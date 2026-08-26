//! rustls session: non-blocking handshake pump, app read/write, close_notify.

use std::io::{ErrorKind, Read, Write};
use std::time::Instant;

use rustls::{ClientConnection, Connection, ServerConnection};

use crate::error::{map_io, map_tls_err, ErrorTag};
use crate::fd::BorrowedTcp;

pub struct TlsSession {
    conn: Connection,
    plaintext: Vec<u8>,
    plaintext_pos: usize,
    deadline: Option<Instant>,
    handshake_done: bool,
    /// VM-owned socket. Attach hooks have no fd argument, so enable stores it.
    fd: i64,
}

impl TlsSession {
    pub fn from_client(conn: ClientConnection, deadline: Option<Instant>, fd: i64) -> Self {
        Self {
            conn: Connection::Client(conn),
            plaintext: Vec::new(),
            plaintext_pos: 0,
            deadline,
            handshake_done: false,
            fd,
        }
    }

    pub fn from_server(conn: ServerConnection, deadline: Option<Instant>, fd: i64) -> Self {
        Self {
            conn: Connection::Server(conn),
            plaintext: Vec::new(),
            plaintext_pos: 0,
            deadline,
            handshake_done: false,
            fd,
        }
    }

    pub fn fd(&self) -> i64 {
        self.fd
    }

    pub fn into_raw(self) -> i64 {
        Box::into_raw(Box::new(self)) as i64
    }

    pub unsafe fn from_raw<'a>(ptr: i64) -> Result<&'a mut Self, ErrorTag> {
        if ptr <= 0 {
            return Err(ErrorTag::InvalidInput);
        }
        Ok(&mut *(ptr as *mut Self))
    }

    pub unsafe fn free(ptr: i64) {
        if ptr <= 0 {
            return;
        }
        drop(Box::from_raw(ptr as *mut Self));
    }

    fn check_deadline(&self) -> Result<(), ErrorTag> {
        if let Some(end) = self.deadline {
            if Instant::now() >= end {
                return Err(ErrorTag::TimedOut);
            }
        }
        Ok(())
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        self.conn.alpn_protocol().unwrap_or(&[])
    }

    fn drain_plaintext_into(&mut self, out: &mut [u8]) -> usize {
        let avail = self.plaintext.len() - self.plaintext_pos;
        if avail == 0 || out.is_empty() {
            return 0;
        }
        let n = avail.min(out.len());
        out[..n].copy_from_slice(&self.plaintext[self.plaintext_pos..self.plaintext_pos + n]);
        self.plaintext_pos += n;
        if self.plaintext_pos >= self.plaintext.len() {
            self.plaintext.clear();
            self.plaintext_pos = 0;
        }
        n
    }

    fn pull_plaintext_from_conn(&mut self) -> Result<(), ErrorTag> {
        loop {
            let mut tmp = [0u8; 16 * 1024];
            match self.conn.reader().read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => self.plaintext.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    return Err(ErrorTag::Truncated);
                }
                Err(_) => return Err(ErrorTag::Other),
            }
        }
        Ok(())
    }

    fn flush_tls(&mut self, sock: &mut BorrowedTcp) -> Result<(), ErrorTag> {
        while self.conn.wants_write() {
            self.check_deadline()?;
            let n = self.conn.write_tls(sock).map_err(map_io)?;
            if n == 0 {
                return Err(ErrorTag::WouldBlock);
            }
        }
        Ok(())
    }

    /// Non-blocking handshake progress. Returns Ok when handshake (and the
    /// post-handshake flush) is done. WouldBlock means the VM should park.
    pub fn pump_handshake(&mut self, sock: &mut BorrowedTcp) -> Result<(), ErrorTag> {
        if self.handshake_done {
            return Ok(());
        }
        loop {
            self.check_deadline()?;
            while self.conn.wants_write() {
                self.check_deadline()?;
                match self.conn.write_tls(sock) {
                    Ok(0) => return Err(ErrorTag::WouldBlock),
                    Ok(_) => {}
                    Err(e)
                        if e.kind() == ErrorKind::WouldBlock
                            || e.kind() == ErrorKind::Interrupted =>
                    {
                        return Err(ErrorTag::WouldBlock);
                    }
                    Err(e) => return Err(map_io(e)),
                }
            }
            if !self.conn.is_handshaking() {
                while self.conn.wants_write() {
                    self.check_deadline()?;
                    match self.conn.write_tls(sock) {
                        Ok(0) => return Err(ErrorTag::WouldBlock),
                        Ok(_) => {}
                        Err(e)
                            if e.kind() == ErrorKind::WouldBlock
                                || e.kind() == ErrorKind::Interrupted =>
                        {
                            return Err(ErrorTag::WouldBlock);
                        }
                        Err(e) => return Err(map_io(e)),
                    }
                }
                self.handshake_done = true;
                self.deadline = None;
                return Ok(());
            }
            match self.conn.read_tls(sock) {
                Ok(0) => return Err(ErrorTag::Handshake),
                Ok(_) => {
                    self.conn.process_new_packets().map_err(map_tls_err)?;
                }
                Err(e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted =>
                {
                    return Err(ErrorTag::WouldBlock);
                }
                Err(e) => return Err(map_io(e)),
            }
        }
    }

    fn read_tls_records(&mut self, sock: &mut BorrowedTcp) -> Result<usize, ErrorTag> {
        match self.conn.read_tls(sock) {
            Ok(0) => Ok(0),
            Ok(n) => {
                self.conn.process_new_packets().map_err(map_tls_err)?;
                self.pull_plaintext_from_conn()?;
                Ok(n)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {
                Err(ErrorTag::WouldBlock)
            }
            Err(e) => Err(map_io(e)),
        }
    }

    /// App read. `Ok(None)` = clean EOF.
    pub fn read(
        &mut self,
        sock: &mut BorrowedTcp,
        buf: &mut [u8],
    ) -> Result<Option<usize>, ErrorTag> {
        self.pump_handshake(sock)?;
        if buf.is_empty() {
            return Ok(Some(0));
        }
        self.flush_tls(sock)?;
        let n = self.drain_plaintext_into(buf);
        if n > 0 {
            return Ok(Some(n));
        }
        self.pull_plaintext_from_conn()?;
        let n = self.drain_plaintext_into(buf);
        if n > 0 {
            return Ok(Some(n));
        }
        match self.read_tls_records(sock) {
            Ok(0) => {
                self.pull_plaintext_from_conn()?;
                let n = self.drain_plaintext_into(buf);
                if n > 0 {
                    Ok(Some(n))
                } else {
                    Ok(None)
                }
            }
            Ok(_) => {
                let n = self.drain_plaintext_into(buf);
                if n > 0 {
                    Ok(Some(n))
                } else {
                    Err(ErrorTag::WouldBlock)
                }
            }
            Err(e) => Err(e),
        }
    }

    pub fn write(&mut self, sock: &mut BorrowedTcp, bytes: &[u8]) -> Result<usize, ErrorTag> {
        self.pump_handshake(sock)?;
        self.flush_tls(sock)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        let n = match self.conn.writer().write(bytes) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                let _ = self.flush_tls(sock);
                return Err(ErrorTag::WouldBlock);
            }
            Err(_) => return Err(ErrorTag::Other),
        };
        match self.flush_tls(sock) {
            Ok(()) | Err(ErrorTag::WouldBlock) => Ok(n),
            Err(e) => Err(e),
        }
    }

    pub fn send_close_notify(&mut self, sock: &mut BorrowedTcp) -> Result<(), ErrorTag> {
        self.conn.send_close_notify();
        match self.flush_tls(sock) {
            Ok(()) | Err(ErrorTag::WouldBlock) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

pub fn deadline_from_ms(ms: i64) -> Option<Instant> {
    if ms <= 0 {
        None
    } else {
        Some(Instant::now() + std::time::Duration::from_millis(ms as u64))
    }
}
