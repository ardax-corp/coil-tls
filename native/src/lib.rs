//! C ABI around rustls for coil FFI (`coil_tls_*`).
//!
//! Handshake never parks. One call pumps rustls until the fd is not ready,
//! then returns WouldBlock so the VM can park (COI-116).

mod config;
mod error;
mod fd;
mod session;

use std::os::raw::c_char;
use std::ptr;

use rustls::{ClientConnection, ServerConnection};

use crate::config::{client_config, ensure_provider, parse_server_name, server_config};
use crate::error::{write_err, write_ok, ErrorTag};
use crate::fd::BorrowedTcp;
use crate::session::{deadline_from_ms, TlsSession};

fn c_str<'a>(p: *const c_char) -> Result<&'a str, ErrorTag> {
    if p.is_null() {
        return Ok("");
    }
    unsafe { std::ffi::CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| ErrorTag::InvalidInput)
}

fn opt_str<'a>(p: *const c_char) -> Result<Option<&'a str>, ErrorTag> {
    let s = c_str(p)?;
    if s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(s))
    }
}

unsafe fn borrow_nb(fd: i64) -> Result<BorrowedTcp, ErrorTag> {
    if fd < 0 {
        return Err(ErrorTag::InvalidInput);
    }
    let sock = BorrowedTcp::from_raw(fd);
    sock.set_nonblocking(true)
        .map_err(|e| ErrorTag::from_kind(e.kind()))?;
    Ok(sock)
}

fn finish_enable(session: TlsSession, sock: &mut BorrowedTcp, err_out: *mut *const c_char) -> i64 {
    let mut session = session;
    match session.pump_handshake(sock) {
        Ok(()) => {
            unsafe { write_ok(err_out) };
            session.into_raw()
        }
        Err(ErrorTag::WouldBlock) => {
            unsafe { write_err(err_out, ErrorTag::WouldBlock) };
            session.into_raw()
        }
        Err(tag) => {
            unsafe { write_err(err_out, tag) };
            0
        }
    }
}

/// Client handshake. Session pointer on success / WouldBlock; 0 on hard error.
#[no_mangle]
pub extern "C" fn coil_tls_client_enable(
    fd: i64,
    host: *const c_char,
    verify: i64,
    ca_pem: *const c_char,
    ca_path: *const c_char,
    timeout_ms: i64,
    alpn: *const c_char,
    err_out: *mut *const c_char,
) -> i64 {
    ensure_provider();
    let fail = |tag: ErrorTag| -> i64 {
        unsafe { write_err(err_out, tag) };
        0
    };
    let host = match c_str(host) {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return fail(ErrorTag::InvalidInput),
        Err(tag) => return fail(tag),
    };
    if verify != 0 && verify != 1 {
        return fail(ErrorTag::InvalidInput);
    }
    let server_name = match parse_server_name(host) {
        Ok(n) => n,
        Err(tag) => return fail(tag),
    };
    let ca_pem = match opt_str(ca_pem) {
        Ok(v) => v,
        Err(tag) => return fail(tag),
    };
    let ca_path = match opt_str(ca_path) {
        Ok(v) => v,
        Err(tag) => return fail(tag),
    };
    let alpn = match c_str(alpn) {
        Ok(s) => s,
        Err(tag) => return fail(tag),
    };
    let config = match client_config(verify != 0, ca_pem, ca_path, alpn) {
        Ok(c) => c,
        Err(tag) => return fail(tag),
    };
    let client = match ClientConnection::new(config, server_name) {
        Ok(c) => c,
        Err(e) => return fail(crate::error::map_tls_err(e)),
    };
    let mut sock = match unsafe { borrow_nb(fd) } {
        Ok(s) => s,
        Err(tag) => return fail(tag),
    };
    let session = TlsSession::from_client(client, deadline_from_ms(timeout_ms));
    finish_enable(session, &mut sock, err_out)
}

/// Server handshake. Same WouldBlock / session rules as the client.
#[no_mangle]
pub extern "C" fn coil_tls_server_enable(
    fd: i64,
    cert_pem: *const c_char,
    key_pem: *const c_char,
    timeout_ms: i64,
    client_ca_pem: *const c_char,
    alpn: *const c_char,
    err_out: *mut *const c_char,
) -> i64 {
    ensure_provider();
    let fail = |tag: ErrorTag| -> i64 {
        unsafe { write_err(err_out, tag) };
        0
    };
    let cert_pem = match c_str(cert_pem) {
        Ok(s) => s,
        Err(tag) => return fail(tag),
    };
    let key_pem = match c_str(key_pem) {
        Ok(s) => s,
        Err(tag) => return fail(tag),
    };
    let client_ca_pem = match c_str(client_ca_pem) {
        Ok(s) => s,
        Err(tag) => return fail(tag),
    };
    let alpn = match c_str(alpn) {
        Ok(s) => s,
        Err(tag) => return fail(tag),
    };
    let config = match server_config(cert_pem, key_pem, client_ca_pem, alpn) {
        Ok(c) => c,
        Err(tag) => return fail(tag),
    };
    let server = match ServerConnection::new(config) {
        Ok(s) => s,
        Err(e) => return fail(crate::error::map_tls_err(e)),
    };
    let mut sock = match unsafe { borrow_nb(fd) } {
        Ok(s) => s,
        Err(tag) => return fail(tag),
    };
    let session = TlsSession::from_server(server, deadline_from_ms(timeout_ms));
    finish_enable(session, &mut sock, err_out)
}

/// App read. 0 = clean EOF, -1 = error (WouldBlock is tagged, not a hang).
#[no_mangle]
pub extern "C" fn coil_tls_read(
    session: i64,
    fd: i64,
    buf: *mut u8,
    len: i64,
    err_out: *mut *const c_char,
) -> i64 {
    let tls = match unsafe { TlsSession::from_raw(session) } {
        Ok(s) => s,
        Err(tag) => {
            unsafe { write_err(err_out, tag) };
            return -1;
        }
    };
    if len < 0 {
        unsafe { write_err(err_out, ErrorTag::InvalidInput) };
        return -1;
    }
    let out = if len == 0 || buf.is_null() {
        &mut []
    } else {
        unsafe { std::slice::from_raw_parts_mut(buf, len as usize) }
    };
    let mut sock = match unsafe { borrow_nb(fd) } {
        Ok(s) => s,
        Err(tag) => {
            unsafe { write_err(err_out, tag) };
            return -1;
        }
    };
    match tls.read(&mut sock, out) {
        Ok(Some(n)) => {
            unsafe { write_ok(err_out) };
            n as i64
        }
        Ok(None) => {
            unsafe { write_ok(err_out) };
            0
        }
        Err(tag) => {
            unsafe { write_err(err_out, tag) };
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn coil_tls_write(
    session: i64,
    fd: i64,
    buf: *const u8,
    len: i64,
    err_out: *mut *const c_char,
) -> i64 {
    let tls = match unsafe { TlsSession::from_raw(session) } {
        Ok(s) => s,
        Err(tag) => {
            unsafe { write_err(err_out, tag) };
            return -1;
        }
    };
    if len < 0 {
        unsafe { write_err(err_out, ErrorTag::InvalidInput) };
        return -1;
    }
    let bytes = if len == 0 || buf.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(buf, len as usize) }
    };
    let mut sock = match unsafe { borrow_nb(fd) } {
        Ok(s) => s,
        Err(tag) => {
            unsafe { write_err(err_out, tag) };
            return -1;
        }
    };
    match tls.write(&mut sock, bytes) {
        Ok(n) => {
            unsafe { write_ok(err_out) };
            n as i64
        }
        Err(tag) => {
            unsafe { write_err(err_out, tag) };
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn coil_tls_alpn(session: i64, out: *mut u8, out_len: i64) -> i64 {
    let tls = match unsafe { TlsSession::from_raw(session) } {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let proto = tls.alpn_protocol();
    if out_len < 0 {
        return -1;
    }
    // Size query: null or zero-length out returns proto.len(), not 0.
    if out.is_null() || out_len == 0 {
        return proto.len() as i64;
    }
    let n = proto.len().min(out_len as usize);
    if n > 0 {
        unsafe { ptr::copy_nonoverlapping(proto.as_ptr(), out, n) };
    }
    n as i64
}

/// close_notify (best effort) then free the session.
#[no_mangle]
pub extern "C" fn coil_tls_disable(session: i64, fd: i64, err_out: *mut *const c_char) {
    let tls = match unsafe { TlsSession::from_raw(session) } {
        Ok(s) => s,
        Err(tag) => {
            unsafe { write_err(err_out, tag) };
            return;
        }
    };
    if let Ok(mut sock) = unsafe { borrow_nb(fd) } {
        let _ = tls.send_close_notify(&mut sock);
    }
    unsafe {
        TlsSession::free(session);
        write_ok(err_out);
    }
}

#[no_mangle]
pub extern "C" fn coil_tls_free(session: i64) {
    unsafe { TlsSession::free(session) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::{ErrorKind, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use rustls::{ServerConfig, ServerConnection};

    use crate::config::parse_pem_cert_key;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    fn tag_of(err: *const c_char) -> String {
        if err.is_null() {
            return String::new();
        }
        unsafe { std::ffi::CStr::from_ptr(err) }
            .to_str()
            .unwrap()
            .to_string()
    }

    fn raw_fd(stream: &TcpStream) -> i64 {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            stream.as_raw_fd() as i64
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            stream.as_raw_socket() as i64
        }
    }

    fn test_server_pem() -> (String, String) {
        let dir = env!("CARGO_MANIFEST_DIR");
        let cert = std::fs::read_to_string(format!("{dir}/tests/fixtures/cert.pem")).unwrap();
        let key = std::fs::read_to_string(format!("{dir}/tests/fixtures/key.pem")).unwrap();
        (cert, key)
    }

    fn test_server_config() -> Arc<ServerConfig> {
        crate::config::ensure_provider();
        let (cert_pem, key_pem) = test_server_pem();
        let (certs, key) = parse_pem_cert_key(&cert_pem, &key_pem).expect("pem");
        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("server config"),
        )
    }

    fn io_transient(err: &std::io::Error) -> bool {
        matches!(
            err.kind(),
            ErrorKind::WouldBlock | ErrorKind::Interrupted | ErrorKind::TimedOut
        )
    }

    fn drain_app_data(conn: &mut ServerConnection, acc: &mut Vec<u8>) -> bool {
        let mut got = false;
        let mut tmp = [0u8; 4096];
        loop {
            match conn.reader().read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    acc.extend_from_slice(&tmp[..n]);
                    got = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        got
    }

    fn spawn_tls_echo_server() -> (u16, thread::JoinHandle<()>) {
        spawn_tls_echo_server_cfg(test_server_config())
    }

    fn spawn_tls_echo_server_with_alpn(alpn: &[&[u8]]) -> (u16, thread::JoinHandle<()>) {
        let mut cfg = (*test_server_config()).clone();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        spawn_tls_echo_server_cfg(Arc::new(cfg))
    }

    fn spawn_tls_echo_server_cfg(cfg: Arc<ServerConfig>) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            ready_tx.send(()).ok();
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let _ = sock.set_nonblocking(true);
            let Ok(mut conn) = ServerConnection::new(cfg) else {
                return;
            };
            let deadline = Instant::now() + Duration::from_secs(5);
            while conn.is_handshaking() && Instant::now() < deadline {
                while conn.wants_write() {
                    match conn.write_tls(&mut sock) {
                        Ok(0) => {
                            thread::sleep(Duration::from_millis(1));
                            break;
                        }
                        Ok(_) => {}
                        Err(e) if io_transient(&e) => {
                            thread::sleep(Duration::from_millis(1));
                            break;
                        }
                        Err(_) => return,
                    }
                }
                if !conn.is_handshaking() {
                    break;
                }
                match conn.read_tls(&mut sock) {
                    Ok(0) => return,
                    Ok(_) => {
                        if conn.process_new_packets().is_err() {
                            return;
                        }
                    }
                    Err(e) if io_transient(&e) => thread::sleep(Duration::from_millis(1)),
                    Err(_) => return,
                }
            }
            if conn.is_handshaking() {
                return;
            }
            while conn.wants_write() && Instant::now() < deadline {
                match conn.write_tls(&mut sock) {
                    Ok(0) => thread::sleep(Duration::from_millis(1)),
                    Ok(_) => {}
                    Err(e) if io_transient(&e) => thread::sleep(Duration::from_millis(1)),
                    Err(_) => return,
                }
            }
            let mut acc = Vec::new();
            let mut last_data = if drain_app_data(&mut conn, &mut acc) {
                Some(Instant::now())
            } else {
                None
            };
            while Instant::now() < deadline {
                if let Some(t) = last_data {
                    if t.elapsed() > Duration::from_millis(100) {
                        break;
                    }
                }
                match conn.read_tls(&mut sock) {
                    Ok(0) => break,
                    Ok(_) => {
                        if conn.process_new_packets().is_err() {
                            return;
                        }
                        if drain_app_data(&mut conn, &mut acc) {
                            last_data = Some(Instant::now());
                        }
                    }
                    Err(e) if io_transient(&e) => {
                        if drain_app_data(&mut conn, &mut acc) {
                            last_data = Some(Instant::now());
                        } else {
                            thread::sleep(Duration::from_millis(2));
                        }
                    }
                    Err(_) => return,
                }
            }
            if acc.is_empty() {
                return;
            }
            if conn.writer().write_all(&acc).is_err() {
                return;
            }
            conn.send_close_notify();
            while conn.wants_write() && Instant::now() < deadline {
                match conn.write_tls(&mut sock) {
                    Ok(0) => thread::sleep(Duration::from_millis(1)),
                    Ok(_) => {}
                    Err(e) if io_transient(&e) => thread::sleep(Duration::from_millis(1)),
                    Err(_) => break,
                }
            }
        });
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("ready");
        (port, handle)
    }

    fn connect_nb(port: u16) -> TcpStream {
        let s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_nonblocking(true).unwrap();
        s
    }

    fn client_enable(
        fd: i64,
        host: &str,
        verify: i64,
        ca_pem: &str,
        ca_path: &str,
        timeout_ms: i64,
        alpn: &str,
    ) -> (i64, String) {
        let host = c(host);
        let ca_pem = c(ca_pem);
        let ca_path = c(ca_path);
        let alpn = c(alpn);
        let mut err: *const c_char = ptr::null();
        let session = coil_tls_client_enable(
            fd,
            host.as_ptr(),
            verify,
            ca_pem.as_ptr(),
            ca_path.as_ptr(),
            timeout_ms,
            alpn.as_ptr(),
            &mut err,
        );
        (session, tag_of(err))
    }

    fn pump_client_enable(
        stream: &TcpStream,
        host: &str,
        verify: i64,
        ca_pem: &str,
        timeout_ms: i64,
        alpn: &str,
    ) -> Result<i64, String> {
        let fd = raw_fd(stream);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (session, tag) = client_enable(fd, host, verify, ca_pem, "", timeout_ms, alpn);
        if session == 0 {
            return Err(tag);
        }
        if tag.is_empty() {
            return Ok(session);
        }
        if tag != "WouldBlock" {
            coil_tls_free(session);
            return Err(tag);
        }
        while Instant::now() < deadline {
            let mut err: *const c_char = ptr::null();
            let n = coil_tls_write(session, fd, ptr::null(), 0, &mut err);
            if n >= 0 && tag_of(err).is_empty() {
                let mut probe = [0u8; 1];
                let mut err2: *const c_char = ptr::null();
                let r = coil_tls_read(session, fd, probe.as_mut_ptr(), 0, &mut err2);
                if r >= 0 {
                    return Ok(session);
                }
                if tag_of(err2) == "WouldBlock" {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
            }
            let t = tag_of(err);
            if t == "WouldBlock" || t.is_empty() {
                thread::sleep(Duration::from_millis(2));
                continue;
            }
            coil_tls_free(session);
            return Err(t);
        }
        coil_tls_free(session);
        Err("TimedOut".into())
    }

    fn write_all(session: i64, fd: i64, mut bytes: &[u8]) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !bytes.is_empty() {
            if Instant::now() >= deadline {
                return Err("TimedOut".into());
            }
            let mut err: *const c_char = ptr::null();
            let n = coil_tls_write(session, fd, bytes.as_ptr(), bytes.len() as i64, &mut err);
            if n > 0 {
                bytes = &bytes[n as usize..];
                continue;
            }
            if n == 0 {
                return Err("write zero".into());
            }
            let t = tag_of(err);
            if t == "WouldBlock" {
                thread::sleep(Duration::from_millis(2));
                continue;
            }
            return Err(t);
        }
        Ok(())
    }

    fn read_to_end(session: i64, fd: i64) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut acc = Vec::new();
        let mut idle = Instant::now();
        while Instant::now() < deadline {
            let mut buf = [0u8; 4096];
            let mut err: *const c_char = ptr::null();
            let n = coil_tls_read(session, fd, buf.as_mut_ptr(), buf.len() as i64, &mut err);
            if n > 0 {
                acc.extend_from_slice(&buf[..n as usize]);
                idle = Instant::now();
                continue;
            }
            if n == 0 && tag_of(err).is_empty() {
                return Ok(acc);
            }
            let t = tag_of(err);
            if t == "WouldBlock" {
                if !acc.is_empty() && idle.elapsed() > Duration::from_millis(150) {
                    return Ok(acc);
                }
                thread::sleep(Duration::from_millis(2));
                continue;
            }
            if t.is_empty() {
                return Ok(acc);
            }
            return Err(t);
        }
        if acc.is_empty() {
            Err("TimedOut".into())
        } else {
            Ok(acc)
        }
    }

    #[test]
    fn enable_rejects_empty_server_name() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = thread::spawn(move || {
            let _ = listener.accept();
        });
        let s = connect_nb(port);
        let (session, tag) = client_enable(raw_fd(&s), "", 0, "", "", 0, "");
        assert_eq!(session, 0);
        assert_eq!(tag, "InvalidInput");
        let _ = accept.join();
    }

    #[test]
    fn enable_rejects_garbage_ca_pem() {
        let (port, handle) = spawn_tls_echo_server();
        let s = connect_nb(port);
        let (session, tag) = client_enable(raw_fd(&s), "127.0.0.1", 1, "not-a-pem", "", 0, "");
        assert_eq!(session, 0);
        assert_eq!(tag, "InvalidInput");
        drop(s);
        let _ = handle.join();
    }

    #[test]
    fn server_enable_rejects_empty_pem() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = thread::spawn(move || {
            let _ = listener.accept();
        });
        let s = connect_nb(port);
        let cert = c("");
        let key = c("");
        let cca = c("");
        let alpn = c("");
        let mut err: *const c_char = ptr::null();
        let session = coil_tls_server_enable(
            raw_fd(&s),
            cert.as_ptr(),
            key.as_ptr(),
            0,
            cca.as_ptr(),
            alpn.as_ptr(),
            &mut err,
        );
        assert_eq!(session, 0);
        assert_eq!(tag_of(err), "InvalidInput");
        let _ = accept.join();
    }

    #[test]
    fn server_enable_rejects_malformed_pem() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = thread::spawn(move || {
            let _ = listener.accept();
        });
        let s = connect_nb(port);
        let cert = c("-----BEGIN CERTIFICATE-----\nnot-valid-base64\n-----END CERTIFICATE-----\n");
        let key = c("-----BEGIN PRIVATE KEY-----\nalso-not-valid\n-----END PRIVATE KEY-----\n");
        let cca = c("");
        let alpn = c("");
        let mut err: *const c_char = ptr::null();
        let session = coil_tls_server_enable(
            raw_fd(&s),
            cert.as_ptr(),
            key.as_ptr(),
            0,
            cca.as_ptr(),
            alpn.as_ptr(),
            &mut err,
        );
        assert_eq!(session, 0);
        assert_eq!(tag_of(err), "InvalidInput");
        let _ = accept.join();
    }

    #[test]
    fn enable_would_block_on_silent_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hold = thread::spawn(move || {
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            thread::sleep(Duration::from_millis(400));
            drop(sock);
        });
        let s = connect_nb(port);
        let (session, tag) = client_enable(raw_fd(&s), "127.0.0.1", 0, "", "", 0, "");
        assert_ne!(session, 0, "session must exist so handshake can resume");
        assert_eq!(tag, "WouldBlock");
        let mut err: *const c_char = ptr::null();
        let n = coil_tls_read(session, raw_fd(&s), ptr::null_mut(), 0, &mut err);
        assert!(n < 0 || tag_of(err) == "WouldBlock" || n == 0);
        if n < 0 {
            assert_eq!(tag_of(err), "WouldBlock");
        }
        coil_tls_free(session);
        drop(s);
        let _ = hold.join();
    }

    #[test]
    fn enable_verify_false_round_trips_bytes() {
        let (port, handle) = spawn_tls_echo_server();
        let s = connect_nb(port);
        let session = pump_client_enable(&s, "127.0.0.1", 0, "", 0, "").expect("enable");
        let fd = raw_fd(&s);
        write_all(session, fd, b"hello-tls").expect("write");
        let echoed = read_to_end(session, fd).expect("read");
        assert_eq!(echoed, b"hello-tls");
        let mut err: *const c_char = ptr::null();
        coil_tls_disable(session, fd, &mut err);
        handle.join().expect("server");
    }

    #[test]
    fn alpn_protocol_empty_when_neither_side_offers() {
        let (port, handle) = spawn_tls_echo_server();
        let s = connect_nb(port);
        let session = pump_client_enable(&s, "127.0.0.1", 0, "", 0, "").expect("enable");
        assert_eq!(coil_tls_alpn(session, ptr::null_mut(), 0), 0);
        let mut buf = [0u8; 32];
        let n = coil_tls_alpn(session, buf.as_mut_ptr(), buf.len() as i64);
        assert_eq!(n, 0);
        coil_tls_free(session);
        drop(s);
        handle.join().expect("server");
    }

    #[test]
    fn alpn_protocol_negotiates_h2() {
        let (port, handle) = spawn_tls_echo_server_with_alpn(&[b"h2"]);
        let s = connect_nb(port);
        let session = pump_client_enable(&s, "127.0.0.1", 0, "", 0, "h2").expect("enable");
        assert_eq!(coil_tls_alpn(session, ptr::null_mut(), 0), 2);
        assert_eq!(coil_tls_alpn(session, ptr::null_mut(), 8), 2);
        let mut untouched = [0xffu8; 1];
        assert_eq!(coil_tls_alpn(session, untouched.as_mut_ptr(), 0), 2);
        assert_eq!(untouched[0], 0xff);
        let mut buf = [0u8; 32];
        let n = coil_tls_alpn(session, buf.as_mut_ptr(), buf.len() as i64);
        assert_eq!(&buf[..n as usize], b"h2");
        coil_tls_free(session);
        drop(s);
        handle.join().expect("server");
    }

    #[test]
    fn alpn_protocol_client_prefers_server_overlap() {
        let (port, handle) = spawn_tls_echo_server_with_alpn(&[b"http/1.1"]);
        let s = connect_nb(port);
        let session = pump_client_enable(&s, "127.0.0.1", 0, "", 0, "h2,http/1.1").expect("enable");
        let mut buf = [0u8; 32];
        let n = coil_tls_alpn(session, buf.as_mut_ptr(), buf.len() as i64);
        assert_eq!(&buf[..n as usize], b"http/1.1");
        coil_tls_free(session);
        drop(s);
        handle.join().expect("server");
    }

    #[test]
    fn enable_verify_true_rejects_self_signed() {
        let (port, handle) = spawn_tls_echo_server();
        let s = TcpStream::connect(("localhost", port)).expect("connect");
        s.set_nonblocking(true).unwrap();
        let fd = raw_fd(&s);
        let (session, tag) = client_enable(fd, "localhost", 1, "", "", 2000, "");
        let last = if session == 0 {
            tag
        } else {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut last = tag;
            while last == "WouldBlock" && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
                let mut err: *const c_char = ptr::null();
                let n = coil_tls_read(session, fd, ptr::null_mut(), 0, &mut err);
                last = tag_of(err);
                if n >= 0 && last.is_empty() {
                    last = "ok".into();
                    break;
                }
            }
            coil_tls_free(session);
            last
        };
        assert_eq!(last, "Certificate");
        drop(s);
        let _ = handle.join();
    }

    #[test]
    fn server_then_client_round_trip() {
        let (cert_pem, key_pem) = test_server_pem();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            ready_tx.send(()).ok();
            let Ok((sock, _)) = listener.accept() else {
                panic!("accept");
            };
            sock.set_nonblocking(true).unwrap();
            let cert = c(&cert_pem);
            let key = c(&key_pem);
            let cca = c("");
            let alpn = c("");
            let fd = raw_fd(&sock);
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut err: *const c_char = ptr::null();
            let mut session = coil_tls_server_enable(
                fd,
                cert.as_ptr(),
                key.as_ptr(),
                5000,
                cca.as_ptr(),
                alpn.as_ptr(),
                &mut err,
            );
            assert_ne!(session, 0, "server enable hard-fail {}", tag_of(err));
            while tag_of(err) == "WouldBlock" && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
                let mut err2: *const c_char = ptr::null();
                let n = coil_tls_read(session, fd, ptr::null_mut(), 0, &mut err2);
                if n >= 0 {
                    break;
                }
                err = err2;
            }
            let mut buf = [0u8; 64];
            let n = loop {
                if Instant::now() >= deadline {
                    panic!("server read timeout");
                }
                let mut rerr: *const c_char = ptr::null();
                let n = coil_tls_read(session, fd, buf.as_mut_ptr(), buf.len() as i64, &mut rerr);
                if n > 0 {
                    break n;
                }
                if n == 0 && tag_of(rerr).is_empty() {
                    panic!("eof before data");
                }
                let t = tag_of(rerr);
                if t == "WouldBlock" || t.is_empty() {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                panic!("read {t}");
            };
            write_all(session, fd, &buf[..n as usize]).expect("echo");
            let mut derr: *const c_char = ptr::null();
            coil_tls_disable(session, fd, &mut derr);
            session = 0;
            let _ = session;
        });
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("ready");
        let s = TcpStream::connect(("localhost", port)).expect("connect");
        s.set_nonblocking(true).unwrap();
        let session = pump_client_enable(&s, "localhost", 0, "", 5000, "").expect("client");
        let fd = raw_fd(&s);
        write_all(session, fd, b"ping-encrypt").expect("write");
        let echoed = read_to_end(session, fd).expect("read");
        assert_eq!(echoed, b"ping-encrypt");
        let mut err: *const c_char = ptr::null();
        coil_tls_disable(session, fd, &mut err);
        server.join().expect("server");
    }

    #[test]
    fn alpn_on_null_session_is_invalid() {
        assert_eq!(coil_tls_alpn(0, ptr::null_mut(), 8), -1);
        assert_eq!(coil_tls_alpn(0, ptr::null_mut(), 0), -1);
    }

    #[test]
    fn free_null_is_safe() {
        coil_tls_free(0);
    }

    #[test]
    fn disable_null_is_invalid_input() {
        let mut err: *const c_char = ptr::null();
        coil_tls_disable(0, 0, &mut err);
        assert_eq!(tag_of(err), "InvalidInput");
    }

    #[test]
    fn read_write_would_block_without_peer_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hold = thread::spawn(move || {
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            thread::sleep(Duration::from_millis(300));
            drop(sock);
        });
        let s = connect_nb(port);
        let (session, tag) = client_enable(raw_fd(&s), "127.0.0.1", 0, "", "", 0, "");
        assert_ne!(session, 0);
        assert_eq!(tag, "WouldBlock");
        let mut buf = [0u8; 8];
        let mut err: *const c_char = ptr::null();
        let n = coil_tls_read(
            session,
            raw_fd(&s),
            buf.as_mut_ptr(),
            buf.len() as i64,
            &mut err,
        );
        assert_eq!(n, -1);
        assert_eq!(tag_of(err), "WouldBlock");
        coil_tls_free(session);
        drop(s);
        let _ = hold.join();
    }

    #[test]
    fn enable_with_custom_ca_pem_round_trips() {
        let (cert_pem, key_pem) = test_server_pem();
        let ca_pem = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ca.pem"
        ))
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let (ready_tx, ready_rx) = mpsc::channel();
        let server_cert = cert_pem.clone();
        let server_key = key_pem.clone();
        let server = thread::spawn(move || {
            ready_tx.send(()).ok();
            let Ok((sock, _)) = listener.accept() else {
                return;
            };
            sock.set_nonblocking(true).unwrap();
            let cert = c(&server_cert);
            let key = c(&server_key);
            let cca = c("");
            let alpn = c("");
            let fd = raw_fd(&sock);
            let mut err: *const c_char = ptr::null();
            let session = coil_tls_server_enable(
                fd,
                cert.as_ptr(),
                key.as_ptr(),
                0,
                cca.as_ptr(),
                alpn.as_ptr(),
                &mut err,
            );
            assert_ne!(session, 0, "{}", tag_of(err));
            let deadline = Instant::now() + Duration::from_secs(5);
            while tag_of(err) == "WouldBlock" && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(2));
                let mut err2: *const c_char = ptr::null();
                let _ = coil_tls_read(session, fd, ptr::null_mut(), 0, &mut err2);
                err = err2;
                if tag_of(err).is_empty() {
                    break;
                }
            }
            let mut buf = [0u8; 64];
            let n = loop {
                if Instant::now() >= deadline {
                    panic!("timeout");
                }
                let mut rerr: *const c_char = ptr::null();
                let n = coil_tls_read(session, fd, buf.as_mut_ptr(), buf.len() as i64, &mut rerr);
                if n > 0 {
                    break n;
                }
                thread::sleep(Duration::from_millis(5));
            };
            write_all(session, fd, &buf[..n as usize]).ok();
            let mut derr: *const c_char = ptr::null();
            coil_tls_disable(session, fd, &mut derr);
        });
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("ready");
        let s = TcpStream::connect(("localhost", port)).expect("connect");
        s.set_nonblocking(true).unwrap();
        let session = pump_client_enable(&s, "localhost", 1, &ca_pem, 0, "").expect("enable+ca");
        let fd = raw_fd(&s);
        write_all(session, fd, b"ca-ok").expect("write");
        let echoed = read_to_end(session, fd).expect("read");
        assert_eq!(echoed, b"ca-ok");
        let mut err: *const c_char = ptr::null();
        coil_tls_disable(session, fd, &mut err);
        server.join().expect("server");
    }
}
