//! Local TCP redirection and a bounded, cancellable Winsock relay.
use crate::metrics::Metrics;
use anyhow::{bail, Context, Result};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV6, TcpListener, TcpStream,
};
use std::os::windows::io::{FromRawSocket, OwnedSocket, RawSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Networking::WinSock as ws;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const BUFFER_BYTES: usize = 32 * 1024;

fn normalized(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn bind_address(local: SocketAddr) -> SocketAddr {
    match local {
        SocketAddr::V4(mut address) => {
            if address.ip().is_unspecified() {
                address.set_ip(Ipv4Addr::LOCALHOST);
            }
            address.set_port(0);
            address.into()
        }
        SocketAddr::V6(mut address) => {
            if address.ip().is_unspecified() {
                address.set_ip(Ipv6Addr::LOCALHOST);
            } else if address.ip().to_ipv4_mapped() == Some(Ipv4Addr::UNSPECIFIED) {
                address.set_ip(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
            }
            address.set_port(0);
            address.into()
        }
    }
}

fn socket_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() })
}

// NetFilter owns a Winsock startup guard until every forwarding worker has joined.
// Explicit dual-stack mode is needed before binding mapped IPv6 on Windows.
fn mapped_listener(address: SocketAddrV6) -> Result<TcpListener> {
    let socket = unsafe {
        ws::WSASocketW(
            i32::from(ws::AF_INET6),
            ws::SOCK_STREAM,
            ws::IPPROTO_TCP,
            std::ptr::null(),
            0,
            ws::WSA_FLAG_OVERLAPPED | ws::WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if socket == ws::INVALID_SOCKET {
        return Err(socket_error()).context("Create mapped IPv6 TCP listener");
    }
    // Own the socket immediately so every error below closes it.
    let owned = unsafe { OwnedSocket::from_raw_socket(socket as RawSocket) };
    let v6_only: u32 = 0;
    if unsafe {
        ws::setsockopt(
            socket,
            ws::IPPROTO_IPV6,
            ws::IPV6_V6ONLY,
            (&v6_only as *const u32).cast(),
            std::mem::size_of_val(&v6_only) as i32,
        )
    } != 0
    {
        return Err(socket_error()).context("Enable mapped IPv6 TCP redirection");
    }
    let sockaddr = ws::SOCKADDR_IN6 {
        sin6_family: ws::AF_INET6,
        sin6_port: address.port().to_be(),
        sin6_flowinfo: address.flowinfo().to_be(),
        sin6_addr: ws::IN6_ADDR {
            u: ws::IN6_ADDR_0 {
                Byte: address.ip().octets(),
            },
        },
        Anonymous: ws::SOCKADDR_IN6_0 {
            sin6_scope_id: address.scope_id(),
        },
    };
    if unsafe {
        ws::bind(
            socket,
            (&sockaddr as *const ws::SOCKADDR_IN6).cast(),
            std::mem::size_of_val(&sockaddr) as i32,
        )
    } != 0
    {
        return Err(socket_error()).context("Bind mapped IPv6 TCP redirect address");
    }
    if unsafe { ws::listen(socket, 1) } != 0 {
        return Err(socket_error()).context("Listen for mapped IPv6 TCP redirection");
    }
    Ok(TcpListener::from(owned))
}

/// Bind the original local IP, or loopback for its family when it is unspecified.
/// The backend must retain its Winsock guard for the lifetime of this listener.
pub(super) fn listener(local: SocketAddr) -> Result<TcpListener> {
    let address = bind_address(local);
    let listener = match address {
        SocketAddr::V6(address) if address.ip().to_ipv4_mapped().is_some() => {
            mapped_listener(address)?
        }
        address => TcpListener::bind(address)
            .with_context(|| format!("Bind TCP redirect listener at {address}"))?,
    };
    listener
        .set_nonblocking(true)
        .context("Make TCP redirect listener cancellable")?;
    Ok(listener)
}

fn expected_peer(peer: SocketAddr, expected_local: SocketAddr, bound: SocketAddr) -> bool {
    let mut expected_ip = normalized(expected_local.ip());
    if expected_ip.is_unspecified() {
        expected_ip = normalized(bound.ip());
    }
    normalized(peer.ip()) == expected_ip
        && (expected_local.port() == 0 || peer.port() == expected_local.port())
}

pub(super) fn accept(
    listener: &TcpListener,
    expected_local: SocketAddr,
    stopped: impl Fn() -> bool,
) -> Result<Option<TcpStream>> {
    let bound = listener.local_addr().context("Read TCP redirect address")?;
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        if stopped() {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            bail!("Timed out waiting for redirected TCP connection at {bound}");
        }
        match listener.accept() {
            Ok((stream, peer)) if expected_peer(peer, expected_local, bound) => {
                return Ok(Some(stream));
            }
            Ok((stream, _)) => {
                let _ = stream.shutdown(Shutdown::Both);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(POLL_INTERVAL),
            Err(error) => return Err(error).context("Accept redirected TCP connection"),
        }
    }
}

struct Direction {
    buffer: [u8; BUFFER_BYTES],
    begin: usize,
    end: usize,
    eof: bool,
    write_closed: bool,
}

impl Direction {
    fn new() -> Self {
        Self {
            buffer: [0; BUFFER_BYTES],
            begin: 0,
            end: 0,
            eof: false,
            write_closed: false,
        }
    }

    // At most one buffer is retained per direction. Pending bytes are drained
    // before reading more; EOF closes only the corresponding outgoing half.
    fn pump(
        &mut self,
        input: &mut TcpStream,
        output: &mut TcpStream,
        transferred: &AtomicU64,
    ) -> io::Result<bool> {
        if self.write_closed {
            return Ok(false);
        }
        let mut progress = false;
        if self.begin == self.end && !self.eof {
            match input.read(&mut self.buffer) {
                Ok(0) => {
                    self.eof = true;
                    progress = true;
                }
                Ok(count) => {
                    self.begin = 0;
                    self.end = count;
                    progress = true;
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                Err(error) => return Err(error),
            }
        }
        if self.begin < self.end {
            match output.write(&self.buffer[self.begin..self.end]) {
                Ok(0) => return Err(io::Error::from(ErrorKind::WriteZero)),
                Ok(count) => {
                    self.begin += count;
                    transferred.fetch_add(count as u64, Ordering::Relaxed);
                    progress = true;
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                Err(error) => return Err(error),
            }
        }
        if self.eof && self.begin == self.end {
            output.shutdown(Shutdown::Write)?;
            self.write_closed = true;
        }
        Ok(progress)
    }
}

pub(super) fn relay(
    mut local: TcpStream,
    mut proxy: TcpStream,
    metrics: &Metrics,
    stopped: &(impl Fn() -> bool + Sync),
) -> Result<()> {
    // A single nonblocking worker pumps both halves. Cancellation never needs to
    // wait for a blocking write or for an unowned background reader thread.
    let result = (|| {
        for stream in [&local, &proxy] {
            stream.set_nonblocking(true)?;
            stream.set_nodelay(true)?;
        }
        let mut upload = Direction::new();
        let mut download = Direction::new();
        while !(stopped() || upload.write_closed && download.write_closed) {
            let up = upload
                .pump(&mut local, &mut proxy, &metrics.tcp_up)
                .context("Relay redirected TCP upload")?;
            let down = download
                .pump(&mut proxy, &mut local, &metrics.tcp_down)
                .context("Relay redirected TCP download")?;
            if !up && !down {
                thread::sleep(POLL_INTERVAL);
            }
        }
        Ok(())
    })();
    let _ = local.shutdown(Shutdown::Both);
    let _ = proxy.shutdown(Shutdown::Both);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        for stream in [&client, &server] {
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
        }
        (client, server)
    }

    #[test]
    fn listener_preserves_family_and_selects_loopback() {
        let _winsock = super::super::Winsock::start().unwrap();
        for source in ["0.0.0.0:12345", "[::]:12345", "[::ffff:0.0.0.0]:12345"] {
            let source: SocketAddr = source.parse().unwrap();
            let listener = listener(source).unwrap();
            let bound = listener.local_addr().unwrap();
            assert_eq!(bound.is_ipv6(), source.is_ipv6());
            assert!(normalized(bound.ip()).is_loopback());
            assert_ne!(bound.port(), 0);
            assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
            let destination = SocketAddr::new(normalized(bound.ip()), bound.port());
            let client = TcpStream::connect(destination).unwrap();
            let accepted = accept(&listener, client.local_addr().unwrap(), || false)
                .unwrap()
                .unwrap();
            assert_eq!(accepted.local_addr().unwrap(), bound);
        }
    }

    #[test]
    fn accept_rejects_other_source_ports() {
        let listener = listener("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut other = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        other
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let expected = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let peer = expected.local_addr().unwrap();
        let accepted = accept(&listener, peer, || false).unwrap().unwrap();
        assert_eq!(accepted.peer_addr().unwrap(), peer);
        let mut byte = [0];
        assert_eq!(other.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn expected_peer_handles_unspecified_and_mapped_addresses() {
        let bound = "[::ffff:127.0.0.1]:1234".parse().unwrap();
        assert!(expected_peer(
            "127.0.0.1:2345".parse().unwrap(),
            "[::ffff:0.0.0.0]:2345".parse().unwrap(),
            bound,
        ));
        assert!(!expected_peer(
            "127.0.0.2:2345".parse().unwrap(),
            "[::ffff:0.0.0.0]:2345".parse().unwrap(),
            bound,
        ));
        assert!(!expected_peer(
            "127.0.0.1:2346".parse().unwrap(),
            "[::ffff:0.0.0.0]:2345".parse().unwrap(),
            bound,
        ));
    }

    #[test]
    fn accept_stops_without_waiting_for_a_connection() {
        let listener = listener("127.0.0.1:0".parse().unwrap()).unwrap();
        let start = Instant::now();
        assert!(accept(&listener, "0.0.0.0:0".parse().unwrap(), || true)
            .unwrap()
            .is_none());
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn relay_preserves_server_first_data_and_client_half_close() {
        let (mut client, local) = pair();
        let (proxy, mut server) = pair();
        let upload: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
        let download: Vec<u8> = (0..180_000).map(|index| (index % 239) as u8).collect();
        let metrics = Metrics::default();
        thread::scope(|scope| {
            let forwarding = scope.spawn(|| relay(local, proxy, &metrics, &|| false));
            let remote = scope.spawn(|| {
                server.write_all(b"ready").unwrap();
                let mut received = Vec::new();
                server.read_to_end(&mut received).unwrap();
                assert_eq!(received, upload);
                server.write_all(&download).unwrap();
                server.shutdown(Shutdown::Write).unwrap();
            });
            let mut greeting = [0; 5];
            client.read_exact(&mut greeting).unwrap();
            assert_eq!(&greeting, b"ready");
            client.write_all(&upload).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut received = Vec::new();
            client.read_to_end(&mut received).unwrap();
            assert_eq!(received, download);
            remote.join().unwrap();
            forwarding.join().unwrap().unwrap();
        });
        assert_eq!(metrics.tcp_up.load(Ordering::Relaxed), upload.len() as u64);
        assert_eq!(
            metrics.tcp_down.load(Ordering::Relaxed),
            download.len() as u64 + 5
        );
    }

    #[test]
    fn relay_keeps_upload_open_after_server_half_close() {
        let (mut client, local) = pair();
        let (proxy, mut server) = pair();
        let metrics = Metrics::default();
        thread::scope(|scope| {
            let forwarding = scope.spawn(|| relay(local, proxy, &metrics, &|| false));
            server.write_all(b"finished").unwrap();
            server.shutdown(Shutdown::Write).unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).unwrap();
            assert_eq!(response, b"finished");
            client.write_all(b"still uploading").unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            let mut request = Vec::new();
            server.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"still uploading");
            forwarding.join().unwrap().unwrap();
        });
    }

    #[test]
    fn relay_cancels_when_idle_or_backpressured() {
        for send_data in [false, true] {
            let (mut client, local) = pair();
            let (proxy, _server) = pair();
            let metrics = Metrics::default();
            let stopped = AtomicBool::new(false);
            thread::scope(|scope| {
                let forwarding = scope
                    .spawn(|| relay(local, proxy, &metrics, &|| stopped.load(Ordering::Acquire)));
                if send_data {
                    client.set_nonblocking(true).unwrap();
                    let bytes = [1; BUFFER_BYTES];
                    for _ in 0..512 {
                        match client.write(&bytes) {
                            Ok(_) => {}
                            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                            Err(error) => panic!("Write test upload: {error}"),
                        }
                    }
                }
                thread::sleep(Duration::from_millis(20));
                let start = Instant::now();
                stopped.store(true, Ordering::Release);
                forwarding.join().unwrap().unwrap();
                assert!(start.elapsed() < Duration::from_secs(1));
            });
        }
    }
}
