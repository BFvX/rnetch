//! SOCKS5 framing (RFC 1928 / RFC 1929). Reads consume exactly one reply,
//! leaving any application data coalesced with the reply on the TCP stream.
use crate::config::Socks5Config;
use anyhow::{bail, ensure, Context, Result};
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    sync::{mpsc, Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(5);
type ProxyCache = Mutex<HashMap<(String, u16), Vec<SocketAddr>>>;
static PROXIES: OnceLock<ProxyCache> = OnceLock::new();

fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    // Windows DNS itself is not cancellable. Only this bounded resolver owns the
    // DNS operation; it cannot retain a driver, flow, or forwarding worker.
    let host = host.to_owned();
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = tx.send(
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>()),
        );
    });
    let addresses = rx
        .recv_timeout(TIMEOUT)
        .context("SOCKS5 DNS lookup timed out")??;
    ensure!(
        !addresses.is_empty(),
        "SOCKS5 hostname resolved to no addresses"
    );
    Ok(addresses)
}

/// Resolve before interception starts. Workers reuse this snapshot, avoiding
/// reentrant DNS traffic and unbounded shutdown delays inside driver callbacks.
pub fn resolve_proxy(config: &Socks5Config) -> Result<Vec<SocketAddr>> {
    let key = (config.host.clone(), config.port);
    let cache = PROXIES.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(addresses) = cache.lock().unwrap().get(&key).cloned() {
        return Ok(addresses);
    }
    let addresses = resolve(&config.host, config.port).context("Cannot resolve SOCKS5 endpoint")?;
    cache.lock().unwrap().insert(key, addresses.clone());
    Ok(addresses)
}

struct DeadlineStream {
    stream: TcpStream,
    until: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.until
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 handshake timed out"))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn authenticated(config: &Socks5Config) -> Result<DeadlineStream> {
    let addresses = resolve_proxy(config)?;
    let until = Instant::now() + TIMEOUT;
    let mut last_error = None;
    for address in addresses {
        let Some(remaining) = until.checked_duration_since(Instant::now()) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                #[cfg(windows)]
                crate::backend::process::register_proxy_connection(&stream)
                    .context("Cannot identify the local SOCKS5 process")?;
                let mut stream = DeadlineStream {
                    stream,
                    until: Instant::now() + TIMEOUT,
                };
                handshake(&mut stream, config)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 connect timed out")))
    .context("Cannot connect to SOCKS5 server")
}

fn handshake<S: Read + Write>(stream: &mut S, config: &Socks5Config) -> Result<()> {
    ensure!(
        config.user.len() <= 255 && config.pass.len() <= 255,
        "SOCKS5 credentials exceed 255 bytes"
    );
    ensure!(
        config.user.is_empty() == config.pass.is_empty(),
        "Incomplete SOCKS5 credentials"
    );
    let method = if config.user.is_empty() { 0 } else { 2 };
    stream.write_all(&[5, 1, method])?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply)?;
    ensure!(
        reply == [5, method],
        "SOCKS5 server rejected the offered authentication method"
    );
    if method == 2 {
        let mut request = vec![1, config.user.len() as u8];
        request.extend_from_slice(config.user.as_bytes());
        request.push(config.pass.len() as u8);
        request.extend_from_slice(config.pass.as_bytes());
        stream.write_all(&request)?;
        stream.read_exact(&mut reply)?;
        ensure!(reply == [1, 0], "SOCKS5 authentication failed");
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum Address {
    Ip(SocketAddr),
    Domain(String, u16),
}

fn read_address(reader: &mut impl Read, kind: u8) -> Result<Address> {
    let ip = match kind {
        1 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes)?;
            IpAddr::from(bytes)
        }
        4 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes)?;
            IpAddr::from(bytes)
        }
        3 => {
            let mut length = [0];
            reader.read_exact(&mut length)?;
            ensure!(length[0] != 0, "Empty SOCKS5 domain name");
            let mut bytes = vec![0; length[0] as usize];
            reader.read_exact(&mut bytes)?;
            let domain = String::from_utf8(bytes).context("Invalid SOCKS5 domain name")?;
            let mut port = [0; 2];
            reader.read_exact(&mut port)?;
            return Ok(Address::Domain(domain, u16::from_be_bytes(port)));
        }
        _ => bail!("Unsupported SOCKS5 address type {kind}"),
    };
    let mut port = [0; 2];
    reader.read_exact(&mut port)?;
    Ok(Address::Ip(SocketAddr::new(ip, u16::from_be_bytes(port))))
}

fn write_address(target: SocketAddr, output: &mut Vec<u8>) {
    match target.ip() {
        IpAddr::V4(ip) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&target.port().to_be_bytes());
}

fn command(stream: &mut (impl Read + Write), code: u8, target: SocketAddr) -> Result<Address> {
    let mut request = vec![5, code, 0];
    write_address(target, &mut request);
    stream.write_all(&request)?;
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    ensure!(
        header[0] == 5 && header[2] == 0,
        "Invalid SOCKS5 command reply"
    );
    ensure!(
        header[1] == 0,
        "SOCKS5 command {code} failed with reply {}",
        header[1]
    );
    read_address(stream, header[3])
}

pub fn connect(config: &Socks5Config, target: SocketAddr) -> Result<TcpStream> {
    let mut stream = authenticated(config)?;
    command(&mut stream, 1, target)?;
    stream
        .stream
        .set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.stream.set_write_timeout(Some(TIMEOUT))?;
    Ok(stream.stream)
}

pub struct UdpAssociation {
    pub socket: UdpSocket,
    pub control: TcpStream,
}

impl UdpAssociation {
    pub fn connect(config: &Socks5Config) -> Result<Self> {
        let mut stream = authenticated(config)?;
        let local_ip = stream.stream.local_addr()?.ip();
        let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0))?;
        let bound = command(&mut stream, 3, socket.local_addr()?)?;
        let relay = match bound {
            Address::Ip(mut address) => {
                if address.ip().is_unspecified() {
                    address.set_ip(stream.stream.peer_addr()?.ip());
                }
                address
            }
            Address::Domain(host, port) => resolve(&host, port)?
                .into_iter()
                .find(|address| address.is_ipv4() == local_ip.is_ipv4())
                .context("SOCKS5 UDP relay has no address matching the proxy connection family")?,
        };
        ensure!(relay.port() != 0, "SOCKS5 UDP relay returned port zero");
        // A connected UDP socket accepts responses only from the negotiated relay.
        ensure!(
            relay.is_ipv4() == local_ip.is_ipv4(),
            "SOCKS5 UDP relay family differs from the advertised UDP client endpoint"
        );
        socket.connect(relay)?;
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        socket.set_write_timeout(Some(TIMEOUT))?;
        stream.stream.set_nonblocking(true)?;
        Ok(Self {
            socket,
            control: stream.stream,
        })
    }

    fn check_control(&self) -> Result<()> {
        let mut byte = [0];
        match self.control.peek(&mut byte) {
            Ok(0) => bail!("SOCKS5 UDP control connection closed"),
            Ok(_) => bail!("Unexpected data on SOCKS5 UDP control connection"),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn send_to(&self, payload: &[u8], target: SocketAddr) -> Result<usize> {
        self.check_control()?;
        let packet = encode_udp(payload, target)?;
        ensure!(
            self.socket.send(&packet)? == packet.len(),
            "Partial SOCKS5 UDP send"
        );
        Ok(payload.len())
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.check_control()?;
        let mut packet = [0; 65535];
        // RFC 1928 requires discarding unsupported fragments. A malformed packet
        // must not tear down a healthy association or starve shutdown indefinitely.
        for _ in 0..16 {
            let size = self.socket.recv(&mut packet)?;
            let Ok((target, payload)) = decode_udp(&packet[..size]) else {
                continue;
            };
            ensure!(
                payload.len() <= buf.len(),
                "SOCKS5 UDP receive buffer is too small"
            );
            buf[..payload.len()].copy_from_slice(payload);
            return Ok((payload.len(), target));
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Discarded invalid SOCKS5 UDP datagrams",
        )
        .into())
    }
}

pub fn encode_udp(payload: &[u8], target: SocketAddr) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    write_address(target, &mut packet);
    ensure!(
        packet.len() + payload.len() <= 65507,
        "SOCKS5 UDP datagram is too large"
    );
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub fn decode_udp(packet: &[u8]) -> Result<(SocketAddr, &[u8])> {
    ensure!(
        packet.len() >= 4 && packet[..2] == [0, 0],
        "Invalid SOCKS5 UDP header"
    );
    ensure!(
        packet[2] == 0,
        "Fragmented SOCKS5 UDP datagrams are unsupported"
    );
    let mut cursor = io::Cursor::new(&packet[4..]);
    let target = match read_address(&mut cursor, packet[3])? {
        Address::Ip(address) => address,
        // Intercepted sockets always send concrete IP destinations. Performing DNS
        // in a receive loop could reorder responses and defeat process isolation.
        Address::Domain(_, _) => {
            bail!("SOCKS5 UDP replies must contain an IPv4/IPv6 source address")
        }
    };
    Ok((target, &packet[4 + cursor.position() as usize..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    struct Fragmented {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Fragmented {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let length = buf.len().min(1);
            self.input.read(&mut buf[..length])
        }
    }
    impl Write for Fragmented {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(&buf[..buf.len().min(1)]);
            Ok(buf.len().min(1))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn config(port: u16) -> Socks5Config {
        Socks5Config {
            host: "127.0.0.1".into(),
            port,
            user: String::new(),
            pass: String::new(),
        }
    }
    #[test]
    fn fragmented_handshake_and_connect_preserve_application_data() {
        let mut stream = Fragmented {
            input: io::Cursor::new(vec![5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 42]),
            output: vec![],
        };
        handshake(&mut stream, &config(1)).unwrap();
        command(&mut stream, 1, "8.8.8.8:443".parse().unwrap()).unwrap();
        assert_eq!(stream.output, [5, 1, 0, 5, 1, 0, 1, 8, 8, 8, 8, 1, 187]);
        let mut app = [0];
        stream.read_exact(&mut app).unwrap();
        assert_eq!(app, [42]);
    }
    #[test]
    fn authentication_rejects_downgrade_and_bad_version() {
        let mut cfg = config(1);
        cfg.user = "u".into();
        cfg.pass = "p".into();
        for input in [vec![5, 0], vec![4, 2], vec![5, 2, 1, 1], vec![5, 2, 5, 0]] {
            let mut stream = Fragmented {
                input: io::Cursor::new(input),
                output: vec![],
            };
            assert!(handshake(&mut stream, &cfg).is_err());
        }
        let mut stream = Fragmented {
            input: io::Cursor::new(vec![5, 2, 1, 0]),
            output: vec![],
        };
        handshake(&mut stream, &cfg).unwrap();
        assert_eq!(stream.output, [5, 1, 2, 1, 1, b'u', 1, b'p']);
    }
    #[test]
    fn udp_ipv4_ipv6_roundtrip_and_malformed_packets() {
        for target in ["8.8.8.8:53", "[2606:4700:4700::1111]:53"] {
            let address = target.parse().unwrap();
            let packet = encode_udp(b"test", address).unwrap();
            assert_eq!(decode_udp(&packet).unwrap(), (address, &b"test"[..]));
            for end in 0..packet.len() - 4 {
                assert!(decode_udp(&packet[..end]).is_err());
            }
            let mut fragment = packet.clone();
            fragment[2] = 1;
            assert!(decode_udp(&fragment).is_err());
        }
        assert!(encode_udp(&vec![0; 65507], "8.8.8.8:1".parse().unwrap()).is_err());
    }
    #[test]
    fn command_accepts_domain_reply_without_resolving_connect_bind_address() {
        let mut stream = Fragmented {
            input: io::Cursor::new(vec![5, 0, 0, 3, 3, b'a', b'.', b'b', 0, 80, 42]),
            output: vec![],
        };
        assert_eq!(
            command(&mut stream, 1, "8.8.8.8:80".parse().unwrap()).unwrap(),
            Address::Domain("a.b".into(), 80)
        );
        assert_eq!(stream.input.position(), 10);
    }
    #[test]
    fn mock_proxy_tcp_connect_and_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            let mut req = [0; 10];
            stream.read_exact(&mut req).unwrap();
            assert_eq!(req[1], 1);
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0, b'o', b'k'])
                .unwrap();
        });
        let mut client = connect(&config(port), "8.8.8.8:443".parse().unwrap()).unwrap();
        let mut payload = [0; 2];
        client.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"ok");
        server.join().unwrap();
    }
    #[test]
    fn mock_proxy_udp_association_and_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        relay.set_read_timeout(Some(TIMEOUT)).unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            stream.write_all(&[5, 0]).unwrap();
            let mut req = [0; 10];
            stream.read_exact(&mut req).unwrap();
            assert_eq!(req[1], 3);
            let mut response = vec![5, 0, 0, 1, 0, 0, 0, 0];
            response.extend_from_slice(&relay_port.to_be_bytes());
            stream.write_all(&response).unwrap();
            let mut data = [0; 512];
            let (size, peer) = relay.recv_from(&mut data).unwrap();
            let (address, body) = decode_udp(&data[..size]).unwrap();
            assert_eq!(address, "8.8.8.8:53".parse().unwrap());
            assert_eq!(body, b"dns");
            let mut fragment = data[..size].to_vec();
            fragment[2] = 1;
            relay.send_to(&fragment, peer).unwrap();
            relay.send_to(&data[..size], peer).unwrap();
            rx.recv_timeout(TIMEOUT).unwrap();
        });
        let association = UdpAssociation::connect(&config(port)).unwrap();
        association
            .send_to(b"dns", "8.8.8.8:53".parse().unwrap())
            .unwrap();
        let mut reply = [0; 32];
        let (size, source) = association.recv_from(&mut reply).unwrap();
        assert_eq!(&reply[..size], b"dns");
        assert_eq!(source, "8.8.8.8:53".parse().unwrap());
        tx.send(()).unwrap();
        server.join().unwrap();
    }
}
