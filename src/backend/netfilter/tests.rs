//! Driver-free regressions: real loopback proxy peers, with only the SDK boundary
//! replaced. No DLL is loaded and no filtering rule or Windows service is changed.
use super::*;
use crate::config::{BackendKind, Rule, Socks5Config, UdpTransportKind};
use crate::gpux::protocol::{self, AeadKey, Packet, PacketType};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Complete(u64, SocketAddr, u32, u32),
    Receive(u64, Vec<u8>),
    SendEof(u64),
    Abort(u64),
    Datagram(u64, SocketAddr, Vec<u8>, Vec<u8>),
}

static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

unsafe extern "C" fn complete(id: u64, info: *mut TcpInfo) -> i32 {
    let info = unsafe { ptr::read_unaligned(info) };
    lock(&EVENTS).push(Event::Complete(
        id,
        decode_address(&info.remote_address).unwrap(),
        info.filtering_flag,
        info.process_id,
    ));
    0
}

unsafe extern "C" fn receive(id: u64, data: *const u8, len: i32) -> i32 {
    let payload = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len as usize).to_vec() }
    };
    lock(&EVENTS).push(Event::Receive(id, payload));
    0
}

unsafe extern "C" fn send_eof(id: u64, _: *const u8, len: i32) -> i32 {
    if len == 0 {
        lock(&EVENTS).push(Event::SendEof(id));
    }
    0
}

unsafe extern "C" fn abort(id: u64) -> i32 {
    lock(&EVENTS).push(Event::Abort(id));
    0
}

unsafe extern "C" fn datagram(
    id: u64,
    source: *const u8,
    data: *const u8,
    len: i32,
    options: *mut UdpOptions,
) -> i32 {
    let source = unsafe { decode_address_pointer(source) }.unwrap();
    let payload = unsafe { std::slice::from_raw_parts(data, len as usize).to_vec() };
    let options = unsafe { copy_options(options) }.unwrap();
    lock(&EVENTS).push(Event::Datagram(id, source, payload, options));
    0
}

struct Harness {
    runtime: Arc<Runtime>,
    _guard: MutexGuard<'static, ()>,
    _winsock: Winsock,
}

impl Harness {
    fn new(port: u16) -> Self {
        Self::with_config(port, |_| {})
    }

    fn with_config(port: u16, configure: impl FnOnce(&mut AppConfig)) -> Self {
        let guard = lock(&START_LOCK);
        lock(&EVENTS).clear();
        let mut api = Api::test_stub();
        api.tcp_complete = complete;
        api.tcp_post_receive = receive;
        api.tcp_post_send = send_eof;
        api.tcp_close = abort;
        api.udp_post_receive = datagram;
        let mut config = AppConfig {
            backend: BackendKind::Netfilter,
            udp_transport: Default::default(),
            gpux: Default::default(),
            socks5: Socks5Config {
                host: "127.0.0.1".into(),
                port,
                user: String::new(),
                pass: String::new(),
            },
            rules: vec![Rule {
                process_names: vec!["mock-game.exe".into()],
                accelerate_tcp: true,
                accelerate_udp: true,
            }],
        };
        configure(&mut config);
        let config = Arc::new(config);
        let upstream = Arc::new(UdpUpstream::start(&config).unwrap());
        let proxy_addresses = upstream
            .endpoint_addresses()
            .unwrap()
            .into_iter()
            .map(proxy_address)
            .collect();
        let runtime = Arc::new(Runtime {
            api: Arc::new(api),
            config,
            upstream,
            proxy_addresses,
            metrics: Arc::new(Metrics::default()),
            external_stop: Arc::new(AtomicBool::new(false)),
            stopping: AtomicBool::new(false),
            tcp: Mutex::new(HashMap::new()),
            udp: Mutex::new(HashMap::new()),
            workers: Mutex::new(Vec::new()),
            diagnostics: Diagnostics::default(),
        });
        *lock(&ACTIVE) = Some(Arc::clone(&runtime));
        Self {
            runtime,
            _guard: guard,
            _winsock: Winsock::start().unwrap(),
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.runtime.stopping.store(true, Ordering::Release);
        let workers = std::mem::take(&mut *lock(&self.runtime.workers));
        for worker in workers {
            let _ = worker.join();
        }
        self.runtime.upstream.stop();
        lock(&ACTIVE).take();
    }
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "timed out; SDK events: {:?}",
            lock(&EVENTS)
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn upstream_endpoint_is_exempt_for_native_and_mapped_ipv4() {
    let harness = Harness::with_config(40000, |config| {
        config.socks5.host = "203.0.113.5".into();
        config.rules[0].process_names = vec!["*.exe".into()];
    });
    assert!(harness.runtime.bypass("203.0.113.5:40000".parse().unwrap()));
    assert!(harness
        .runtime
        .bypass("[::ffff:203.0.113.5]:40000".parse().unwrap()));
    assert!(!harness.runtime.bypass("203.0.113.5:40001".parse().unwrap()));
    assert!(!harness.runtime.bypass("203.0.113.6:40000".parse().unwrap()));
}

fn accept(listener: &TcpListener, command: u8) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "SOCKS client did not connect");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("{error}"),
        }
    };
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut hello = [0; 3];
    socket.read_exact(&mut hello).unwrap();
    assert_eq!(hello, [5, 1, 0]);
    socket.write_all(&[5, 0]).unwrap();
    let mut request = [0; 10];
    socket.read_exact(&mut request).unwrap();
    assert_eq!(&request[..4], &[5, command, 0, 1]);
    socket
}

fn tcp_info() -> TcpInfo {
    TcpInfo {
        filtering_flag: ffi::FILTER | ffi::CONNECT_REQUESTS,
        process_id: u32::MAX,
        direction: 2,
        ip_family: 2,
        local_address: encode_address("127.0.0.1:0".parse().unwrap()),
        remote_address: encode_address("203.0.113.1:443".parse().unwrap()),
    }
}

#[test]
fn tcp_redirect_uses_real_stream_without_sdk_connected_or_injection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let harness = Harness::new(listener.local_addr().unwrap().port());
    let reply: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    let expected = reply.clone();
    let server = thread::spawn(move || {
        let mut socket = accept(&listener, 1);
        socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        socket.write_all(b"banner").unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"request-one/request-two");
        socket.write_all(&reply).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
    });
    unsafe {
        tcp_connect(7, &mut tcp_info());
    }
    let mut redirect = None;
    wait_until(|| {
        redirect = lock(&EVENTS).iter().find_map(|event| match *event {
            Event::Complete(7, address, flags, owner) => Some((address, flags, owner)),
            _ => None,
        });
        redirect.is_some()
    });
    let (address, flags, owner) = redirect.unwrap();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    assert_eq!(
        flags, 0,
        "WFP uses a real local connection, not OFFLINE/FILTER"
    );
    assert_eq!(
        owner,
        std::process::id(),
        "WFP must identify the local proxy owner"
    );
    // Model the application connecting to the address returned by the WFP callback.
    // Deliberately never deliver tcpConnected, tcpCanReceive, or tcpSend events.
    let mut application = TcpStream::connect(address).unwrap();
    application
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    application
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut banner = [0; 6];
    application.read_exact(&mut banner).unwrap();
    assert_eq!(&banner, b"banner");
    application.write_all(b"request-one/").unwrap();
    application.write_all(b"request-two").unwrap();
    application.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    application.read_to_end(&mut response).unwrap();
    assert_eq!(response, expected);
    server.join().unwrap();
    wait_until(|| {
        lock(&harness.runtime.workers)
            .iter()
            .all(JoinHandle::is_finished)
    });
    assert_eq!(
        *lock(&EVENTS),
        vec![Event::Complete(7, address, 0, std::process::id())]
    );
    assert_eq!(harness.runtime.metrics.tcp_up.load(Ordering::Relaxed), 23);
    assert_eq!(
        harness.runtime.metrics.tcp_down.load(Ordering::Relaxed),
        100_006
    );
    assert!(!lock(&harness.runtime.tcp).contains_key(&7));
}

fn options(tag: u8) -> Vec<u8> {
    let mut result = vec![0; 9];
    result[4..8].copy_from_slice(&1i32.to_ne_bytes());
    result[8] = tag;
    result
}

#[test]
fn udp_reply_uses_its_peer_options_and_original_sdk_address_family() {
    let mut routes = UdpRoutes::default();
    let mapped: SocketAddr = "[::ffff:203.0.113.1]:3659".parse().unwrap();
    let native: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    routes.remember(mapped, options(11));
    routes.remember(native, options(22));
    let (address, option) = routes.reply("203.0.113.1:3659".parse().unwrap()).unwrap();
    assert_eq!(decode_address(&address), Some(mapped));
    assert_eq!(option, options(11));
    let (address, option) = routes.reply(native).unwrap();
    assert_eq!(decode_address(&address), Some(native));
    assert_eq!(option, options(22));
    assert_eq!(proxy_address(mapped), "203.0.113.1:3659".parse().unwrap());
    for port in 1..300 {
        routes.remember(
            SocketAddr::new(Ipv4Addr::new(203, 0, 113, 2).into(), port),
            options(33),
        );
    }
    assert_eq!(routes.entries.len(), 256);
    assert_eq!(routes.bytes, 256 * 9);
}

#[test]
fn udp_recovers_on_same_endpoint_after_proxy_control_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let harness = Harness::new(listener.local_addr().unwrap().port());
    let (closed_tx, closed_rx) = mpsc::channel();
    let (finish_tx, finish_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        for attempt in 0..2 {
            let mut control = accept(&listener, 3);
            let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
            relay
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
            response.extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
            control.write_all(&response).unwrap();
            let mut buffer = [0; 1024];
            let (len, client) = relay.recv_from(&mut buffer).unwrap();
            assert_eq!(
                &buffer[..4],
                &[0, 0, 0, 1],
                "mapped IPv4 must use SOCKS IPv4 framing"
            );
            if attempt == 0 {
                control.shutdown(Shutdown::Both).unwrap();
                closed_tx.send(()).unwrap();
            } else {
                relay.send_to(&buffer[..len], client).unwrap();
                finish_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            }
        }
    });
    let mut info = UdpInfo {
        process_id: u32::MAX,
        ip_family: 23,
        local_address: encode_address("[::]:12345".parse().unwrap()),
    };
    let remote: SocketAddr = "[::ffff:203.0.113.1]:3659".parse().unwrap();
    let address = encode_address(remote);
    let mut options = options(77);
    unsafe {
        udp_created(9, &mut info);
        udp_send(
            9,
            address.as_ptr(),
            b"first".as_ptr(),
            5,
            options.as_mut_ptr().cast(),
        );
    }
    closed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut last_send = Instant::now();
    wait_until(|| {
        if lock(&EVENTS)
            .iter()
            .any(|event| matches!(event, Event::Datagram(9, ..)))
        {
            return true;
        }
        if last_send.elapsed() >= Duration::from_millis(50) {
            unsafe {
                udp_send(
                    9,
                    address.as_ptr(),
                    b"recovered".as_ptr(),
                    9,
                    options.as_mut_ptr().cast(),
                );
            }
            last_send = Instant::now();
        }
        false
    });
    assert!(lock(&EVENTS).contains(&Event::Datagram(9, remote, b"recovered".to_vec(), options)));
    assert!(!lock(&harness.runtime.udp)
        .get(&9)
        .unwrap()
        .closed
        .load(Ordering::Acquire));
    unsafe {
        udp_closed(9, ptr::null_mut());
    }
    finish_tx.send(()).unwrap();
    server.join().unwrap();
}

#[test]
fn gpux_encrypted_udp_restores_each_route_options_and_original_address_family() {
    const TOKEN: &str = "netfilter-gpux-test";
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let port = peer.local_addr().unwrap().port();
    let (finish_tx, finish_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut buffer = [0; 65_507];
        let mut key: Option<AeadKey> = None;
        let mut sequence = 0;
        let mut flows = HashMap::new();
        let mut requests = Vec::new();
        loop {
            let (length, client) = peer.recv_from(&mut buffer).unwrap();
            assert!(length >= protocol::OUTER_HEADER_SIZE + protocol::AUTH_TAG_SIZE);
            let connection_id = u64::from_be_bytes(buffer[8..16].try_into().unwrap());
            let key =
                key.get_or_insert_with(|| protocol::derive_key(TOKEN, connection_id).unwrap());
            let packet = protocol::decode(&buffer[..length], Some(key), 0).unwrap();
            if packet.packet_type == PacketType::Ack {
                continue;
            }
            let acknowledgement = Packet {
                packet_type: PacketType::Ack,
                connection_id,
                packet_seq: sequence,
                ack_base: packet.packet_seq,
                ack_bitmap: 1,
                ..Packet::default()
            };
            sequence += 1;
            peer.send_to(
                &protocol::encode(&acknowledgement, Some(key), 1).unwrap(),
                client,
            )
            .unwrap();
            match packet.packet_type {
                PacketType::Chlo => {
                    let hello = protocol::decode_chlo(&packet.payload).unwrap();
                    assert_eq!(hello.connection_id, connection_id);
                    assert_eq!(hello.token, TOKEN);
                }
                PacketType::FlowOpen => {
                    let flow = protocol::decode_flow_open(&packet.payload).unwrap();
                    assert_eq!(flow.profile, "opaque_fps");
                    flows.insert(flow.flow_id, flow.target);
                }
                PacketType::Data => {
                    for inner in protocol::decode_inners(&packet.payload).unwrap() {
                        assert_eq!(inner.direction, 0);
                        assert!(inner.ttl_us.is_some());
                        assert!(flows.contains_key(&inner.flow_id));
                        requests.push(inner);
                    }
                    if requests.len() == 2 {
                        // Reverse the routes in a single reply so the SDK adapter
                        // must look up both saved option buffers, including IPv4
                        // represented by an original IPv6-mapped SDK address.
                        let mut payload = Vec::new();
                        for inner in requests.iter().rev() {
                            let echoed = [inner.payload.as_slice(), b"-echo"].concat();
                            payload.extend(
                                protocol::encode_inner(
                                    inner.flow_id,
                                    1,
                                    1,
                                    Some(1_000_000),
                                    &echoed,
                                )
                                .unwrap(),
                            );
                        }
                        let response = Packet {
                            packet_type: PacketType::Data,
                            connection_id,
                            packet_seq: sequence,
                            ack_base: packet.packet_seq,
                            ack_bitmap: 1,
                            payload,
                            ..Packet::default()
                        };
                        peer.send_to(&protocol::encode(&response, Some(key), 1).unwrap(), client)
                            .unwrap();
                        finish_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        return flows;
                    }
                }
                _ => panic!("unexpected GPUX packet: {:?}", packet.packet_type),
            }
        }
    });
    let harness = Harness::with_config(1080, |config| {
        config.udp_transport = UdpTransportKind::Gpux;
        config.gpux.port = port;
        config.gpux.token = TOKEN.into();
        config.gpux.deadline_ms = 1000;
        config.rules[0].accelerate_tcp = false;
    });
    let mut info = UdpInfo {
        process_id: u32::MAX,
        ip_family: 23,
        local_address: encode_address("[::]:12345".parse().unwrap()),
    };
    let mapped: SocketAddr = "[::ffff:203.0.113.1]:3659".parse().unwrap();
    let native: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    unsafe { udp_created(11, &mut info) };
    for (remote, payload, tag) in [
        (mapped, b"mapped-first".as_slice(), 77),
        (native, b"native-second", 88),
    ] {
        let address = encode_address(remote);
        let mut option = options(tag);
        unsafe {
            udp_send(
                11,
                address.as_ptr(),
                payload.as_ptr(),
                payload.len() as i32,
                option.as_mut_ptr().cast(),
            )
        };
        // The callback must copy SDK data before the driver reuses its memory.
        option.fill(0);
    }
    wait_until(|| {
        lock(&EVENTS)
            .iter()
            .filter(|event| matches!(event, Event::Datagram(11, ..)))
            .count()
            == 2
    });
    assert_eq!(
        *lock(&EVENTS),
        vec![
            Event::Datagram(11, native, b"native-second-echo".to_vec(), options(88)),
            Event::Datagram(11, mapped, b"mapped-first-echo".to_vec(), options(77)),
        ]
    );
    assert_eq!(harness.runtime.metrics.udp_up.load(Ordering::Relaxed), 25);
    assert_eq!(harness.runtime.metrics.udp_down.load(Ordering::Relaxed), 35);
    unsafe { udp_closed(11, ptr::null_mut()) };
    wait_until(|| {
        lock(&harness.runtime.workers)
            .iter()
            .all(JoinHandle::is_finished)
    });
    harness.runtime.upstream.stop();
    finish_tx.send(()).unwrap();
    let flows = server.join().unwrap();
    assert_eq!(flows.len(), 2);
    assert!(flows
        .values()
        .any(|address| *address == proxy_address(mapped)));
    assert!(flows.values().any(|address| *address == native));
}
