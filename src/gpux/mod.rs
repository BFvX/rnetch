//! Driver-neutral GPUX UDP tunnel. The one owned worker performs every network
//! operation; forwarding workers only enqueue datagrams and inspect replies.
pub mod protocol;

use crate::config::{GpuxConfig, GpuxEncryption};
use anyhow::{bail, ensure, Context, Result};
use protocol::{AeadKey, FecParity, FecSource, Packet, PacketType};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Condvar, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const POLL_INTERVAL: Duration = Duration::from_millis(1);
const CONTROL_RETRY: Duration = Duration::from_millis(250);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const ACK_DELAY: Duration = Duration::from_millis(5);
const REPLAY_WINDOW: u64 = 2048;
const FEC_K: u8 = 4;
const INNER_HEADER_SIZE: usize = 13;
// The reference server silently evicts idle egress sockets after 45 seconds.
// Retire cached IDs earlier so the first resumed request opens a fresh flow.
const FLOW_IDLE_REFRESH: Duration = Duration::from_secs(30);
// XOR parity has four fixed bytes and nine metadata bytes per source.
const FEC_OVERHEAD: usize = 4 + FEC_K as usize * 9;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockServer {
        address: SocketAddr,
        stopping: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
        events: mpsc::Receiver<Packet>,
    }

    impl MockServer {
        fn start(encryption: GpuxEncryption, reject_flows: bool) -> Self {
            Self::start_with_behavior(encryption, reject_flows, false)
        }

        fn start_with_behavior(
            encryption: GpuxEncryption,
            reject_flows: bool,
            close_on_data: bool,
        ) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let address = socket.local_addr().unwrap();
            let stopping = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stopping);
            let (events_tx, events) = mpsc::sync_channel(512);
            let worker = thread::spawn(move || {
                let mut wire = [0; 65535];
                let mut sequence = 0;
                while !worker_stop.load(Ordering::Acquire) {
                    let (size, peer) = match socket.recv_from(&mut wire) {
                        Ok(value) => value,
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::TimedOut
                                    | io::ErrorKind::WouldBlock
                                    | io::ErrorKind::ConnectionReset
                            ) =>
                        {
                            continue
                        }
                        Err(error) => panic!("mock receive: {error}"),
                    };
                    if size < protocol::OUTER_HEADER_SIZE {
                        continue;
                    }
                    let connection_id = u64::from_be_bytes(wire[8..16].try_into().unwrap());
                    let key = (encryption == GpuxEncryption::Chacha20Poly1305)
                        .then(|| protocol::derive_key("mock-token", connection_id).unwrap());
                    let packet = protocol::decode(&wire[..size], key.as_ref(), 0).unwrap();
                    let _ = events_tx.try_send(packet.clone());
                    if packet.packet_type == PacketType::Ack {
                        continue;
                    }
                    let mut response = Packet {
                        packet_type: PacketType::Ack,
                        connection_id,
                        packet_seq: sequence,
                        ack_base: packet.packet_seq,
                        ack_bitmap: 1,
                        ..Packet::default()
                    };
                    sequence += 1;
                    socket
                        .send_to(&protocol::encode(&response, key.as_ref(), 1).unwrap(), peer)
                        .unwrap();
                    if reject_flows && packet.packet_type == PacketType::FlowOpen {
                        let flow = protocol::decode_flow_open(&packet.payload).unwrap();
                        response.packet_type = PacketType::FlowClose;
                        response.packet_seq = sequence;
                        sequence += 1;
                        response.payload = protocol::encode_flow_close(flow.flow_id, 2);
                        socket
                            .send_to(&protocol::encode(&response, key.as_ref(), 1).unwrap(), peer)
                            .unwrap();
                    }
                    if packet.packet_type == PacketType::Data && !reject_flows {
                        if close_on_data {
                            response.packet_type = PacketType::Close;
                            response.packet_seq = sequence;
                            sequence += 1;
                            socket
                                .send_to(
                                    &protocol::encode(&response, key.as_ref(), 1).unwrap(),
                                    peer,
                                )
                                .unwrap();
                            continue;
                        }
                        response.packet_type = PacketType::Data;
                        response.packet_seq = sequence;
                        sequence += 1;
                        response.payload.clear();
                        for inner in protocol::decode_inners(&packet.payload).unwrap() {
                            response.payload.extend(
                                protocol::encode_inner(
                                    inner.flow_id,
                                    1,
                                    1,
                                    Some(500_000),
                                    &inner.payload,
                                )
                                .unwrap(),
                            );
                        }
                        let encoded = protocol::encode(&response, key.as_ref(), 1).unwrap();
                        socket.send_to(&encoded, peer).unwrap();
                        // Deliberately duplicate server data to exercise replay
                        // protection on the runtime rather than the wire codec.
                        socket.send_to(&encoded, peer).unwrap();
                    }
                }
            });
            Self {
                address,
                stopping,
                worker: Some(worker),
                events,
            }
        }

        fn config(&self, encryption: GpuxEncryption) -> GpuxConfig {
            GpuxConfig {
                host: self.address.ip().to_string(),
                port: self.address.port(),
                token: "mock-token".into(),
                encryption,
                deadline_ms: 500,
                ..GpuxConfig::default()
            }
        }

        fn wait_packet(&self, packet_type: PacketType) -> Packet {
            let until = Instant::now() + Duration::from_secs(2);
            loop {
                let packet = self
                    .events
                    .recv_timeout(until.saturating_duration_since(Instant::now()))
                    .expect("mock packet timed out");
                if packet.packet_type == packet_type {
                    return packet;
                }
            }
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.stopping.store(true, Ordering::Release);
            self.worker.take().unwrap().join().unwrap();
        }
    }

    fn receive(session: &GpuxSession) -> (Vec<u8>, SocketAddr) {
        let until = Instant::now() + Duration::from_secs(2);
        let mut buffer = [0; 2048];
        loop {
            match session.recv_from(&mut buffer) {
                Ok((size, target)) => return (buffer[..size].to_vec(), target),
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock) =>
                {
                    assert!(Instant::now() < until, "GPUX reply timed out");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("GPUX receive: {error:#}"),
            }
        }
    }

    #[test]
    fn multiplexes_sessions_and_destinations_without_duplicate_delivery() {
        for encryption in [GpuxEncryption::Plaintext, GpuxEncryption::Chacha20Poly1305] {
            let server = MockServer::start(encryption, false);
            let runtime = GpuxRuntime::start(&server.config(encryption)).unwrap();
            assert_eq!(runtime.endpoint_addresses(), vec![server.address]);
            let first = runtime.open_session().unwrap();
            let second = runtime.open_session().unwrap();
            let target_v4 = "192.0.2.1:8001".parse().unwrap();
            let target_v6 = "[2001:db8::1]:8002".parse().unwrap();
            first.send_to(b"one", target_v4, Instant::now()).unwrap();
            first.send_to(b"two", target_v6, Instant::now()).unwrap();
            second.send_to(b"three", target_v4, Instant::now()).unwrap();
            assert_eq!(receive(&first), (b"one".to_vec(), target_v4));
            assert_eq!(receive(&first), (b"two".to_vec(), target_v6));
            assert_eq!(receive(&second), (b"three".to_vec(), target_v4));
            assert!(first.recv_from(&mut [0; 1024]).is_err());
            assert!(second.recv_from(&mut [0; 1024]).is_err());
            drop(first);
            let close = server.wait_packet(PacketType::FlowClose);
            assert_eq!(protocol::decode_flow_close(&close.payload).unwrap().1, 0);
            runtime.stop();
            runtime.stop();
            assert!(runtime.check_alive().is_err());
            assert!(second.check_alive().is_err());
            let _ = server.wait_packet(PacketType::Close);
        }
    }

    #[test]
    fn deadline_starts_at_capture_and_bounded_queue_is_retryable() {
        let server = MockServer::start(GpuxEncryption::Plaintext, false);
        let config = GpuxConfig {
            queue_limit: 1,
            batch_window_us: 200_000,
            ..server.config(GpuxEncryption::Plaintext)
        };
        let runtime = GpuxRuntime::start(&config).unwrap();
        let session = runtime.open_session().unwrap();
        let target = "192.0.2.1:8001".parse().unwrap();
        assert_eq!(
            session
                .send_to(b"expired", target, Instant::now() - Duration::from_secs(1))
                .unwrap(),
            0
        );
        assert_eq!(
            session
                .send_to(
                    &vec![0; config.mtu_payload as usize],
                    target,
                    Instant::now()
                )
                .unwrap(),
            0
        );
        assert_eq!(
            session.send_to(b"queued", target, Instant::now()).unwrap(),
            6
        );
        let error = session
            .send_to(b"full", target, Instant::now())
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        let _ = server.wait_packet(PacketType::FlowOpen);
        drop(session);
        let _ = server.wait_packet(PacketType::FlowClose);
        runtime.stop();
    }

    #[test]
    fn server_flow_rejection_surfaces_to_forwarding_worker() {
        let server = MockServer::start(GpuxEncryption::Chacha20Poly1305, true);
        let runtime = GpuxRuntime::start(&server.config(GpuxEncryption::Chacha20Poly1305)).unwrap();
        let session = runtime.open_session().unwrap();
        session
            .send_to(
                b"rejected",
                "192.0.2.1:8001".parse().unwrap(),
                Instant::now(),
            )
            .unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        while session.check_alive().is_ok() {
            assert!(Instant::now() < until, "flow rejection was not propagated");
            thread::sleep(Duration::from_millis(1));
        }
        assert!(format!("{:#}", session.check_alive().unwrap_err()).contains("reason 2"));
        runtime.check_alive().unwrap();
        runtime.stop();
    }

    #[test]
    fn receive_window_rejects_duplicate_and_old_sequences() {
        let mut window = ReceiveWindow::default();
        assert!(window.accept(10));
        assert!(window.accept(12));
        assert!(window.accept(11));
        assert!(!window.accept(11));
        assert_eq!(window.ack(), (12, 7));
        assert!(window.accept(3000));
        assert!(!window.accept(12));
    }

    #[test]
    fn queued_reply_expiry_is_checked_at_delivery() {
        let server = MockServer::start(GpuxEncryption::Plaintext, false);
        let runtime = GpuxRuntime::start(&server.config(GpuxEncryption::Plaintext)).unwrap();
        let session = runtime.open_session().unwrap();
        lock(&session.state.received).push_back(ReceivedDatagram {
            target: "192.0.2.1:8001".parse().unwrap(),
            payload: b"stale".to_vec(),
            expires: Some(Instant::now() - Duration::from_millis(1)),
        });
        let error = session.recv_from(&mut [0; 1024]).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        runtime.stop();
    }

    #[test]
    fn fec_recovers_missing_first_source_before_delivering_later_originals() {
        let server = MockServer::start(GpuxEncryption::Plaintext, false);
        let runtime = GpuxRuntime::start(&server.config(GpuxEncryption::Plaintext)).unwrap();
        let session = runtime.open_session().unwrap();
        let (started, _) = mpsc::sync_channel(1);
        let mut worker = Worker::new(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            Arc::clone(&runtime.shared),
            42,
            None,
            started,
            Duration::from_secs(1),
        );
        worker.flows.insert(
            7,
            WorkerFlow {
                target: "192.0.2.1:8001".parse().unwrap(),
                session: Arc::clone(&session.state),
                last_down_sequence: None,
                opened: true,
            },
        );
        let sources: Vec<_> = (0..4)
            .map(|index| FecSource {
                fec_index: index,
                packet_seq: 20 + index as u64,
                payload: protocol::encode_inner(7, 1, 1, Some(500_000), &[index]).unwrap(),
            })
            .collect();
        for source in &sources[1..] {
            worker
                .handle_packet(Packet {
                    packet_type: PacketType::Data,
                    connection_id: 42,
                    packet_seq: source.packet_seq,
                    fec_group_id: 1,
                    fec_k: 4,
                    fec_n: 5,
                    fec_index: source.fec_index,
                    payload: source.payload.clone(),
                    ..Packet::default()
                })
                .unwrap();
            worker.flush_received_fec();
            assert!(lock(&session.state.received).is_empty());
        }
        // A later complete group must also wait for the older missing source;
        // otherwise recovering that source would violate per-flow ordering.
        for index in 0..4 {
            worker
                .handle_packet(Packet {
                    packet_type: PacketType::Data,
                    connection_id: 42,
                    packet_seq: 25 + index as u64,
                    fec_group_id: 2,
                    fec_k: 4,
                    fec_n: 5,
                    fec_index: index,
                    payload: protocol::encode_inner(7, 1, 1, Some(500_000), &[index + 4]).unwrap(),
                    ..Packet::default()
                })
                .unwrap();
        }
        worker.flush_received_fec();
        assert!(lock(&session.state.received).is_empty());
        worker
            .handle_packet(Packet {
                packet_type: PacketType::Parity,
                connection_id: 42,
                packet_seq: 24,
                fec_group_id: 1,
                fec_k: 4,
                fec_n: 5,
                fec_index: 4,
                payload: protocol::encode_fec(&sources).unwrap(),
                ..Packet::default()
            })
            .unwrap();
        worker.flush_received_fec();
        let delivered: Vec<_> = lock(&session.state.received)
            .iter()
            .map(|datagram| datagram.payload.clone())
            .collect();
        assert_eq!(
            delivered,
            (0..8).map(|index| vec![index]).collect::<Vec<_>>()
        );
        assert!(!worker.received.accept(20));
        runtime.stop();
    }

    #[test]
    fn missing_parity_flushes_originals_before_their_ttl_expires() {
        let server = MockServer::start(GpuxEncryption::Plaintext, false);
        let runtime = GpuxRuntime::start(&server.config(GpuxEncryption::Plaintext)).unwrap();
        let session = runtime.open_session().unwrap();
        let (started, _) = mpsc::sync_channel(1);
        let mut worker = Worker::new(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            Arc::clone(&runtime.shared),
            42,
            None,
            started,
            Duration::from_secs(1),
        );
        worker.flows.insert(
            7,
            WorkerFlow {
                target: "192.0.2.1:8001".parse().unwrap(),
                session: Arc::clone(&session.state),
                last_down_sequence: None,
                opened: true,
            },
        );
        worker
            .handle_packet(Packet {
                packet_type: PacketType::Data,
                connection_id: 42,
                packet_seq: 21,
                fec_group_id: 1,
                fec_k: 4,
                fec_n: 5,
                fec_index: 1,
                payload: protocol::encode_inner(7, 1, 1, Some(50_000), b"survived").unwrap(),
                ..Packet::default()
            })
            .unwrap();
        worker.fec_decode.get_mut(&1).unwrap().first_seen =
            Instant::now() - Duration::from_millis(26);
        worker.flush_received_fec();
        assert_eq!(receive(&session).0, b"survived");
        assert!(worker.fec_decode.is_empty());
        runtime.stop();
    }

    #[test]
    fn redundant_late_parity_cannot_recreate_a_delivered_group() {
        let server = MockServer::start(GpuxEncryption::Plaintext, false);
        let runtime = GpuxRuntime::start(&server.config(GpuxEncryption::Plaintext)).unwrap();
        let session = runtime.open_session().unwrap();
        let (started, _) = mpsc::sync_channel(1);
        let mut worker = Worker::new(
            UdpSocket::bind("127.0.0.1:0").unwrap(),
            Arc::clone(&runtime.shared),
            42,
            None,
            started,
            Duration::from_secs(1),
        );
        worker.flows.insert(
            7,
            WorkerFlow {
                target: "192.0.2.1:8001".parse().unwrap(),
                session: Arc::clone(&session.state),
                last_down_sequence: None,
                opened: true,
            },
        );
        let sources: Vec<_> = (0..4)
            .map(|index| FecSource {
                fec_index: index,
                packet_seq: 20 + index as u64,
                payload: protocol::encode_inner(7, 1, 1, Some(8_000), &[index]).unwrap(),
            })
            .collect();
        for source in &sources {
            worker
                .handle_packet(Packet {
                    packet_type: PacketType::Data,
                    connection_id: 42,
                    packet_seq: source.packet_seq,
                    fec_group_id: 1,
                    fec_k: 4,
                    fec_n: 5,
                    fec_index: source.fec_index,
                    payload: source.payload.clone(),
                    ..Packet::default()
                })
                .unwrap();
        }
        worker.flush_received_fec();
        assert!(worker.fec_decode.is_empty());
        assert_eq!(lock(&session.state.received).len(), 4);
        worker
            .handle_packet(Packet {
                packet_type: PacketType::Parity,
                connection_id: 42,
                packet_seq: 24,
                fec_group_id: 1,
                fec_k: 4,
                fec_n: 5,
                fec_index: 4,
                payload: protocol::encode_fec(&sources).unwrap(),
                ..Packet::default()
            })
            .unwrap();
        assert!(
            worker.fec_decode.is_empty(),
            "late parity recreated completed group"
        );
        for index in 0..4 {
            worker
                .handle_packet(Packet {
                    packet_type: PacketType::Data,
                    connection_id: 42,
                    packet_seq: 25 + index as u64,
                    fec_group_id: 2,
                    fec_k: 4,
                    fec_n: 5,
                    fec_index: index,
                    payload: protocol::encode_inner(7, 1, 1, Some(8_000), &[index + 4]).unwrap(),
                    ..Packet::default()
                })
                .unwrap();
        }
        worker.flush_received_fec();
        assert!(worker.fec_decode.is_empty());
        let delivered: Vec<_> = lock(&session.state.received)
            .iter()
            .map(|datagram| datagram.payload.clone())
            .collect();
        assert_eq!(
            delivered,
            (0..8).map(|index| vec![index]).collect::<Vec<_>>()
        );
        runtime.stop();
    }

    #[test]
    fn resumed_idle_destination_gets_a_fresh_acknowledged_flow() {
        let server = MockServer::start(GpuxEncryption::Plaintext, false);
        let runtime = GpuxRuntime::start(&server.config(GpuxEncryption::Plaintext)).unwrap();
        let session = runtime.open_session().unwrap();
        let target = "192.0.2.1:8001".parse().unwrap();
        session
            .send_to(b"before-idle", target, Instant::now())
            .unwrap();
        assert_eq!(receive(&session).0, b"before-idle");
        let original =
            protocol::decode_flow_open(&server.wait_packet(PacketType::FlowOpen).payload).unwrap();
        lock(&runtime.shared.queues)
            .sessions
            .get_mut(&session.id)
            .unwrap()
            .flows
            .get_mut(&target)
            .unwrap()
            .last_activity = Instant::now() - FLOW_IDLE_REFRESH - Duration::from_secs(1);
        session
            .send_to(b"after-idle", target, Instant::now())
            .unwrap();
        assert_eq!(receive(&session).0, b"after-idle");
        let reopened =
            protocol::decode_flow_open(&server.wait_packet(PacketType::FlowOpen).payload).unwrap();
        assert_ne!(original.flow_id, reopened.flow_id);
        assert_eq!(original.target, reopened.target);
        assert_eq!(lock(&runtime.shared.queues).flow_count, 1);
        runtime.stop();
    }

    #[test]
    fn authenticated_server_close_is_terminal_and_shutdown_joins_promptly() {
        let server = MockServer::start_with_behavior(GpuxEncryption::Chacha20Poly1305, false, true);
        let runtime = GpuxRuntime::start(&server.config(GpuxEncryption::Chacha20Poly1305)).unwrap();
        let session = runtime.open_session().unwrap();
        let target = "192.0.2.1:8001".parse().unwrap();
        session
            .send_to(b"close-me", target, Instant::now())
            .unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        while runtime.check_alive().is_ok() {
            assert!(
                Instant::now() < until,
                "server CLOSE did not terminate runtime"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert!(session.check_alive().is_err());
        assert!(runtime.open_session().is_err());
        assert!(session
            .send_to(b"after-close", target, Instant::now())
            .is_err());
        let shutdown_started = Instant::now();
        runtime.stop();
        assert!(shutdown_started.elapsed() < Duration::from_millis(500));
    }
}

fn would_block(message: &'static str) -> anyhow::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message).into()
}

struct ReceivedDatagram {
    target: SocketAddr,
    payload: Vec<u8>,
    expires: Option<Instant>,
}

#[derive(Default)]
struct SessionState {
    received: Mutex<VecDeque<ReceivedDatagram>>,
    failure: Mutex<Option<String>>,
}

struct Registration {
    state: Arc<SessionState>,
    flows: HashMap<SocketAddr, RegisteredFlow>,
}

#[derive(Clone, Copy)]
struct RegisteredFlow {
    id: u32,
    last_activity: Instant,
}

struct QueuedDatagram {
    flow_id: u32,
    payload: Vec<u8>,
    expires: Instant,
    queued_at: Instant,
}

struct QueueState {
    sessions: HashMap<u64, Registration>,
    data: VecDeque<QueuedDatagram>,
    retired_flows: BTreeSet<u32>,
    revision: u64,
    next_session: u64,
    next_flow: u32,
    flow_count: usize,
}

struct Shared {
    config: GpuxConfig,
    queues: Mutex<QueueState>,
    wake: Condvar,
    stopping: AtomicBool,
    failure: Mutex<Option<String>>,
}

pub struct GpuxRuntime {
    shared: Arc<Shared>,
    addresses: Vec<SocketAddr>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

pub struct GpuxSession {
    runtime: Arc<GpuxRuntime>,
    id: u64,
    state: Arc<SessionState>,
}

impl GpuxRuntime {
    /// Resolve and authenticate before interception starts. GPUX v1 acknowledges
    /// CHLO using the ordinary ACK bitmap rather than a separate server hello.
    pub fn start(config: &GpuxConfig) -> Result<Arc<Self>> {
        ensure!(config.queue_limit > 0, "GPUX queue limit must be positive");
        ensure!(config.deadline_ms > 0, "GPUX deadline must be positive");
        ensure!(
            config.mtu_payload as usize
                > protocol::OUTER_HEADER_SIZE
                    + protocol::AUTH_TAG_SIZE
                    + INNER_HEADER_SIZE
                    + FEC_OVERHEAD,
            "GPUX MTU is too small"
        );
        let addresses = resolve(config)?;
        let until = Instant::now() + HANDSHAKE_TIMEOUT;
        let mut last_error = None;
        for (index, &endpoint) in addresses.iter().enumerate() {
            let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                break;
            };
            // Give later DNS candidates a chance when an earlier address is
            // routable locally but its server silently drops the handshake.
            let candidate_timeout = remaining / (addresses.len() - index) as u32;
            let result =
                Self::start_endpoint(config, endpoint, addresses.clone(), candidate_timeout);
            match result {
                Ok(runtime) => return Ok(runtime),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("GPUX handshake timed out")))
            .context("Cannot authenticate GPUX tunnel")
    }

    fn start_endpoint(
        config: &GpuxConfig,
        endpoint: SocketAddr,
        addresses: Vec<SocketAddr>,
        timeout: Duration,
    ) -> Result<Arc<Self>> {
        let bind: SocketAddr = if endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;
        let socket = UdpSocket::bind(bind).context("Cannot bind GPUX tunnel")?;
        socket
            .connect(endpoint)
            .context("Cannot connect GPUX tunnel")?;
        socket.set_nonblocking(true)?;
        #[cfg(windows)]
        let local_endpoint = socket.local_addr()?;
        let mut random = [0; 8];
        getrandom::getrandom(&mut random)
            .map_err(|error| anyhow::anyhow!("GPUX random connection ID: {error}"))?;
        let connection_id = u64::from_be_bytes(random);
        let key = match config.encryption {
            GpuxEncryption::Plaintext => None,
            GpuxEncryption::Chacha20Poly1305 => {
                Some(protocol::derive_key(&config.token, connection_id)?)
            }
        };
        let shared = Arc::new(Shared {
            config: config.clone(),
            queues: Mutex::new(QueueState {
                sessions: HashMap::new(),
                data: VecDeque::new(),
                retired_flows: BTreeSet::new(),
                revision: 0,
                next_session: 1,
                next_flow: 1,
                flow_count: 0,
            }),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
            failure: Mutex::new(None),
        });
        let worker_shared = Arc::clone(&shared);
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("gpux-tunnel".into())
            .spawn(move || {
                let mut worker = Worker::new(
                    socket,
                    Arc::clone(&worker_shared),
                    connection_id,
                    key,
                    started_tx,
                    timeout,
                );
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker.run()));
                let failure = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(format!("GPUX worker failed: {error:#}")),
                    Err(_) => Some("GPUX tunnel worker panicked".to_owned()),
                };
                if let Some(message) = failure {
                    *lock(&worker_shared.failure) = Some(message.clone());
                    if let Some(started) = worker.started.take() {
                        let _ = started.send(Err(message));
                    }
                }
                worker_shared.wake.notify_all();
            })
            .context("Cannot start GPUX tunnel worker")?;
        let runtime = Arc::new(Self {
            shared,
            addresses,
            worker: Mutex::new(Some(worker)),
        });
        match started_rx.recv_timeout(timeout + Duration::from_millis(100)) {
            Ok(Ok(())) => {
                #[cfg(windows)]
                crate::backend::process::register_udp_proxy(endpoint, local_endpoint)
                    .context("Cannot identify local GPUX server process")?;
                Ok(runtime)
            }
            Ok(Err(message)) => {
                runtime.stop();
                bail!(message)
            }
            Err(_) => {
                runtime.stop();
                bail!("GPUX CHLO was not acknowledged; check server, token and encryption")
            }
        }
    }

    pub fn endpoint_addresses(&self) -> Vec<SocketAddr> {
        self.addresses.clone()
    }

    pub fn check_alive(&self) -> Result<()> {
        if let Some(message) = lock(&self.shared.failure).as_ref() {
            bail!("{message}");
        }
        ensure!(
            !self.shared.stopping.load(Ordering::Acquire),
            "GPUX tunnel stopped"
        );
        Ok(())
    }

    pub fn open_session(self: &Arc<Self>) -> Result<GpuxSession> {
        self.check_alive()?;
        let state = Arc::new(SessionState::default());
        let mut queues = lock(&self.shared.queues);
        if queues.sessions.len() >= self.shared.config.queue_limit {
            return Err(would_block("GPUX session limit reached"));
        }
        let id = queues.next_session;
        queues.next_session = id.checked_add(1).context("GPUX session IDs exhausted")?;
        queues.sessions.insert(
            id,
            Registration {
                state: Arc::clone(&state),
                flows: HashMap::new(),
            },
        );
        Ok(GpuxSession {
            runtime: Arc::clone(self),
            id,
            state,
        })
    }

    /// Idempotent explicit shutdown, also used by Drop. The worker owns its socket
    /// and Shared, never the runtime Arc, so joining cannot form an ownership cycle.
    pub fn stop(&self) {
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.wake.notify_all();
        if let Some(worker) = lock(&self.worker).take() {
            if worker.join().is_err() {
                *lock(&self.shared.failure) = Some("GPUX tunnel worker panicked".into());
            }
        }
    }
}

impl Drop for GpuxRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

impl GpuxSession {
    pub fn check_alive(&self) -> Result<()> {
        self.runtime.check_alive()?;
        if let Some(message) = lock(&self.state.failure).as_ref() {
            bail!("{message}");
        }
        Ok(())
    }

    /// The capture timestamp includes time spent in the driver's forwarding
    /// queue. Intentional deadline/MTU drops return zero; queue pressure is retryable.
    pub fn send_to(
        &self,
        payload: &[u8],
        target: SocketAddr,
        captured_at: Instant,
    ) -> Result<usize> {
        self.check_alive()?;
        let config = &self.runtime.shared.config;
        let now = Instant::now();
        let expires = captured_at
            .checked_add(Duration::from_millis(config.deadline_ms as u64))
            .context("GPUX deadline overflow")?;
        if now >= expires || payload.len() + INNER_HEADER_SIZE > max_data_payload(config) {
            return Ok(0);
        }
        let mut queues = lock(&self.runtime.shared.queues);
        if queues.data.len() >= config.queue_limit {
            return Err(would_block("GPUX data queue is full"));
        }
        let existing = queues
            .sessions
            .get(&self.id)
            .and_then(|session| session.flows.get(&target))
            .copied();
        let flow_id = if let Some(flow) = existing
            .filter(|flow| now.saturating_duration_since(flow.last_activity) < FLOW_IDLE_REFRESH)
        {
            queues
                .sessions
                .get_mut(&self.id)
                .unwrap()
                .flows
                .get_mut(&target)
                .unwrap()
                .last_activity = now;
            flow.id
        } else {
            if existing.is_none() && queues.flow_count >= config.queue_limit.saturating_mul(4) {
                return Err(would_block("GPUX flow limit reached"));
            }
            if queues.flow_count + queues.retired_flows.len()
                >= config.queue_limit.saturating_mul(8)
            {
                return Err(would_block("GPUX flow cleanup queue is full"));
            }
            let flow_id = queues.next_flow;
            queues.next_flow = flow_id.checked_add(1).context("GPUX flow IDs exhausted")?;
            queues
                .sessions
                .get_mut(&self.id)
                .context("GPUX session closed")?
                .flows
                .insert(
                    target,
                    RegisteredFlow {
                        id: flow_id,
                        last_activity: now,
                    },
                );
            if let Some(old) = existing {
                queues.data.retain(|datagram| datagram.flow_id != old.id);
                queues.retired_flows.insert(old.id);
            } else {
                queues.flow_count += 1;
            }
            queues.revision = queues.revision.wrapping_add(1);
            flow_id
        };
        queues.data.push_back(QueuedDatagram {
            flow_id,
            payload: payload.to_vec(),
            expires,
            queued_at: now,
        });
        drop(queues);
        self.runtime.shared.wake.notify_one();
        Ok(payload.len())
    }

    pub fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.check_alive()?;
        let mut received = lock(&self.state.received);
        while let Some(datagram) = received.pop_front() {
            if datagram
                .expires
                .is_some_and(|expires| Instant::now() >= expires)
            {
                continue;
            }
            ensure!(
                datagram.payload.len() <= buffer.len(),
                "GPUX UDP receive buffer is too small"
            );
            buffer[..datagram.payload.len()].copy_from_slice(&datagram.payload);
            return Ok((datagram.payload.len(), datagram.target));
        }
        Err(would_block("GPUX receive queue is empty"))
    }
}

impl Drop for GpuxSession {
    fn drop(&mut self) {
        let mut queues = lock(&self.runtime.shared.queues);
        if let Some(registration) = queues.sessions.remove(&self.id) {
            let flows: BTreeSet<_> = registration
                .flows
                .into_values()
                .map(|flow| flow.id)
                .collect();
            queues.flow_count = queues.flow_count.saturating_sub(flows.len());
            queues.retired_flows.extend(flows.iter().copied());
            queues
                .data
                .retain(|datagram| !flows.contains(&datagram.flow_id));
            queues.revision = queues.revision.wrapping_add(1);
        }
        drop(queues);
        self.runtime.shared.wake.notify_one();
    }
}

fn max_data_payload(config: &GpuxConfig) -> usize {
    (config.mtu_payload as usize).saturating_sub(
        protocol::OUTER_HEADER_SIZE
            + protocol::AUTH_TAG_SIZE
            + if config.fec_uplink > 0 {
                FEC_OVERHEAD
            } else {
                0
            },
    )
}

fn resolve(config: &GpuxConfig) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = config.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, config.port)]);
    }
    let host = config.host.clone();
    let port = config.port;
    let (tx, rx) = mpsc::sync_channel(1);
    // Windows DNS is not cancellable. This bounded resolver owns no tunnel,
    // driver or flow state and therefore cannot delay driver shutdown.
    thread::spawn(move || {
        let _ = tx.send(
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.collect::<Vec<_>>()),
        );
    });
    let addresses = rx
        .recv_timeout(HANDSHAKE_TIMEOUT)
        .context("GPUX DNS lookup timed out")??;
    ensure!(
        !addresses.is_empty(),
        "GPUX hostname resolved to no addresses"
    );
    Ok(addresses)
}

#[derive(Default)]
struct ReceiveWindow {
    maximum: Option<u64>,
    sequences: BTreeSet<u64>,
}

impl ReceiveWindow {
    fn accept(&mut self, sequence: u64) -> bool {
        if let Some(maximum) = self.maximum {
            if sequence <= maximum
                && (maximum - sequence >= REPLAY_WINDOW || self.sequences.contains(&sequence))
            {
                return false;
            }
        }
        let maximum = self.maximum.map_or(sequence, |old| old.max(sequence));
        self.maximum = Some(maximum);
        self.sequences.insert(sequence);
        while self
            .sequences
            .first()
            .is_some_and(|old| maximum - old >= REPLAY_WINDOW)
        {
            self.sequences.pop_first();
        }
        true
    }

    fn ack(&self) -> (u64, u64) {
        let Some(maximum) = self.maximum else {
            return (0, 0);
        };
        let mut bitmap = 0;
        for bit in 0..64 {
            if bit > maximum {
                break;
            }
            if self.sequences.contains(&(maximum - bit)) {
                bitmap |= 1 << bit;
            }
        }
        (maximum, bitmap)
    }
}

struct WorkerFlow {
    target: SocketAddr,
    session: Arc<SessionState>,
    last_down_sequence: Option<u64>,
    opened: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Control {
    Hello,
    Open(u32),
    Close(u32),
}

struct PendingControl {
    kind: Control,
    due: Instant,
    attempts: u8,
    sequences: Vec<u64>,
}

struct DecodeGroup {
    first_seen: Instant,
    sources: Vec<FecSource>,
    parity: Option<FecParity>,
    expected_sources: u8,
}

struct EncodeGroup {
    id: u32,
    first_sent: Instant,
    sources: Vec<FecSource>,
}

struct Worker {
    socket: UdpSocket,
    shared: Arc<Shared>,
    connection_id: u64,
    key: Option<AeadKey>,
    started: Option<mpsc::SyncSender<std::result::Result<(), String>>>,
    handshake_until: Instant,
    authenticated: bool,
    origin: Instant,
    sequence: u64,
    registry_revision: u64,
    flows: HashMap<u32, WorkerFlow>,
    controls: Vec<PendingControl>,
    sent: BTreeMap<u64, Instant>,
    received: ReceiveWindow,
    ack_pending: usize,
    last_ack: Instant,
    next_data_send: Instant,
    fec_encode: Option<EncodeGroup>,
    next_fec_group: u32,
    fec_decode: BTreeMap<u32, DecodeGroup>,
    completed_fec: BTreeSet<u32>,
    completed_fec_order: VecDeque<u32>,
    latest_rtt: Option<Duration>,
}

impl Worker {
    fn new(
        socket: UdpSocket,
        shared: Arc<Shared>,
        connection_id: u64,
        key: Option<AeadKey>,
        started: mpsc::SyncSender<std::result::Result<(), String>>,
        timeout: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            socket,
            shared,
            connection_id,
            key,
            started: Some(started),
            handshake_until: now + timeout,
            authenticated: false,
            origin: now,
            sequence: 0,
            registry_revision: 0,
            flows: HashMap::new(),
            controls: vec![PendingControl {
                kind: Control::Hello,
                due: now,
                attempts: 0,
                sequences: Vec::new(),
            }],
            sent: BTreeMap::new(),
            received: ReceiveWindow::default(),
            ack_pending: 0,
            last_ack: now,
            next_data_send: now,
            fec_encode: None,
            next_fec_group: 1,
            fec_decode: BTreeMap::new(),
            completed_fec: BTreeSet::new(),
            completed_fec_order: VecDeque::new(),
            latest_rtt: None,
        }
    }

    fn now_us(&self) -> u64 {
        self.origin.elapsed().as_micros().min(u64::MAX as u128) as u64
    }

    fn run(&mut self) -> Result<()> {
        let mut buffer = [0; 65535];
        while !self.shared.stopping.load(Ordering::Acquire) {
            if !self.authenticated && Instant::now() >= self.handshake_until {
                bail!("GPUX CHLO was not acknowledged; check server, token and encryption");
            }
            self.sync_flows();
            self.send_due_controls()?;
            // Bound each receive turn so busy peers cannot starve outgoing data,
            // control cleanup or shutdown. The connected socket rejects strangers.
            for _ in 0..64 {
                match self.socket.recv(&mut buffer) {
                    Ok(size) => {
                        if let Ok(packet) = protocol::decode(&buffer[..size], self.key.as_ref(), 1)
                        {
                            self.handle_packet(packet)?;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error).context("GPUX receive"),
                }
            }
            if self.authenticated {
                self.send_data()?;
                self.flush_fec(false)?;
                if self.ack_pending > 0
                    && (self.ack_pending >= 8 || self.last_ack.elapsed() >= ACK_DELAY)
                {
                    let _ = self.transmit(Packet {
                        packet_type: PacketType::Ack,
                        ..Packet::default()
                    })?;
                }
            }
            self.flush_received_fec();
            let queues = lock(&self.shared.queues);
            let wait = self.next_wait(&queues);
            let _ = self
                .shared
                .wake
                .wait_timeout(queues, wait)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        // Close messages are emitted by this same worker even if the data queue
        // was full. Shutdown does not drain obsolete application datagrams.
        let flow_ids: Vec<_> = self.flows.keys().copied().collect();
        for flow_id in flow_ids {
            let _ = self.transmit(Packet {
                packet_type: PacketType::FlowClose,
                payload: protocol::encode_flow_close(flow_id, 0),
                ..Packet::default()
            });
        }
        let _ = self.transmit(Packet {
            packet_type: PacketType::Close,
            ..Packet::default()
        });
        Ok(())
    }

    fn next_wait(&self, queues: &QueueState) -> Duration {
        if queues.revision != self.registry_revision {
            return Duration::ZERO;
        }
        if let Some(first) = queues.data.front() {
            let batch_due =
                first.queued_at + Duration::from_micros(self.shared.config.batch_window_us as u64);
            let due = batch_due.max(self.next_data_send).min(first.expires);
            return due
                .saturating_duration_since(Instant::now())
                .min(POLL_INTERVAL);
        }
        POLL_INTERVAL
    }

    fn sync_flows(&mut self) {
        let queues = lock(&self.shared.queues);
        if queues.revision == self.registry_revision {
            return;
        }
        self.registry_revision = queues.revision;
        let desired: HashMap<u32, _> = queues
            .sessions
            .values()
            .filter(|registration| lock(&registration.state.failure).is_none())
            .flat_map(|registration| {
                registration
                    .flows
                    .iter()
                    .map(|(&target, flow)| (flow.id, (target, Arc::clone(&registration.state))))
            })
            .collect();
        let retired: Vec<_> = queues.retired_flows.iter().copied().collect();
        drop(queues);
        let removed: Vec<_> = self
            .flows
            .keys()
            .filter(|flow_id| !desired.contains_key(flow_id))
            .copied()
            .collect();
        for flow_id in removed {
            self.flows.remove(&flow_id);
            self.controls
                .retain(|control| control.kind != Control::Open(flow_id));
            if !self
                .controls
                .iter()
                .any(|control| control.kind == Control::Close(flow_id))
            {
                self.controls.push(PendingControl {
                    kind: Control::Close(flow_id),
                    due: Instant::now(),
                    attempts: 0,
                    sequences: Vec::new(),
                });
            }
        }
        for flow_id in retired {
            if !self
                .controls
                .iter()
                .any(|control| control.kind == Control::Close(flow_id))
            {
                self.controls.push(PendingControl {
                    kind: Control::Close(flow_id),
                    due: Instant::now(),
                    attempts: 0,
                    sequences: Vec::new(),
                });
            }
        }
        for (flow_id, (target, session)) in desired {
            if let std::collections::hash_map::Entry::Vacant(entry) = self.flows.entry(flow_id) {
                entry.insert(WorkerFlow {
                    target,
                    session,
                    last_down_sequence: None,
                    opened: false,
                });
                self.controls.push(PendingControl {
                    kind: Control::Open(flow_id),
                    due: Instant::now(),
                    attempts: 0,
                    sequences: Vec::new(),
                });
            }
        }
    }

    fn send_due_controls(&mut self) -> Result<()> {
        let mut index = 0;
        while index < self.controls.len() {
            if self.controls[index].due > Instant::now() {
                index += 1;
                continue;
            }
            let kind = self.controls[index].kind;
            if self.controls[index].attempts >= 5 && kind != Control::Hello {
                if let Control::Open(flow_id) = kind {
                    self.fail_flow(flow_id, "GPUX server did not acknowledge FLOW_OPEN".into());
                    self.controls.push(PendingControl {
                        kind: Control::Close(flow_id),
                        due: Instant::now(),
                        attempts: 0,
                        sequences: Vec::new(),
                    });
                }
                if let Control::Close(flow_id) = kind {
                    lock(&self.shared.queues).retired_flows.remove(&flow_id);
                }
                self.controls.remove(index);
                continue;
            }
            let (packet_type, payload) = match kind {
                Control::Hello => (
                    PacketType::Chlo,
                    protocol::encode_chlo(
                        self.connection_id,
                        &self.shared.config.token,
                        self.now_us(),
                    )?,
                ),
                Control::Open(flow_id) => {
                    let Some(flow) = self.flows.get(&flow_id) else {
                        self.controls.remove(index);
                        continue;
                    };
                    (
                        PacketType::FlowOpen,
                        protocol::encode_flow_open(
                            flow_id,
                            flow.target,
                            self.now_us(),
                            "opaque_fps",
                        )?,
                    )
                }
                Control::Close(flow_id) => (
                    PacketType::FlowClose,
                    protocol::encode_flow_close(flow_id, 0),
                ),
            };
            if let Some(sequence) = self.transmit(Packet {
                packet_type,
                payload,
                ..Packet::default()
            })? {
                self.controls[index].sequences.push(sequence);
                self.controls[index].attempts += 1;
                self.controls[index].due = Instant::now() + CONTROL_RETRY;
            } else {
                self.controls[index].due = Instant::now() + POLL_INTERVAL;
            }
            index += 1;
        }
        Ok(())
    }

    /// A newly allocated sequence is never reused, including WouldBlock sends.
    /// DATA is never retransmitted; ACKs serve control reliability and RTT only.
    fn transmit(&mut self, mut packet: Packet) -> Result<Option<u64>> {
        ensure!(
            self.sequence <= protocol::MAX_PACKET_SEQ,
            "GPUX packet sequence exhausted; restart tunnel before nonce reuse"
        );
        let sequence = self.sequence;
        self.sequence += 1;
        packet.connection_id = self.connection_id;
        packet.packet_seq = sequence;
        packet.send_time_us = self.now_us() as u32;
        (packet.ack_base, packet.ack_bitmap) = self.received.ack();
        let wire = protocol::encode(&packet, self.key.as_ref(), 0)?;
        ensure!(
            wire.len() <= self.shared.config.mtu_payload as usize,
            "GPUX packet exceeds configured MTU"
        );
        match self.socket.send(&wire) {
            Ok(size) => ensure!(size == wire.len(), "Partial GPUX UDP send"),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error).context("GPUX send"),
        }
        self.sent.insert(sequence, Instant::now());
        while self.sent.len() > 2048 {
            self.sent.pop_first();
        }
        self.ack_pending = 0;
        self.last_ack = Instant::now();
        Ok(Some(sequence))
    }

    fn send_data(&mut self) -> Result<()> {
        let now = Instant::now();
        let mut queues = lock(&self.shared.queues);
        // A forwarding worker may register another destination between this
        // iteration's reconciliation and batch formation. Reconcile before
        // touching its data, including pruning, while holding this same mutex.
        if queues.revision != self.registry_revision {
            return Ok(());
        }
        queues.data.retain(|datagram| {
            datagram.expires > now && self.flows.contains_key(&datagram.flow_id)
        });
        let Some(first) = queues.data.front() else {
            return Ok(());
        };
        if now < self.next_data_send
            || now
                < first.queued_at + Duration::from_micros(self.shared.config.batch_window_us as u64)
        {
            return Ok(());
        }
        let max_payload = max_data_payload(&self.shared.config);
        let mut batch = Vec::new();
        let mut used = 0;
        // FIFO preserves each flow's capture order; a pending FLOW_OPEN cannot
        // be bypassed by its own data if the OS send buffer is temporarily full.
        while let Some(first) = queues.data.front() {
            if !self
                .flows
                .get(&first.flow_id)
                .is_some_and(|flow| flow.opened)
                || used + INNER_HEADER_SIZE + first.payload.len() > max_payload
            {
                break;
            }
            used += INNER_HEADER_SIZE + first.payload.len();
            batch.push(queues.data.pop_front().unwrap());
        }
        drop(queues);
        let mut payload = Vec::with_capacity(used);
        for datagram in &batch {
            let remaining = datagram.expires.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                continue;
            }
            payload.extend(protocol::encode_inner(
                datagram.flow_id,
                0,
                self.shared.config.deadline_ms.min(255) as u8,
                Some(remaining.as_micros().min(u32::MAX as u128) as u32),
                &datagram.payload,
            )?);
        }
        if payload.is_empty() {
            return Ok(());
        }
        let (group_id, fec_k, fec_n, fec_index) = if self.shared.config.fec_uplink > 0 {
            if self.fec_encode.is_none() {
                let id = self.next_fec_group;
                self.next_fec_group = id.wrapping_add(1).max(1);
                self.fec_encode = Some(EncodeGroup {
                    id,
                    first_sent: Instant::now(),
                    sources: Vec::new(),
                });
            }
            let group = self.fec_encode.as_ref().unwrap();
            (group.id, FEC_K, FEC_K + 1, group.sources.len() as u8)
        } else {
            (0, 0, 0, 0)
        };
        let result = self.transmit(Packet {
            packet_type: PacketType::Data,
            fec_group_id: group_id,
            fec_k,
            fec_n,
            fec_index,
            payload: payload.clone(),
            ..Packet::default()
        })?;
        if let Some(sequence) = result {
            self.next_data_send = Instant::now()
                + Duration::from_micros(self.shared.config.pacing_interval_us as u64);
            if let Some(group) = self.fec_encode.as_mut() {
                group.sources.push(FecSource {
                    fec_index,
                    packet_seq: sequence,
                    payload,
                });
                if group.sources.len() >= FEC_K as usize {
                    self.flush_fec(true)?;
                }
            }
        } else {
            let mut queues = lock(&self.shared.queues);
            // Reserve capacity for requeue without exceeding the configured bound.
            while let Some(datagram) = batch.pop() {
                if queues.data.len() < self.shared.config.queue_limit {
                    queues.data.push_front(datagram);
                }
            }
        }
        Ok(())
    }

    fn flush_fec(&mut self, force: bool) -> Result<()> {
        let Some(group) = self.fec_encode.as_ref() else {
            return Ok(());
        };
        if group.sources.is_empty()
            || (!force
                && group.first_sent.elapsed()
                    < Duration::from_micros(self.shared.config.fec_group_max_us as u64))
        {
            return Ok(());
        }
        let group = self.fec_encode.take().unwrap();
        let k = group.sources.len() as u8;
        let payload = protocol::encode_fec(&group.sources)?;
        let _ = self.transmit(Packet {
            packet_type: PacketType::Parity,
            fec_group_id: group.id,
            fec_k: k,
            fec_n: k + 1,
            fec_index: k,
            payload,
            ..Packet::default()
        })?;
        Ok(())
    }

    fn observe_ack(&mut self, base: u64, bitmap: u64) {
        if bitmap == 0 {
            return;
        }
        let acknowledged = |sequence: u64| {
            sequence <= base && base - sequence < 64 && bitmap & (1 << (base - sequence)) != 0
        };
        let sequences: Vec<_> = self
            .sent
            .keys()
            .copied()
            .filter(|sequence| acknowledged(*sequence))
            .collect();
        for sequence in sequences {
            if let Some(sent_at) = self.sent.remove(&sequence) {
                self.latest_rtt = Some(sent_at.elapsed());
            }
        }
        let mut hello_acked = false;
        let mut opened = Vec::new();
        let mut closed = Vec::new();
        self.controls.retain(|control| {
            let acked = control.sequences.iter().copied().any(&acknowledged);
            if acked && control.kind == Control::Hello {
                hello_acked = true;
            }
            if acked {
                if let Control::Open(flow_id) = control.kind {
                    opened.push(flow_id);
                }
                if let Control::Close(flow_id) = control.kind {
                    closed.push(flow_id);
                }
            }
            !acked
        });
        for flow_id in opened {
            if let Some(flow) = self.flows.get_mut(&flow_id) {
                flow.opened = true;
            }
        }
        if !closed.is_empty() {
            let mut queues = lock(&self.shared.queues);
            for flow_id in closed {
                queues.retired_flows.remove(&flow_id);
            }
        }
        if hello_acked && !self.authenticated {
            self.authenticated = true;
            if let Some(started) = self.started.take() {
                let _ = started.send(Ok(()));
            }
        }
    }

    fn handle_packet(&mut self, packet: Packet) -> Result<()> {
        if packet.connection_id != self.connection_id || packet.path_id != 0 {
            return Ok(());
        }
        self.observe_ack(packet.ack_base, packet.ack_bitmap);
        if !self.received.accept(packet.packet_seq) {
            return Ok(());
        }
        if packet.packet_type != PacketType::Ack {
            self.ack_pending += 1;
        }
        match packet.packet_type {
            PacketType::Data => {
                if packet.fec_group_id == 0 {
                    self.deliver_data(packet.packet_seq, &packet.payload, Duration::ZERO);
                } else {
                    self.store_fec(&packet, false)?;
                }
            }
            PacketType::Parity => self.store_fec(&packet, true)?,
            PacketType::FlowClose => {
                if let Ok((flow_id, reason)) = protocol::decode_flow_close(&packet.payload) {
                    self.fail_flow(
                        flow_id,
                        format!("GPUX server closed flow {flow_id} (reason {reason})"),
                    );
                    self.controls
                        .retain(|control| control.kind != Control::Open(flow_id));
                }
            }
            PacketType::Close => bail!("GPUX server closed tunnel"),
            PacketType::Ack | PacketType::Chlo | PacketType::FlowOpen => {}
        }
        Ok(())
    }

    fn fail_flow(&mut self, flow_id: u32, message: String) {
        if let Some(flow) = self.flows.remove(&flow_id) {
            *lock(&flow.session.failure) = Some(message);
        }
    }

    fn deliver_data(&mut self, sequence: u64, payload: &[u8], elapsed: Duration) {
        let Ok(datagrams) = protocol::decode_inners(payload) else {
            return;
        };
        let now = Instant::now();
        for datagram in datagrams {
            if datagram.direction != 1 {
                continue;
            }
            let Some(flow) = self.flows.get_mut(&datagram.flow_id) else {
                continue;
            };
            // Delayed FEC recovery cannot deliver an older packet after a newer
            // packet has already reached this flow's application socket.
            if flow.last_down_sequence.is_some_and(|last| sequence < last) {
                continue;
            }
            let expires = if let Some(ttl) = datagram.ttl_us {
                let remaining = Duration::from_micros(ttl as u64).saturating_sub(elapsed);
                if remaining.is_zero() {
                    continue;
                }
                Some(now + remaining)
            } else {
                None
            };
            flow.last_down_sequence = Some(sequence);
            let mut received = lock(&flow.session.received);
            if received.len() < self.shared.config.queue_limit {
                received.push_back(ReceivedDatagram {
                    target: flow.target,
                    payload: datagram.payload,
                    expires,
                });
            }
        }
    }

    fn store_fec(&mut self, packet: &Packet, parity: bool) -> Result<()> {
        // Four intact originals can complete a group before its redundant
        // parity arrives. Remember retired IDs so that late parity cannot
        // recreate an empty group and block newer, complete groups.
        if self.completed_fec.contains(&packet.fec_group_id) {
            return Ok(());
        }
        if packet.fec_group_id == 0
            || packet.fec_k == 0
            || packet.fec_n != packet.fec_k.saturating_add(1)
        {
            return Ok(());
        }
        if (!parity && packet.fec_index >= packet.fec_k)
            || (parity && packet.fec_index != packet.fec_k)
        {
            return Ok(());
        }
        let decoded_parity = if parity {
            let Ok(decoded) = protocol::decode_fec(&packet.payload) else {
                return Ok(());
            };
            Some(decoded)
        } else {
            None
        };
        let group = self
            .fec_decode
            .entry(packet.fec_group_id)
            .or_insert_with(|| DecodeGroup {
                first_seen: Instant::now(),
                sources: Vec::new(),
                parity: None,
                expected_sources: packet.fec_k,
            });
        if parity {
            if let Some(decoded) = decoded_parity.as_ref() {
                group.expected_sources = decoded.sources.len() as u8;
            }
            group.parity = decoded_parity;
        } else if !group
            .sources
            .iter()
            .any(|source| source.fec_index == packet.fec_index)
        {
            group.sources.push(FecSource {
                fec_index: packet.fec_index,
                packet_seq: packet.packet_seq,
                payload: packet.payload.clone(),
            });
        }
        let recovered = group
            .parity
            .as_ref()
            .and_then(|parity| protocol::recover_fec(parity, &group.sources).ok().flatten());
        if let Some(recovered) = recovered {
            if self.received.accept(recovered.packet_seq) {
                self.ack_pending += 1;
                group.sources.push(recovered);
            }
        }
        while self.fec_decode.len() > 64 {
            if let Some((group_id, group)) = self.fec_decode.pop_first() {
                self.deliver_fec_group(group_id, group);
            }
        }
        Ok(())
    }

    fn flush_received_fec(&mut self) {
        while let Some((_, group)) = self.fec_decode.first_key_value() {
            let complete = group.sources.len() >= group.expected_sources as usize;
            // Keep later originals briefly while a missing earlier source can
            // still be reconstructed. Retain half their TTL for delivery and
            // forwarding; missing parity cannot stall a flow indefinitely.
            let minimum_ttl = group
                .sources
                .iter()
                .filter_map(|source| protocol::decode_inners(&source.payload).ok())
                .flatten()
                .filter_map(|inner| inner.ttl_us)
                .min()
                .unwrap_or(self.shared.config.deadline_ms.saturating_mul(1000));
            let hold = Duration::from_micros(
                (minimum_ttl as u64 / 2).min(
                    (self.shared.config.fec_group_max_us as u64)
                        .saturating_mul(4)
                        .max(25_000),
                ),
            );
            if !complete && group.first_seen.elapsed() < hold {
                break;
            }
            let (group_id, group) = self.fec_decode.pop_first().unwrap();
            self.deliver_fec_group(group_id, group);
        }
    }

    fn deliver_fec_group(&mut self, group_id: u32, mut group: DecodeGroup) {
        if self.completed_fec.insert(group_id) {
            self.completed_fec_order.push_back(group_id);
            while self.completed_fec_order.len() > REPLAY_WINDOW as usize {
                let retired = self.completed_fec_order.pop_front().unwrap();
                self.completed_fec.remove(&retired);
            }
        }
        group
            .sources
            .sort_unstable_by_key(|source| source.packet_seq);
        let elapsed = group.first_seen.elapsed();
        for source in group.sources {
            self.deliver_data(source.packet_seq, &source.payload, elapsed);
        }
    }
}
