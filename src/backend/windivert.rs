//! Process-selective WinDivert backend. TCP is reflected into a local stream relay;
//! UDP uses a shared upstream abstraction and replies are injected into the original socket.
//! References: https://reqrypt.org/windivert-doc.html and upstream streamdump example.
mod driver;
mod owner;
mod packet;
mod state;

use crate::{
    backend::RunningBackend,
    config::{is_private_or_local, AppConfig},
    metrics::{self, Metrics},
    socks5,
    upstream::UdpUpstream,
};
use anyhow::{Context, Result};
use driver::{Address, Driver};
use packet::{Flow, Packet};
use state::{normalize, Mapping, Nat};
use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_UDP_SESSIONS: usize = 256;
const UDP_IDLE: Duration = Duration::from_secs(60);

struct Backend {
    driver: Arc<Driver>,
    metrics: Arc<Metrics>,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl RunningBackend for Backend {
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.driver.shutdown_receive();
        for worker in self.workers.drain(..) {
            join_worker(worker, &self.metrics, &self.stop);
        }
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start(
    config: Arc<AppConfig>,
    metrics: Arc<Metrics>,
    stop: Arc<AtomicBool>,
    upstream: Arc<UdpUpstream>,
) -> Result<Box<dyn RunningBackend>> {
    owner::preflight().context("WinDivert requires readable IPv4/IPv6 process owner tables")?;
    let ipv4 = TcpListener::bind("0.0.0.0:0").context("bind WinDivert IPv4 relay")?;
    let ipv6 = TcpListener::bind("[::]:0")
        .context("bind WinDivert IPv6 relay; Windows IPv6 support is required")?;
    ipv4.set_nonblocking(true)?;
    ipv6.set_nonblocking(true)?;
    let ports = [ipv4.local_addr()?.port(), ipv6.local_addr()?.port()];
    let mut proxy_addresses: HashSet<_> = upstream
        .endpoint_addresses()?
        .into_iter()
        .map(normalize)
        .collect();
    if config.needs_socks5() {
        proxy_addresses.extend(
            socks5::resolve_proxy(&config.socks5)?
                .into_iter()
                .map(normalize),
        );
    }
    // Block unsolicited external access to the wildcard relay listeners. Reflected
    // packets injected by this handle are not captured again at its priority.
    // IP fragments cannot be attributed reliably without reassembly and pass through.
    let filter = format!("(outbound and !loopback and !impostor and !fragment and (tcp or udp)) or (inbound and tcp and (tcp.DstPort == {} or tcp.DstPort == {}))", ports[0], ports[1]);
    let driver = Driver::open(&filter)?;
    let nat = Arc::new(Mutex::new(Nat::new()));
    let mut backend = Backend {
        driver: driver.clone(),
        metrics: metrics.clone(),
        stop: stop.clone(),
        workers: Vec::new(),
    };
    for listener in [ipv4, ipv6] {
        let config = config.clone();
        let metrics = metrics.clone();
        let stop = stop.clone();
        let nat = nat.clone();
        let failure_metrics = metrics.clone();
        let failure_stop = stop.clone();
        backend.workers.push(
            thread::Builder::new()
                .name("windivert-tcp-listener".into())
                .spawn(move || {
                    supervise(
                        || listen(listener, config, metrics, stop, nat),
                        &failure_metrics,
                        &failure_stop,
                    )
                })?,
        );
    }
    let failure_metrics = metrics.clone();
    let failure_stop = stop.clone();
    let udp_runtime = Arc::new(UdpRuntime {
        driver,
        config,
        upstream,
        metrics,
        stop,
        own_sockets: Arc::new(Mutex::new(HashSet::new())),
    });
    backend.workers.push(
        thread::Builder::new()
            .name("windivert-network".into())
            .spawn(move || {
                supervise(
                    || capture(udp_runtime, nat, ports, proxy_addresses),
                    &failure_metrics,
                    &failure_stop,
                );
            })?,
    );
    Ok(Box::new(backend))
}

fn report(context: &str, error: impl std::fmt::Display) {
    metrics::status("warning", &format!("WinDivert {context}: {error}"));
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn join_worker(worker: JoinHandle<()>, metrics: &Metrics, stop: &AtomicBool) {
    if worker.join().is_err() {
        metrics.fail("WinDivert worker panicked");
        stop.store(true, Ordering::Release);
    }
}

fn supervise(operation: impl FnOnce(), metrics: &Metrics, stop: &AtomicBool) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).is_err() {
        // The main loop observes stop and releases interception immediately even
        // if the capture/listener thread itself cannot report normal completion.
        metrics.fail("WinDivert capture/listener worker panicked");
        stop.store(true, Ordering::Release);
    }
}

fn listen(
    listener: TcpListener,
    config: Arc<AppConfig>,
    metrics: Arc<Metrics>,
    stop: Arc<AtomicBool>,
    nat: Arc<Mutex<Nat>>,
) {
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let mut reaped = Instant::now();
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let mapping = stream
                    .local_addr()
                    .ok()
                    .and_then(|local| lock(&nat).accept(normalize(local), normalize(peer)));
                if let Some(mapping) = mapping {
                    let config = config.clone();
                    let metrics = metrics.clone();
                    let stop = stop.clone();
                    let worker_nat = nat.clone();
                    match thread::Builder::new()
                        .name("windivert-tcp".into())
                        .spawn(move || {
                            if let Err(error) = relay_tcp(stream, mapping, &config, &metrics, &stop)
                            {
                                if !stop.load(Ordering::Acquire) {
                                    report("TCP relay", error);
                                }
                            }
                            lock(&worker_nat).finish(mapping);
                        }) {
                        Ok(worker) => workers.push(worker),
                        Err(error) => {
                            lock(&nat).finish(mapping);
                            report("start TCP relay", error);
                        }
                    }
                }
                // Unmapped direct connections are dropped when stream leaves scope.
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(error) => {
                metrics.fail(&format!("WinDivert listener failed: {error}"));
                stop.store(true, Ordering::Release);
                break;
            }
        }
        if reaped.elapsed() >= Duration::from_secs(1) {
            let mut index = 0;
            while index < workers.len() {
                if workers[index].is_finished() {
                    join_worker(workers.swap_remove(index), &metrics, &stop);
                } else {
                    index += 1;
                }
            }
            lock(&nat).reap();
            reaped = Instant::now();
        }
    }
    for worker in workers {
        join_worker(worker, &metrics, &stop);
    }
}

fn relay_tcp(
    mut local: TcpStream,
    mapping: Mapping,
    config: &AppConfig,
    metrics: &Metrics,
    stop: &AtomicBool,
) -> Result<()> {
    let mut remote = socks5::connect(&config.socks5, mapping.flow.remote)?;
    for stream in [&local, &remote] {
        stream.set_read_timeout(Some(Duration::from_millis(250)))?;
        stream.set_write_timeout(Some(Duration::from_millis(250)))?;
        stream.set_nodelay(true)?;
    }
    let mut local_read = local.try_clone()?;
    let mut remote_write = remote.try_clone()?;
    let failed = AtomicBool::new(false);
    thread::scope(|scope| {
        let upload = scope.spawn(|| {
            transfer(
                &mut local_read,
                &mut remote_write,
                &metrics.tcp_up,
                stop,
                &failed,
            )
        });
        let download = transfer(&mut remote, &mut local, &metrics.tcp_down, stop, &failed);
        let upload = upload
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("TCP upload worker panicked")));
        download.and(upload)
    })?;
    Ok(())
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn transfer(
    input: &mut TcpStream,
    output: &mut TcpStream,
    counter: &std::sync::atomic::AtomicU64,
    stop: &AtomicBool,
    failed: &AtomicBool,
) -> io::Result<()> {
    let result = (|| {
        let mut buffer = [0; 32768];
        while !stop.load(Ordering::Acquire) && !failed.load(Ordering::Acquire) {
            let count = match input.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => count,
                Err(error) if retryable(&error) => continue,
                Err(error) => return Err(error),
            };
            let mut written = 0;
            let started = Instant::now();
            while written < count {
                if stop.load(Ordering::Acquire) || failed.load(Ordering::Acquire) {
                    return Ok(());
                }
                match output.write(&buffer[written..count]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(size) => {
                        written += size;
                        counter.fetch_add(size as u64, Ordering::Relaxed);
                    }
                    Err(error)
                        if retryable(&error) && started.elapsed() < Duration::from_secs(30) =>
                    {
                        continue
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    })();
    if result.is_err() {
        failed.store(true, Ordering::Release);
    }
    // Preserve TCP half-close: one EOF need not discard the other direction's reply.
    let _ = output.shutdown(Shutdown::Write);
    result
}

struct Datagram {
    captured_at: Instant,
    target: SocketAddr,
    payload: Vec<u8>,
    address: Address,
}
struct UdpSession {
    pid: u32,
    sender: SyncSender<Datagram>,
    worker: JoinHandle<()>,
}
struct OwnUdpSocket {
    sockets: Arc<Mutex<HashSet<SocketAddr>>>,
    address: SocketAddr,
}
impl OwnUdpSocket {
    fn register(sockets: Arc<Mutex<HashSet<SocketAddr>>>, address: SocketAddr) -> Self {
        lock(&sockets).insert(address);
        Self { sockets, address }
    }
}
impl Drop for OwnUdpSocket {
    fn drop(&mut self) {
        lock(&self.sockets).remove(&self.address);
    }
}
struct UdpRuntime {
    driver: Arc<Driver>,
    config: Arc<AppConfig>,
    upstream: Arc<UdpUpstream>,
    metrics: Arc<Metrics>,
    stop: Arc<AtomicBool>,
    own_sockets: Arc<Mutex<HashSet<SocketAddr>>>,
}

fn selected(config: &AppConfig, flow: Flow, tcp: bool) -> Option<u32> {
    let pid = owner::process(flow, tcp).ok().flatten()?;
    if pid == std::process::id() || crate::backend::process::is_local_proxy(pid) {
        return None;
    }
    let path = owner::path(pid).ok()?;
    config.matches_process(&path, tcp).then_some(pid)
}

fn capture(
    udp_runtime: Arc<UdpRuntime>,
    nat: Arc<Mutex<Nat>>,
    ports: [u16; 2],
    proxy_addresses: HashSet<SocketAddr>,
) {
    let driver = udp_runtime.driver.clone();
    let config = udp_runtime.config.clone();
    let metrics = udp_runtime.metrics.clone();
    let stop = udp_runtime.stop.clone();
    let mut buffer = vec![0u8; 65575];
    let mut sessions: HashMap<SocketAddr, UdpSession> = HashMap::new();
    let mut retiring: Vec<JoinHandle<()>> = Vec::new();
    let mut reaped = Instant::now();
    loop {
        let mut address = Address::default();
        let length = match driver.recv(&mut buffer, &mut address) {
            Ok(length) => length,
            Err(error) => {
                if !stop.load(Ordering::Acquire) {
                    metrics.fail(&format!("WinDivert receive stopped: {error}"));
                    stop.store(true, Ordering::Release);
                }
                break;
            }
        };
        let captured_at = Instant::now();
        let bytes = &mut buffer[..length];
        if stop.load(Ordering::Acquire) {
            // ShutdownReceive stops new capture. Drain already captured packets.
            let _ = driver.send(bytes, &address);
            continue;
        }
        let Some(packet) = Packet::parse(bytes) else {
            let _ = driver.send(bytes, &address);
            continue;
        };
        if !address.outbound() {
            continue;
        } // Unsolicited network access to the relay.
        if packet.protocol == 6 {
            let reverse = lock(&nat).reverse(packet.flow.local, packet.flow.remote);
            if let Some(mapping) = reverse {
                packet.reflect(bytes, mapping.flow.remote.port(), mapping.flow.local.port());
                address.inbound();
                if let Err(error) = driver.send_modified(bytes, &mut address) {
                    report("TCP reply injection", error);
                }
                continue;
            }
            let mapping = if packet.initial_syn() {
                // Ownership and ISN must be rechecked even if this tuple existed.
                if bypass(packet.flow.remote, &proxy_addresses)
                    || selected(&config, packet.flow, true).is_none()
                {
                    lock(&nat).forget(packet.flow);
                    None
                } else {
                    let port = ports[usize::from(packet.flow.local.is_ipv6())];
                    let mapping = lock(&nat).begin(packet.flow, port, packet.tcp_sequence);
                    // Selected connections retry their SYN when the flow table is full.
                    if mapping.is_none() {
                        continue;
                    }
                    mapping
                }
            } else {
                lock(&nat).get(packet.flow)
            };
            if let Some(mapping) = mapping {
                packet.reflect(bytes, mapping.token, mapping.relay_port);
                address.inbound();
                if let Err(error) = driver.send_modified(bytes, &mut address) {
                    report("TCP redirect", error);
                }
                continue;
            }
        } else if !bypass(packet.flow.remote, &proxy_addresses) {
            let local = packet.flow.local;
            // These sockets are registered before their first send.
            if lock(&udp_runtime.own_sockets).contains(&local) {
                let _ = driver.send(bytes, &address);
                continue;
            }
            // Do not cache UDP ownership: a socket can close and another process
            // can reuse the same local endpoint between successive datagrams.
            if let Some(pid) = selected(&config, packet.flow, false) {
                let replace = sessions
                    .get(&local)
                    .is_some_and(|session| session.pid != pid || session.worker.is_finished());
                if replace {
                    let session = sessions.remove(&local).unwrap();
                    drop(session.sender);
                    retiring.push(session.worker);
                }
                if !sessions.contains_key(&local)
                    && sessions.len() + retiring.len() < MAX_UDP_SESSIONS
                {
                    let (sender, receiver) = mpsc::sync_channel(64);
                    let runtime = udp_runtime.clone();
                    match thread::Builder::new()
                        .name("windivert-udp".into())
                        .spawn(move || {
                            if let Err(error) = relay_udp(local, pid, receiver, &runtime) {
                                if !runtime.stop.load(Ordering::Acquire) {
                                    report("UDP relay", error);
                                }
                            }
                        }) {
                        Ok(worker) => {
                            sessions.insert(
                                local,
                                UdpSession {
                                    pid,
                                    sender,
                                    worker,
                                },
                            );
                        }
                        Err(error) => report("start UDP relay", error),
                    }
                }
                if let Some(session) = sessions.get(&local) {
                    let datagram = Datagram {
                        captured_at,
                        target: packet.flow.remote,
                        payload: bytes[packet.payload..packet.length].to_vec(),
                        address,
                    };
                    match session.sender.try_send(datagram) {
                        Ok(()) | Err(TrySendError::Full(_)) => {} // Bounded loss, like an OS UDP send queue.
                        Err(TrySendError::Disconnected(_)) => { /* Retried on the next datagram. */
                        }
                    }
                }
                // Selected UDP must never escape directly on association failure or overload.
                if reaped.elapsed() >= Duration::from_secs(1) {
                    reap_udp(&mut sessions, &mut retiring, &metrics, &stop);
                    reaped = Instant::now();
                }
                continue;
            } else if let Some(session) = sessions.remove(&local) {
                drop(session.sender);
                retiring.push(session.worker);
            }
        }
        if let Err(error) = driver.send(bytes, &address) {
            report("pass-through", error);
        }
        if reaped.elapsed() >= Duration::from_secs(1) {
            reap_udp(&mut sessions, &mut retiring, &metrics, &stop);
            reaped = Instant::now();
        }
    }
    driver.shutdown_receive();
    for (_, session) in sessions {
        drop(session.sender);
        retiring.push(session.worker);
    }
    for worker in retiring {
        join_worker(worker, &metrics, &stop);
    }
}

fn bypass(remote: SocketAddr, proxy_addresses: &HashSet<SocketAddr>) -> bool {
    is_private_or_local(remote.ip()) || proxy_addresses.contains(&remote)
}

fn reap_udp(
    sessions: &mut HashMap<SocketAddr, UdpSession>,
    retiring: &mut Vec<JoinHandle<()>>,
    metrics: &Metrics,
    stop: &AtomicBool,
) {
    let finished: Vec<_> = sessions
        .iter()
        .filter(|(_, session)| session.worker.is_finished())
        .map(|(local, _)| *local)
        .collect();
    for local in finished {
        join_worker(sessions.remove(&local).unwrap().worker, metrics, stop);
    }
    let mut index = 0;
    while index < retiring.len() {
        if retiring[index].is_finished() {
            join_worker(retiring.swap_remove(index), metrics, stop);
        } else {
            index += 1;
        }
    }
}

fn relay_udp(
    local: SocketAddr,
    pid: u32,
    receiver: Receiver<Datagram>,
    runtime: &UdpRuntime,
) -> Result<()> {
    let UdpRuntime {
        driver,
        config: _,
        upstream,
        metrics,
        stop,
        own_sockets,
    } = runtime;
    let association = upstream.open_session()?;
    let _own_sockets: Vec<_> = association
        .local_addresses()?
        .into_iter()
        .map(|address| OwnUdpSocket::register(own_sockets.clone(), normalize(address)))
        .collect();
    let mut buffer = vec![0; 65535];
    let mut destinations: HashMap<SocketAddr, (Address, Instant)> = HashMap::new();
    let mut activity = Instant::now();
    let mut control_checked = Instant::now();
    let mut pending = None;
    while !stop.load(Ordering::Acquire) && activity.elapsed() < UDP_IDLE {
        // Drain at most one queue's worth before processing incoming responses.
        for _ in 0..64 {
            let datagram = match pending
                .take()
                .map(Ok)
                .unwrap_or_else(|| receiver.try_recv())
            {
                Ok(datagram) => datagram,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
            };
            if destinations.len() >= 256 && !destinations.contains_key(&datagram.target) {
                destinations.retain(|_, (_, seen)| seen.elapsed() < Duration::from_secs(30));
                if destinations.len() >= 256 {
                    continue;
                }
            }
            destinations.insert(
                datagram.target,
                (datagram.address.for_reply(local.is_ipv6()), Instant::now()),
            );
            let sent = match association.send_to(
                &datagram.payload,
                normalize(datagram.target),
                datagram.captured_at,
            ) {
                Ok(sent) => sent,
                Err(error) if error.downcast_ref::<io::Error>().is_some_and(retryable) => {
                    pending = Some(datagram);
                    break;
                }
                Err(error) => return Err(error),
            };
            metrics.udp_up.fetch_add(sent as u64, Ordering::Relaxed);
            activity = Instant::now();
        }
        for _ in 0..64 {
            let (count, remote) = match association.recv_from(&mut buffer) {
                Ok(value) => value,
                Err(error) if error.downcast_ref::<io::Error>().is_some_and(retryable) => break,
                Err(error) => return Err(error),
            };
            let remote = normalize(remote);
            let Some((address, _)) = destinations.get(&remote) else {
                continue;
            };
            // A stale association must not inject into a reused port belonging to another app.
            if owner::process(Flow { local, remote }, false).ok().flatten() != Some(pid) {
                return Ok(());
            }
            if let Some(mut packet) = packet::udp_reply(remote, local, &buffer[..count]) {
                let mut address = *address;
                driver.send_modified(&mut packet, &mut address)?;
                metrics.udp_down.fetch_add(count as u64, Ordering::Relaxed);
                activity = Instant::now();
            }
        }
        if control_checked.elapsed() >= Duration::from_secs(1) {
            association.check_alive()?;
            control_checked = Instant::now();
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_relay_preserves_response_after_client_half_close() {
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let upstream = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            let mut command = [0; 10];
            stream.read_exact(&mut command).unwrap();
            assert_eq!(command, [5, 1, 0, 1, 8, 8, 8, 8, 1, 187]);
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut body = Vec::new();
            stream.read_to_end(&mut body).unwrap();
            assert_eq!(body, b"request");
            stream.write_all(b"response after EOF").unwrap();
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(local).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream.write_all(b"request").unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).unwrap();
            assert_eq!(reply, b"response after EOF");
        });
        let (stream, peer) = listener.accept().unwrap();
        let config = AppConfig::from_xml(&format!(r#"<config><socks5 host="127.0.0.1" port="{proxy_port}"/><rules><rule name="test.exe" tcp="true"/></rules></config>"#)).unwrap();
        let mapping = Mapping {
            flow: Flow {
                local: peer,
                remote: "8.8.8.8:443".parse().unwrap(),
            },
            token: 1,
            relay_port: local.port(),
            syn_sequence: 0,
            accepted: true,
            closed: false,
            touched: Instant::now(),
        };
        let metrics = Metrics::default();
        relay_tcp(stream, mapping, &config, &metrics, &AtomicBool::new(false)).unwrap();
        client.join().unwrap();
        upstream.join().unwrap();
        assert_eq!(metrics.tcp_up.load(Ordering::Relaxed), 7);
        assert_eq!(metrics.tcp_down.load(Ordering::Relaxed), 18);
    }
}
