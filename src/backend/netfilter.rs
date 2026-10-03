//! NetFilter transport backend. The SDK is loaded at runtime; no C++ shim is used.
mod ffi;
mod rules;
mod service;
mod tcp;

use crate::config::{is_private_or_local, AppConfig};
use crate::metrics::{status, Metrics};
use crate::upstream::UdpUpstream;
use anyhow::{anyhow, bail, Context, Result};
use ffi::{Api, EventHandler, TcpInfo, UdpInfo, UdpOptions, UdpRequest};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use windows_sys::Win32::Networking::WinSock::{WSACleanup, WSAStartup, WSADATA};

const MAX_UDP_OPTION_BYTES: usize = 2 * 1024 * 1024;
const MAX_ENDPOINTS: usize = 1024;
static ACTIVE: Mutex<Option<Arc<Runtime>>> = Mutex::new(None);
static START_LOCK: Mutex<()> = Mutex::new(());

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct TcpSession {
    closed: AtomicBool,
}

struct Datagram {
    captured_at: Instant,
    destination: SocketAddr,
    payload: Vec<u8>,
    options: Vec<u8>,
}

// A game can contact multiple servers (and both IP families) on the same UDP
// socket. SDK options belong to that route, not to the most recently sent packet.
#[derive(Default)]
struct UdpRoutes {
    entries: VecDeque<(SocketAddr, Vec<u8>)>,
    bytes: usize,
}

impl UdpRoutes {
    fn remember(&mut self, destination: SocketAddr, options: Vec<u8>) {
        if let Some(index) = self
            .entries
            .iter()
            .position(|(peer, _)| proxy_address(*peer) == proxy_address(destination))
        {
            let (_, previous) = self.entries.remove(index).unwrap();
            self.bytes -= previous.len();
        }
        self.bytes += options.len();
        self.entries.push_back((destination, options));
        while self.entries.len() > 256 || self.bytes > MAX_UDP_OPTION_BYTES {
            self.bytes -= self.entries.pop_front().unwrap().1.len();
        }
    }

    fn reply(&mut self, source: SocketAddr) -> Option<([u8; 28], &mut [u8])> {
        let source = proxy_address(source);
        let index = self
            .entries
            .iter()
            .position(|(peer, _)| proxy_address(*peer) == source)
            .or_else(|| self.entries.len().checked_sub(1))?;
        let (peer, options) = &mut self.entries[index];
        // Translate IPv4 replies back to the SDK's original mapped IPv6 address
        // when a dual-stack application used an AF_INET6 socket.
        let source = match (source, *peer) {
            (SocketAddr::V4(address), SocketAddr::V6(_)) => SocketAddr::V6(SocketAddrV6::new(
                address.ip().to_ipv6_mapped(),
                address.port(),
                0,
                0,
            )),
            _ => source,
        };
        Some((encode_address(source), options))
    }
}

struct UdpSession {
    tx: SyncSender<Datagram>,
    closed: AtomicBool,
    queue_warning_emitted: AtomicBool,
}

#[derive(Default)]
struct Diagnostics {
    tcp_requests: AtomicU64,
    tcp_selected: AtomicU64,
    tcp_redirected: AtomicU64,
    tcp_accepted: AtomicU64,
    udp_selected: AtomicU64,
    udp_sends: AtomicU64,
    process_lookup_failures: AtomicU64,
}

impl Diagnostics {
    fn snapshot(&self) -> [u64; 7] {
        [
            &self.tcp_requests,
            &self.tcp_selected,
            &self.tcp_redirected,
            &self.tcp_accepted,
            &self.udp_selected,
            &self.udp_sends,
            &self.process_lookup_failures,
        ]
        .map(|count| count.load(Ordering::Relaxed))
    }
}

struct Runtime {
    api: Arc<Api>,
    config: Arc<AppConfig>,
    upstream: Arc<UdpUpstream>,
    proxy_addresses: HashSet<SocketAddr>,
    metrics: Arc<Metrics>,
    external_stop: Arc<AtomicBool>,
    stopping: AtomicBool,
    tcp: Mutex<HashMap<u64, Arc<TcpSession>>>,
    udp: Mutex<HashMap<u64, Arc<UdpSession>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    diagnostics: Diagnostics,
}

impl Runtime {
    fn stopped(&self) -> bool {
        self.stopping.load(Ordering::Acquire) || self.external_stop.load(Ordering::Acquire)
    }

    fn bypass(&self, target: SocketAddr) -> bool {
        is_private_or_local(target.ip()) || self.proxy_addresses.contains(&proxy_address(target))
    }

    fn matches(&self, process_id: u32, tcp: bool) -> bool {
        if process_id == std::process::id() || crate::backend::process::is_local_proxy(process_id) {
            return false;
        }
        let mut name = [0u16; 32768];
        if unsafe { (self.api.process_name)(process_id, name.as_mut_ptr(), name.len() as u32) } == 0
        {
            let failures = self
                .diagnostics
                .process_lookup_failures
                .fetch_add(1, Ordering::Relaxed);
            if failures == 0 {
                status(
                    "warning",
                    &format!(
                        "NetFilter cannot resolve process {process_id}; its traffic is bypassed"
                    ),
                );
            }
            return false;
        }
        let length = name.iter().position(|ch| *ch == 0).unwrap_or(name.len());
        self.config
            .matches_process(&String::from_utf16_lossy(&name[..length]), tcp)
    }

    fn spawn(self: &Arc<Self>, name: String, work: impl FnOnce() + Send + 'static) -> Result<()> {
        let mut workers = lock(&self.workers);
        if self.stopped() {
            bail!("NetFilter is stopping");
        }
        // Completed workers are joined on subsequent connection creation and on shutdown.
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                if workers.swap_remove(index).join().is_err() {
                    self.metrics.fail("NetFilter forwarding worker panicked");
                    self.external_stop.store(true, Ordering::Release);
                    bail!("NetFilter forwarding worker panicked");
                }
            } else {
                index += 1;
            }
        }
        let runtime = Arc::clone(self);
        workers.push(thread::Builder::new().name(name).spawn(move || {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).is_err() {
                runtime.metrics.fail("NetFilter forwarding worker panicked");
                runtime.external_stop.store(true, Ordering::Release);
            }
        })?);
        Ok(())
    }
}

pub struct NetFilter {
    runtime: Arc<Runtime>,
    _handler: Box<EventHandler>,
    driver: Option<service::DriverService>,
    initialized: bool,
    _winsock: Winsock,
}

struct Winsock;
impl Winsock {
    fn start() -> Result<Self> {
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        let result = unsafe { WSAStartup(0x0202, &mut data) };
        if result != 0 {
            bail!("Initialize Winsock for NetFilter failed: {result}");
        }
        Ok(Self)
    }
}
impl Drop for Winsock {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}

impl crate::backend::RunningBackend for NetFilter {
    fn stop(&mut self) {
        if !self.initialized {
            return;
        }
        self.runtime.stopping.store(true, Ordering::Release);
        unsafe {
            (self.runtime.api.delete_rules)();
        }
        // No callback waits for a worker. Setting stopping before taking the worker lock
        // prevents callbacks from creating a worker after this drain.
        let workers = std::mem::take(&mut *lock(&self.runtime.workers));
        for worker in workers {
            if worker.join().is_err() {
                self.runtime
                    .metrics
                    .fail("NetFilter forwarding worker panicked");
                self.runtime.external_stop.store(true, Ordering::Release);
            }
        }
        // nf_free waits for SDK callbacks; keep both context and DLL alive until it returns.
        unsafe {
            (self.runtime.api.free)();
        }
        lock(&ACTIVE).take();
        lock(&self.runtime.tcp).clear();
        lock(&self.runtime.udp).clear();
        self.initialized = false;
        self.driver.take();
    }
}

impl Drop for NetFilter {
    fn drop(&mut self) {
        crate::backend::RunningBackend::stop(self);
    }
}

fn asset_path(name: &str) -> Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let mut candidates = vec![executable.with_file_name(name)];
    if let Some(parent) = executable.parent() {
        candidates.push(parent.join("deps").join(name));
    }
    candidates.push(std::env::current_dir()?.join("deps").join(name));
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            anyhow!("{name} is missing; place the NetFilter SDK files beside rnetch.exe or in deps")
        })?
        .canonicalize()
        .with_context(|| format!("Resolve {name}"))
}

pub fn start(
    config: Arc<AppConfig>,
    metrics: Arc<Metrics>,
    stop: Arc<AtomicBool>,
    upstream: Arc<UdpUpstream>,
) -> Result<Box<dyn crate::backend::RunningBackend>> {
    let _start = lock(&START_LOCK);
    if lock(&ACTIVE).is_some() {
        bail!("NetFilter backend is already running");
    }
    let winsock = Winsock::start()?;
    let mut proxy_addresses: HashSet<_> = upstream
        .endpoint_addresses()?
        .into_iter()
        .map(proxy_address)
        .collect();
    if config.needs_socks5() {
        proxy_addresses.extend(
            crate::socks5::resolve_proxy(&config.socks5)?
                .into_iter()
                .map(proxy_address),
        );
    }
    let api = Arc::new(Api::load(&asset_path("nfapi.dll")?)?);
    let driver_path = asset_path("nfdriver.sys")?;
    let driver_bytes = std::fs::read(&driver_path).context("Read NetFilter driver metadata")?;
    if driver_bytes
        .windows(b"ReleaseDemo".len())
        .any(|bytes| bytes == b"ReleaseDemo")
    {
        status("warning", "NetFilter driver contains a Demo-build marker. The vendor's demo limits filtered TCP connections/UDP sockets and requires a system reboot after exhaustion; use a licensed production driver for sustained use.");
    }
    let driver = service::DriverService::start(&driver_path)?;
    let runtime = Arc::new(Runtime {
        api,
        config,
        upstream,
        proxy_addresses,
        metrics,
        external_stop: stop,
        stopping: AtomicBool::new(false),
        tcp: Mutex::new(HashMap::new()),
        udp: Mutex::new(HashMap::new()),
        workers: Mutex::new(Vec::new()),
        diagnostics: Diagnostics::default(),
    });
    let mut backend = NetFilter {
        runtime: Arc::clone(&runtime),
        driver: Some(driver),
        initialized: false,
        _winsock: winsock,
        _handler: Box::new(EventHandler {
            thread_start: noop,
            thread_end: noop,
            tcp_connect_request: tcp_connect,
            tcp_connected: noop_tcp,
            tcp_closed,
            tcp_receive,
            tcp_send,
            tcp_can_receive: noop_id,
            tcp_can_send: noop_id,
            udp_created,
            udp_connect_request: udp_connect,
            udp_closed,
            udp_receive,
            udp_send,
            udp_can_receive: noop_id,
            udp_can_send: noop_id,
        }),
    };
    *lock(&ACTIVE) = Some(Arc::clone(&runtime));
    // Our SCM code owns registration/startup, so prevent the SDK from changing it.
    unsafe {
        (runtime.api.set_options)(1, 4 | 8);
    }
    let result =
        unsafe { (runtime.api.init)(c"netfilter2".as_ptr().cast(), &mut *backend._handler) };
    if result != 0 {
        lock(&ACTIVE).take();
        bail!("nf_init failed with SDK status {result}");
    }
    backend.initialized = true;
    rules::install(&runtime.api, &runtime.config)?;
    status("info", "NetFilter TCP uses a local WFP redirect relay. Start acceleration before launching the game; existing connections may need to be recreated.");
    let diagnostics_runtime = Arc::clone(&runtime);
    runtime.spawn("nf-diagnostics".into(), move || {
        report_diagnostics(diagnostics_runtime)
    })?;
    Ok(Box::new(backend))
}

fn report_diagnostics(runtime: Arc<Runtime>) {
    let mut previous = None;
    while !runtime.stopped() {
        for _ in 0..100 {
            if runtime.stopped() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let snapshot = runtime.diagnostics.snapshot();
        if previous != Some(snapshot) {
            status("info", &format!(
                "NetFilter diagnostics: TCP requests={} selected={} redirected={} accepted={}, UDP selected={} sends={}, process lookup failures={}",
                snapshot[0], snapshot[1], snapshot[2], snapshot[3], snapshot[4], snapshot[5], snapshot[6]
            ));
            previous = Some(snapshot);
        }
    }
}

// Prevent unwinding across the SDK's C callback boundary.
fn callback(work: impl FnOnce(Arc<Runtime>)) {
    let runtime = lock(&ACTIVE).clone();
    if let Some(runtime) = runtime {
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(Arc::clone(&runtime))))
            .is_err()
        {
            runtime.metrics.fail("NetFilter callback panicked");
            runtime.external_stop.store(true, Ordering::Release);
        }
    }
}

unsafe extern "C" fn noop() {}
unsafe extern "C" fn noop_id(_: u64) {}
unsafe extern "C" fn noop_tcp(_: u64, _: *mut TcpInfo) {}
unsafe extern "C" fn udp_connect(_: u64, _: *mut UdpRequest) {}

unsafe extern "C" fn tcp_connect(id: u64, info: *mut TcpInfo) {
    if info.is_null() {
        return;
    }
    callback(|runtime| {
        runtime
            .diagnostics
            .tcp_requests
            .fetch_add(1, Ordering::Relaxed);
        let mut connection = unsafe { ptr::read_unaligned(info) };
        let target = decode_address(&connection.remote_address);
        if runtime.stopped()
            || target.is_none()
            || connection.direction != 2
            || target.is_some_and(|target| runtime.bypass(target))
            || !runtime.matches(connection.process_id, true)
        {
            connection.filtering_flag = 0;
            unsafe {
                ptr::write_unaligned(info, connection);
                (runtime.api.tcp_disable)(id);
            }
            return;
        }
        let session = Arc::new(TcpSession {
            closed: AtomicBool::new(false),
        });
        runtime
            .diagnostics
            .tcp_selected
            .fetch_add(1, Ordering::Relaxed);
        {
            let mut sessions = lock(&runtime.tcp);
            if sessions.len() >= MAX_ENDPOINTS {
                connection.filtering_flag = 1;
                unsafe {
                    ptr::write_unaligned(info, connection);
                }
                status("warning", "NetFilter TCP connection limit reached");
                return;
            }
            sessions.insert(id, Arc::clone(&session));
        }
        connection.filtering_flag = ffi::PEND_CONNECT;
        unsafe {
            ptr::write_unaligned(info, connection);
        }
        let worker_runtime = Arc::clone(&runtime);
        let result = runtime.spawn(format!("nf-tcp-{id}"), move || {
            tcp_worker(
                worker_runtime,
                id,
                connection,
                proxy_address(target.unwrap()),
                session,
            );
        });
        if let Err(error) = result {
            lock(&runtime.tcp).remove(&id);
            connection.filtering_flag = 1;
            unsafe {
                ptr::write_unaligned(info, connection);
            }
            status("warning", &format!("NetFilter TCP worker: {error}"));
        }
    });
}

unsafe extern "C" fn tcp_closed(id: u64, _: *mut TcpInfo) {
    callback(|runtime| {
        if let Some(session) = lock(&runtime.tcp).remove(&id) {
            session.closed.store(true, Ordering::Release);
        }
    });
}

unsafe extern "C" fn tcp_receive(id: u64, data: *const u8, len: i32) {
    callback(|runtime| {
        if !runtime.stopped() {
            unsafe {
                (runtime.api.tcp_post_receive)(id, data, len);
            }
        }
    });
}

unsafe extern "C" fn tcp_send(id: u64, data: *const u8, len: i32) {
    // Selected TCP streams use WFP connection redirection and ordinary WinSock
    // transport. Pass through any SDK data callbacks for unrelated connections.
    callback(|runtime| {
        if !runtime.stopped() && len >= 0 && (len == 0 || !data.is_null()) {
            unsafe {
                (runtime.api.tcp_post_send)(id, data, len);
            }
        }
    });
}

fn tcp_worker(
    runtime: Arc<Runtime>,
    id: u64,
    mut info: TcpInfo,
    target: SocketAddr,
    session: Arc<TcpSession>,
) {
    let stopped = || runtime.stopped() || session.closed.load(Ordering::Acquire);
    let result = (|| -> Result<()> {
        let connection = crate::socks5::connect(&runtime.config.socks5, target);
        if stopped() {
            return Ok(());
        }
        let proxy = match connection {
            Ok(socket) => socket,
            Err(error) => {
                info.filtering_flag = 0;
                let result = unsafe { (runtime.api.tcp_complete)(id, &mut info) };
                if result != 0 {
                    bail!("Complete direct TCP connect failed: {result}");
                }
                status(
                    "warning",
                    &format!("SOCKS5 TCP connection failed; using direct connection: {error:#}"),
                );
                return Ok(());
            }
        };
        let local = decode_address(&info.local_address)
            .context("NetFilter supplied an unsupported local TCP address")?;
        let listener = tcp::listener(local)?;
        // Match the official WFP SocksRedirector: point the original connection
        // at a real local listener and identify its owner. This avoids OFFLINE
        // emulation, injected TCP stream data, and waiting for tcpConnected.
        info.remote_address = encode_address(listener.local_addr()?);
        info.process_id = std::process::id();
        info.filtering_flag = 0;
        if stopped() {
            return Ok(());
        }
        let completed = unsafe { (runtime.api.tcp_complete)(id, &mut info) };
        if completed != 0 {
            bail!("Complete redirected TCP connect failed: {completed}");
        }
        runtime
            .diagnostics
            .tcp_redirected
            .fetch_add(1, Ordering::Relaxed);
        if let Some(application) = tcp::accept(&listener, local, stopped)? {
            runtime
                .diagnostics
                .tcp_accepted
                .fetch_add(1, Ordering::Relaxed);
            drop(listener);
            tcp::relay(application, proxy, &runtime.metrics, &stopped)?;
        }
        Ok(())
    })();
    if !session.closed.swap(true, Ordering::AcqRel) {
        if let Err(error) = &result {
            status(
                "warning",
                &format!("NetFilter TCP {id} -> {target}: {error:#}"),
            );
        }
        if result.is_err() || runtime.stopped() {
            unsafe {
                (runtime.api.tcp_close)(id);
            }
        }
    }
    lock(&runtime.tcp).remove(&id);
}

unsafe extern "C" fn udp_created(id: u64, info: *mut UdpInfo) {
    if info.is_null() {
        return;
    }
    callback(|runtime| {
        let info = unsafe { ptr::read_unaligned(info) };
        if runtime.stopped() || !runtime.matches(info.process_id, false) {
            unsafe {
                (runtime.api.udp_disable)(id);
            }
            return;
        }
        let (tx, rx) = mpsc::sync_channel(256);
        runtime
            .diagnostics
            .udp_selected
            .fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(UdpSession {
            tx,
            closed: AtomicBool::new(false),
            queue_warning_emitted: AtomicBool::new(false),
        });
        {
            let mut sessions = lock(&runtime.udp);
            if sessions.len() >= MAX_ENDPOINTS {
                status("warning", "NetFilter UDP endpoint limit reached");
                return;
            }
            sessions.insert(id, Arc::clone(&session));
        }
        let worker_runtime = Arc::clone(&runtime);
        if let Err(error) = runtime.spawn(format!("nf-udp-{id}"), move || {
            udp_worker(worker_runtime, id, session, rx)
        }) {
            lock(&runtime.udp).remove(&id);
            status("warning", &format!("NetFilter UDP worker: {error}"));
        }
    });
}

unsafe extern "C" fn udp_closed(id: u64, _: *mut UdpInfo) {
    callback(|runtime| {
        if let Some(session) = lock(&runtime.udp).remove(&id) {
            session.closed.store(true, Ordering::Release);
        }
    });
}

unsafe extern "C" fn udp_receive(
    id: u64,
    address: *const u8,
    data: *const u8,
    len: i32,
    options: *mut UdpOptions,
) {
    callback(|runtime| {
        if !runtime.stopped() {
            unsafe {
                (runtime.api.udp_post_receive)(id, address, data, len, options);
            }
        }
    });
}

unsafe extern "C" fn udp_send(
    id: u64,
    address: *const u8,
    data: *const u8,
    len: i32,
    options: *mut UdpOptions,
) {
    let captured_at = Instant::now();
    callback(|runtime| {
        if runtime.stopped()
            || address.is_null()
            || !(0..=65535).contains(&len)
            || (len > 0 && data.is_null())
        {
            return;
        }
        let target = unsafe { decode_address_pointer(address) };
        if target.is_none() || target.is_some_and(|target| runtime.bypass(target)) {
            unsafe {
                (runtime.api.udp_post_send)(id, address, data, len, options);
            }
            return;
        }
        let session = lock(&runtime.udp).get(&id).cloned();
        if let Some(session) = session {
            runtime
                .diagnostics
                .udp_sends
                .fetch_add(1, Ordering::Relaxed);
            if session.closed.load(Ordering::Acquire) {
                return;
            }
            let Some(options) = (unsafe { copy_options(options) }) else {
                return;
            };
            let payload = if len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(data, len as usize).to_vec() }
            };
            let packet = Datagram {
                captured_at,
                destination: target.unwrap(),
                payload,
                options,
            };
            if session.tx.try_send(packet).is_err()
                && !session.queue_warning_emitted.swap(true, Ordering::AcqRel)
            {
                status("warning", "NetFilter UDP queue exhausted; datagram dropped");
            }
        } else {
            unsafe {
                (runtime.api.udp_post_send)(id, address, data, len, options);
            }
        }
    });
}

fn udp_worker(runtime: Arc<Runtime>, id: u64, session: Arc<UdpSession>, rx: Receiver<Datagram>) {
    let mut retry_delay = Duration::from_millis(250);
    let mut recovering = false;
    while !runtime.stopped() && !session.closed.load(Ordering::Acquire) {
        // Delay UDP ASSOCIATE until the first public datagram. Private-only sockets
        // therefore need no connection to the SOCKS5 server.
        let first = loop {
            if runtime.stopped() || session.closed.load(Ordering::Acquire) {
                return;
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(packet) => break packet,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        };
        let result = udp_relay(
            &runtime,
            id,
            &session,
            &rx,
            first,
            &mut recovering,
            &mut retry_delay,
        );
        if runtime.stopped() || session.closed.load(Ordering::Acquire) {
            break;
        }
        if let Err(error) = result {
            status(
                "warning",
                &format!(
                    "NetFilter UDP {id}: {error:#}; retrying UDP upstream on the next datagram"
                ),
            );
            recovering = true;
            // Discard old game frames and bound retries. Keep the selected socket
            // registered so a transient proxy failure neither leaks direct traffic
            // nor permanently blackholes every later datagram from this socket.
            let retry_at = Instant::now() + retry_delay;
            while Instant::now() < retry_at {
                if runtime.stopped() || session.closed.load(Ordering::Acquire) {
                    return;
                }
                for _ in 0..256 {
                    if rx.try_recv().is_err() {
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(10));
            }
            retry_delay = (retry_delay * 2).min(Duration::from_secs(2));
        }
    }
}

fn udp_relay(
    runtime: &Runtime,
    id: u64,
    session: &UdpSession,
    rx: &Receiver<Datagram>,
    first: Datagram,
    recovering: &mut bool,
    retry_delay: &mut Duration,
) -> Result<()> {
    let association = runtime.upstream.open_session()?;
    let mut routes = UdpRoutes::default();
    let mut pending = Some(first);
    let mut buffer = [0u8; 65535];
    while !runtime.stopped() && !session.closed.load(Ordering::Acquire) {
        let mut progressed = false;
        for _ in 0..32 {
            let packet = match pending.take().or_else(|| rx.try_recv().ok()) {
                Some(packet) => packet,
                None => break,
            };
            match association.send_to(
                &packet.payload,
                proxy_address(packet.destination),
                packet.captured_at,
            ) {
                Ok(sent) => {
                    runtime
                        .metrics
                        .udp_up
                        .fetch_add(sent as u64, Ordering::Relaxed);
                    routes.remember(packet.destination, packet.options);
                    session
                        .queue_warning_emitted
                        .store(false, Ordering::Release);
                    progressed = true;
                }
                Err(error) if is_would_block(&error) => {
                    pending = Some(packet);
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        for _ in 0..32 {
            match association.recv_from(&mut buffer) {
                Ok((length, source)) => {
                    let Some((address, options)) = routes.reply(source) else {
                        continue;
                    };
                    let posted = unsafe {
                        (runtime.api.udp_post_receive)(
                            id,
                            address.as_ptr(),
                            buffer.as_ptr(),
                            length as i32,
                            options.as_mut_ptr().cast(),
                        )
                    };
                    if posted != 0 {
                        bail!("Post UDP receive failed: {posted}");
                    }
                    runtime
                        .metrics
                        .udp_down
                        .fetch_add(length as u64, Ordering::Relaxed);
                    if *recovering {
                        status(
                            "info",
                            &format!("NetFilter UDP {id}: UDP upstream recovered"),
                        );
                        *recovering = false;
                    }
                    *retry_delay = Duration::from_millis(250);
                    progressed = true;
                }
                Err(error) if is_would_block(&error) => break,
                Err(error) => return Err(error),
            }
        }
        association.check_alive()?;
        if !progressed {
            thread::sleep(Duration::from_millis(5));
        }
    }
    Ok(())
}

fn proxy_address(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => match address.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::new(ip.into(), address.port()),
            None => SocketAddr::V6(address),
        },
        address => address,
    }
}

fn is_would_block(error: &anyhow::Error) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|error| {
        matches!(
            error.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
        )
    })
}

unsafe fn copy_options(options: *mut UdpOptions) -> Option<Vec<u8>> {
    if options.is_null() {
        return Some(vec![0u8; 9]);
    }
    let length = unsafe { ptr::read_unaligned(ptr::addr_of!((*options).options_length)) };
    if !(0..=65535).contains(&length) {
        return None;
    }
    let mut copy =
        unsafe { std::slice::from_raw_parts(options.cast::<u8>(), 8 + length as usize).to_vec() };
    copy.resize(copy.len().max(9), 0);
    Some(copy)
}

unsafe fn decode_address_pointer(address: *const u8) -> Option<SocketAddr> {
    if address.is_null() {
        return None;
    }
    let family = unsafe { ptr::read_unaligned(address.cast::<u16>()) };
    let length = match family {
        2 => 16,
        23 => 28,
        _ => return None,
    };
    let mut copy = [0u8; 28];
    unsafe {
        ptr::copy_nonoverlapping(address, copy.as_mut_ptr(), length);
    }
    decode_address(&copy)
}

fn decode_address(address: &[u8; 28]) -> Option<SocketAddr> {
    let family = u16::from_ne_bytes([address[0], address[1]]);
    let port = u16::from_be_bytes([address[2], address[3]]);
    match family {
        2 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                address[4], address[5], address[6], address[7],
            )),
            port,
        )),
        23 => Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(<[u8; 16]>::try_from(&address[8..24]).ok()?),
            port,
            u32::from_be_bytes(address[4..8].try_into().ok()?),
            u32::from_ne_bytes(address[24..28].try_into().ok()?),
        ))),
        _ => None,
    }
}

fn encode_address(address: SocketAddr) -> [u8; 28] {
    let mut output = [0u8; 28];
    output[2..4].copy_from_slice(&address.port().to_be_bytes());
    match address {
        SocketAddr::V4(address) => {
            output[..2].copy_from_slice(&2u16.to_ne_bytes());
            output[4..8].copy_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            output[..2].copy_from_slice(&23u16.to_ne_bytes());
            output[4..8].copy_from_slice(&address.flowinfo().to_be_bytes());
            output[8..24].copy_from_slice(&address.ip().octets());
            output[24..28].copy_from_slice(&address.scope_id().to_ne_bytes());
        }
    }
    output
}

#[cfg(test)]
#[path = "netfilter/tests.rs"]
mod tests;

#[cfg(test)]
mod address_tests {
    use super::*;

    #[test]
    fn sdk_sockaddr_round_trip() {
        for address in [
            "8.8.8.8:53".parse::<SocketAddr>().unwrap(),
            "[2001:4860:4860::8888]:443".parse().unwrap(),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9000, 7, 3)),
        ] {
            assert_eq!(decode_address(&encode_address(address)), Some(address));
        }
        assert!(decode_address(&[0u8; 28]).is_none());
    }

    #[test]
    fn udp_options_are_owned_and_validated() {
        let mut raw = vec![0u8; 12];
        raw[4..8].copy_from_slice(&4i32.to_ne_bytes());
        raw[8..].copy_from_slice(&[1, 2, 3, 4]);
        let copy = unsafe { copy_options(raw.as_mut_ptr().cast()) }.unwrap();
        raw[8] = 99;
        assert_eq!(copy[8..], [1, 2, 3, 4]);
        raw[4..8].copy_from_slice(&(-1i32).to_ne_bytes());
        assert!(unsafe { copy_options(raw.as_mut_ptr().cast()) }.is_none());
    }
}
