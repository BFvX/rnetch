//! Opt-in Windows driver acceptance test. `--help` and `--self-test` never load
//! drivers. The mock proxy only echoes data in memory; it never connects to the
//! TEST-NET destinations. Run each backend separately from an elevated terminal.
use anyhow::{bail, ensure, Context, Result};
use rnetch::{config::Socks5Config, socks5};
use serde_json::Value;
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const HELP: &str = "Isolated rnetch driver smoke test\n\n\
Usage:\n  cargo run --example driver_smoke -- --help\n  \
cargo run --example driver_smoke -- --self-test\n  \
cargo run --example driver_smoke -- --run --backend netfilter|windivert [--exe PATH]\n\n\
--run explicitly loads the selected real driver and requires Administrator.\n\
Build target/release/rnetch.exe and its runtime files first. Stop other rnetch\n\
instances. The temporary config matches only driver_smoke.exe. A localhost\n\
SOCKS5 mock echoes TCP and UDP addressed to 198.51.100.1; no remote echo server\n\
is contacted by the mock. A working IPv4 route is still needed by Windows.\n\
Tests require running status, both echo paths, four nonzero byte counters, and\n\
clean Enter shutdown. Each wait is bounded; failures terminate the child.\n\
Record the selected backend and whether its driver was already installed.\n";
const TCP_TARGET: &str = "198.51.100.1:32123";
const UDP_TARGET: &str = "198.51.100.1:32124";
const TCP_PAYLOAD: &[u8] = b"rnetch isolated TCP echo\0\x01\xff";
const UDP_PAYLOAD: &[u8] = b"rnetch isolated UDP echo\0\x02\xff";
const POLL: Duration = Duration::from_millis(100);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn read_exact_until(stream: &mut TcpStream, bytes: &mut [u8], stop: &AtomicBool) -> Result<()> {
    let until = Instant::now() + IO_TIMEOUT;
    let mut offset = 0;
    while offset < bytes.len() {
        ensure!(!stop.load(Ordering::Acquire), "Mock proxy is stopping");
        ensure!(Instant::now() < until, "Mock SOCKS5 handshake timed out");
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => bail!("Mock SOCKS5 handshake ended unexpectedly"),
            Ok(size) => offset += size,
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[derive(Default)]
struct Traffic {
    tcp_connects: AtomicUsize,
    udp_associations: AtomicUsize,
    tcp_echo_bytes: AtomicUsize,
    udp_echo_bytes: AtomicUsize,
}

struct MockProxy {
    port: u16,
    stop: Arc<AtomicBool>,
    traffic: Arc<Traffic>,
    errors: Arc<Mutex<Vec<String>>>,
    worker: Option<JoinHandle<()>>,
}

impl MockProxy {
    fn start() -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let traffic = Arc::new(Traffic::default());
        let errors = Arc::new(Mutex::new(Vec::new()));
        let (signal, counts, failures) = (stop.clone(), traffic.clone(), errors.clone());
        let worker = thread::spawn(move || {
            let mut clients = Vec::new();
            while !signal.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if clients.len() >= 8 {
                            failures
                                .lock()
                                .unwrap()
                                .push("Unexpected number of mock proxy connections".into());
                            break;
                        }
                        let (signal, counts, failures) =
                            (signal.clone(), counts.clone(), failures.clone());
                        clients.push(thread::spawn(move || {
                            if let Err(error) = serve_client(stream, &signal, &counts) {
                                if !signal.load(Ordering::Acquire) {
                                    failures.lock().unwrap().push(format!("{error:#}"));
                                }
                            }
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => {
                        failures.lock().unwrap().push(error.to_string());
                        break;
                    }
                }
            }
            signal.store(true, Ordering::Release);
            for client in clients {
                if client.join().is_err() {
                    failures
                        .lock()
                        .unwrap()
                        .push("Mock proxy worker panicked".into());
                }
            }
        });
        Ok(Self {
            port,
            stop,
            traffic,
            errors,
            worker: Some(worker),
        })
    }

    fn verify(&self) -> Result<()> {
        let errors = self.errors.lock().unwrap();
        ensure!(
            errors.is_empty(),
            "Mock proxy errors: {}",
            errors.join("; ")
        );
        ensure!(
            self.traffic.tcp_connects.load(Ordering::Relaxed) > 0,
            "No SOCKS5 CONNECT reached the mock"
        );
        ensure!(
            self.traffic.udp_associations.load(Ordering::Relaxed) > 0,
            "No SOCKS5 UDP ASSOCIATE reached the mock"
        );
        ensure!(
            self.traffic.tcp_echo_bytes.load(Ordering::Relaxed) >= TCP_PAYLOAD.len(),
            "TCP payload did not reach the mock"
        );
        ensure!(
            self.traffic.udp_echo_bytes.load(Ordering::Relaxed) >= UDP_PAYLOAD.len(),
            "UDP payload did not reach the mock"
        );
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("Mock listener panicked"))?;
        }
        self.verify()
    }
}

impl Drop for MockProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn socks_reply(stream: &mut TcpStream, port: u16) -> Result<()> {
    let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
    reply.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&reply)?;
    Ok(())
}

fn serve_client(mut stream: TcpStream, stop: &AtomicBool, traffic: &Traffic) -> Result<()> {
    stream.set_read_timeout(Some(POLL))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut greeting = [0; 2];
    read_exact_until(&mut stream, &mut greeting, stop)?;
    ensure!(
        greeting[0] == 5 && greeting[1] > 0,
        "Invalid SOCKS5 greeting"
    );
    let mut methods = vec![0; greeting[1] as usize];
    read_exact_until(&mut stream, &mut methods, stop)?;
    ensure!(methods.contains(&0), "Mock requires SOCKS5 no-auth");
    stream.write_all(&[5, 0])?;
    let mut request = [0; 4];
    read_exact_until(&mut stream, &mut request, stop)?;
    ensure!(
        request[0] == 5 && request[2] == 0 && request[3] == 1,
        "Mock requires an IPv4 SOCKS5 request"
    );
    let mut address = [0; 6];
    read_exact_until(&mut stream, &mut address, stop)?;
    let target = SocketAddr::from((
        Ipv4Addr::new(address[0], address[1], address[2], address[3]),
        u16::from_be_bytes([address[4], address[5]]),
    ));
    match request[1] {
        1 => {
            ensure!(
                target == TCP_TARGET.parse::<SocketAddr>()?,
                "Unexpected TCP destination: {target}"
            );
            traffic.tcp_connects.fetch_add(1, Ordering::Relaxed);
            socks_reply(&mut stream, 1)?;
            let mut bytes = [0; 4096];
            while !stop.load(Ordering::Acquire) {
                match stream.read(&mut bytes) {
                    Ok(0) => return Ok(()),
                    Ok(size) => {
                        stream.write_all(&bytes[..size])?;
                        traffic.tcp_echo_bytes.fetch_add(size, Ordering::Relaxed);
                    }
                    Err(error) if retryable(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        3 => {
            let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
            relay.set_read_timeout(Some(POLL))?;
            relay.set_write_timeout(Some(IO_TIMEOUT))?;
            traffic.udp_associations.fetch_add(1, Ordering::Relaxed);
            socks_reply(&mut stream, relay.local_addr()?.port())?;
            stream.set_nonblocking(true)?;
            let mut packet = [0; 65535];
            while !stop.load(Ordering::Acquire) {
                match stream.peek(&mut [0]) {
                    Ok(0) => return Ok(()),
                    Ok(_) => bail!("Unexpected UDP association control data"),
                    Err(error) if retryable(&error) => {}
                    Err(error) => return Err(error.into()),
                }
                match relay.recv_from(&mut packet) {
                    Ok((size, peer)) => {
                        // Decode independently of the production framing helpers.
                        ensure!(
                            size >= 10 && packet[..4] == [0, 0, 0, 1],
                            "Invalid IPv4 SOCKS5 UDP packet"
                        );
                        let destination = SocketAddr::from((
                            Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]),
                            u16::from_be_bytes([packet[8], packet[9]]),
                        ));
                        ensure!(
                            destination == UDP_TARGET.parse::<SocketAddr>()?,
                            "Unexpected UDP destination: {destination}"
                        );
                        ensure!(
                            peer.ip().is_loopback(),
                            "Mock relay received a nonlocal peer"
                        );
                        ensure!(
                            relay.send_to(&packet[..size], peer)? == size,
                            "Partial mock UDP echo"
                        );
                        traffic
                            .udp_echo_bytes
                            .fetch_add(size - 10, Ordering::Relaxed);
                    }
                    Err(error) if retryable(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        command => bail!("Unsupported mock SOCKS5 command: {command}"),
    }
    Ok(())
}

fn check_tcp_echo(mut stream: TcpStream) -> Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(TCP_PAYLOAD)?;
    let mut echoed = vec![0; TCP_PAYLOAD.len()];
    stream
        .read_exact(&mut echoed)
        .context("TCP echo timed out or was truncated")?;
    ensure!(echoed == TCP_PAYLOAD, "TCP echo payload mismatch");
    Ok(())
}

fn exercise_mock(port: u16) -> Result<()> {
    let config = Socks5Config {
        host: "127.0.0.1".into(),
        port,
        user: String::new(),
        pass: String::new(),
    };
    check_tcp_echo(socks5::connect(&config, TCP_TARGET.parse()?)?)?;
    let association = socks5::UdpAssociation::connect(&config)?;
    association.socket.set_read_timeout(Some(IO_TIMEOUT))?;
    association.send_to(UDP_PAYLOAD, UDP_TARGET.parse()?)?;
    let mut echoed = [0; 4096];
    let (size, source) = association.recv_from(&mut echoed)?;
    ensure!(
        source == UDP_TARGET.parse::<SocketAddr>()? && &echoed[..size] == UDP_PAYLOAD,
        "Mock SOCKS5 UDP roundtrip mismatch"
    );
    Ok(())
}

fn self_test() -> Result<()> {
    let mut proxy = ProxyProcess::start()?;
    exercise_mock(proxy.port)?;
    proxy.finish()?;
    println!("PASS: isolated localhost mock SOCKS5 TCP/UDP self-test; no driver loaded");
    Ok(())
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

// In live tests the SOCKS daemon must have a different PID from the application:
// rnetch excludes the detected proxy PID to prevent proxy loops for broad rules.
struct ProxyProcess {
    process: KillOnDrop,
    lines: Receiver<String>,
    port: u16,
}

impl ProxyProcess {
    fn start() -> Result<Self> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--mock-server")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut process = KillOnDrop(
            command
                .spawn()
                .context("Cannot start isolated mock proxy")?,
        );
        let stdout = process.0.stdout.take().context("Mock stdout unavailable")?;
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let line = lines
            .recv_timeout(IO_TIMEOUT)
            .context("Mock proxy startup timed out")?;
        let ready: Value = serde_json::from_str(&line).context("Invalid mock readiness message")?;
        ensure!(
            ready["type"] == "mock-ready",
            "Unexpected mock readiness message"
        );
        let port = ready["port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port > 0)
            .context("Invalid mock listen port")?;
        Ok(Self {
            process,
            lines,
            port,
        })
    }

    fn finish(&mut self) -> Result<()> {
        let mut stdin = self
            .process
            .0
            .stdin
            .take()
            .context("Mock stdin unavailable")?;
        stdin.write_all(b"\n")?;
        drop(stdin);
        let until = Instant::now() + IO_TIMEOUT + Duration::from_secs(1);
        let mut verified = false;
        loop {
            if let Ok(line) = self.lines.recv_timeout(POLL) {
                let result: Value =
                    serde_json::from_str(&line).context("Invalid mock result message")?;
                ensure!(
                    result["type"] == "mock-result" && result["ok"] == true,
                    "Mock verification failed: {line}"
                );
                verified = true;
                println!("mock: {line}");
            }
            if let Some(status) = self.process.0.try_wait()? {
                if !verified {
                    if let Ok(line) = self.lines.recv_timeout(POLL) {
                        let result: Value = serde_json::from_str(&line)?;
                        verified = result["type"] == "mock-result" && result["ok"] == true;
                    }
                }
                ensure!(
                    status.success() && verified,
                    "Mock proxy exited without successful TCP/UDP verification: {status}"
                );
                return Ok(());
            }
            ensure!(Instant::now() < until, "Mock proxy shutdown timed out");
        }
    }
}

fn mock_server() -> Result<()> {
    let mut proxy = MockProxy::start()?;
    println!(
        "{}",
        serde_json::json!({"type":"mock-ready", "port":proxy.port})
    );
    io::stdout().flush()?;
    io::stdin().read_line(&mut String::new())?;
    proxy.finish()?;
    println!(
        "{}",
        serde_json::json!({"type":"mock-result", "ok":true,
        "tcpBytes":proxy.traffic.tcp_echo_bytes.load(Ordering::Relaxed),
        "udpBytes":proxy.traffic.udp_echo_bytes.load(Ordering::Relaxed)})
    );
    io::stdout().flush()?;
    Ok(())
}

struct ChildSession {
    process: KillOnDrop,
    lines: Receiver<String>,
    bytes: [u64; 4],
    running: bool,
}

impl ChildSession {
    fn start(executable: &PathBuf, config: &PathBuf) -> Result<Self> {
        let mut command = Command::new(executable);
        command
            .arg(config)
            .current_dir(
                executable
                    .parent()
                    .context("Executable has no parent directory")?,
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        let mut process = KillOnDrop(command.spawn().context("Cannot start rnetch executable")?);
        let stdout = process
            .0
            .stdout
            .take()
            .context("Missing child stdout pipe")?;
        let stderr = process
            .0
            .stderr
            .take()
            .context("Missing child stderr pipe")?;
        let (tx, lines) = mpsc::channel();
        let out_tx = tx.clone();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if out_tx.send(line).is_err() {
                    break;
                }
            }
        });
        thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if tx.send(format!("stderr: {line}")).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            process,
            lines,
            bytes: [0; 4],
            running: false,
        })
    }

    fn receive(&mut self) -> Result<()> {
        if let Ok(line) = self.lines.recv_timeout(POLL) {
            println!("rnetch: {line}");
            if let Ok(event) = serde_json::from_str::<Value>(&line) {
                if event["type"] == "status" {
                    ensure!(
                        event["state"] != "error",
                        "Native runtime error: {}",
                        event["message"]
                    );
                    if event["state"] == "running" || event["state"] == "started" {
                        self.running = true;
                    }
                }
                if event["type"] == "metrics" {
                    for (index, key) in ["tcpUpBytes", "tcpDownBytes", "udpUpBytes", "udpDownBytes"]
                        .iter()
                        .enumerate()
                    {
                        self.bytes[index] = self.bytes[index].max(event[key].as_u64().unwrap_or(0));
                    }
                }
            }
        }
        Ok(())
    }

    fn wait_for(
        &mut self,
        timeout: Duration,
        label: &str,
        complete: impl Fn(&Self) -> bool,
    ) -> Result<()> {
        let until = Instant::now() + timeout;
        while !complete(self) {
            ensure!(Instant::now() < until, "Timed out waiting for {label}");
            self.receive()?;
            if let Some(status) = self.process.0.try_wait()? {
                bail!("rnetch exited before {label}: {status}");
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        let mut stdin = self
            .process
            .0
            .stdin
            .take()
            .context("Child stdin is unavailable")?;
        stdin
            .write_all(b"\n")
            .context("Cannot send Enter shutdown")?;
        drop(stdin);
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            self.receive()?;
            if let Some(status) = self.process.0.try_wait()? {
                ensure!(status.success(), "Enter shutdown failed: {status}");
                return Ok(());
            }
            ensure!(Instant::now() < until, "Enter shutdown exceeded 15 seconds");
        }
    }
}

struct TemporaryConfig(PathBuf);
impl Drop for TemporaryConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn driver_test(backend: &str, executable: PathBuf) -> Result<()> {
    ensure!(cfg!(windows), "Real driver tests require Windows x64");
    let this_executable = std::env::current_exe()?;
    ensure!(
        this_executable
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("driver_smoke.exe")),
        "Run the example as driver_smoke.exe so only its process matches the temporary config"
    );
    let executable = executable
        .canonicalize()
        .context("Build target/release/rnetch.exe before driver testing")?;
    let mut proxy = ProxyProcess::start()?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let config = TemporaryConfig(std::env::temp_dir().join(format!(
        "rnetch-driver-smoke-{}-{nonce}.xml",
        std::process::id()
    )));
    std::fs::write(&config.0, format!("<config><backend type=\"{backend}\"/><socks5 host=\"127.0.0.1\" port=\"{}\"/><rules><rule name=\"driver_smoke.exe\" tcp=\"1\" udp=\"1\"/></rules></config>", proxy.port))?;
    println!("Testing backend={backend}; rule=driver_smoke.exe only; SOCKS5=127.0.0.1:{}; destinations={TCP_TARGET}, {UDP_TARGET}", proxy.port);
    let mut child = ChildSession::start(&executable, &config.0)?;
    child.wait_for(Duration::from_secs(20), "running status", |session| {
        session.running
    })?;

    check_tcp_echo(
        TcpStream::connect_timeout(&TCP_TARGET.parse()?, IO_TIMEOUT)
            .context("Intercepted TEST-NET TCP connection failed")?,
    )?;
    println!("PASS: intercepted TCP CONNECT echo");
    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    udp.connect(UDP_TARGET)?;
    udp.set_read_timeout(Some(Duration::from_millis(400)))?;
    udp.set_write_timeout(Some(IO_TIMEOUT))?;
    let until = Instant::now() + IO_TIMEOUT;
    let mut echoed = [0; 4096];
    loop {
        ensure!(Instant::now() < until, "Intercepted UDP echo timed out");
        udp.send(UDP_PAYLOAD)?;
        match udp.recv(&mut echoed) {
            Ok(size) => {
                ensure!(
                    &echoed[..size] == UDP_PAYLOAD,
                    "Intercepted UDP echo mismatch"
                );
                break;
            }
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error).context("Intercepted TEST-NET UDP receive failed"),
        }
    }
    drop(udp);
    println!("PASS: intercepted UDP ASSOCIATE echo");
    child.wait_for(
        Duration::from_secs(5),
        "TCP/UDP upload/download metrics",
        |session| session.bytes.iter().all(|&bytes| bytes > 0),
    )?;
    child.stop()?;
    proxy.finish()?;
    println!(
        "PASS: {backend} driver TCP/UDP echoes, four byte counters {:?}, Enter shutdown exit 0",
        child.bytes
    );
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        print!("{HELP}");
        return Ok(());
    }
    if args == ["--self-test"] {
        return self_test();
    }
    if args == ["--mock-server"] {
        return mock_server();
    }
    let mut backend = None;
    let mut executable =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/release/rnetch.exe");
    let mut opt_in = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--run") => opt_in = true,
            Some("--backend") => {
                let value = args
                    .next()
                    .context("--backend requires netfilter or windivert")?;
                ensure!(
                    value == "netfilter" || value == "windivert",
                    "Choose exactly one backend: netfilter or windivert"
                );
                backend = Some(value.to_string_lossy().into_owned());
            }
            Some("--exe") => executable = args.next().context("--exe requires a path")?.into(),
            _ => bail!("Unknown argument; use --help"),
        }
    }
    ensure!(opt_in, "Driver execution requires explicit --run; use --self-test to test the mock without a driver");
    driver_test(
        &backend.context("--run requires an explicit --backend")?,
        executable,
    )
}

fn main() {
    if let Err(error) = run() {
        eprintln!("FAIL: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn mock_socks5_tcp_and_udp_echo_without_driver() {
        let mut proxy = super::MockProxy::start().unwrap();
        super::exercise_mock(proxy.port).unwrap();
        proxy.finish().unwrap();
    }
}
