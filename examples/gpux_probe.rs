//! Driver-free interop probe against an existing GPUX server and UDP echo targets.
use anyhow::{bail, ensure, Context, Result};
use rnetch::{
    config::{AppConfig, UdpTransportKind},
    upstream::UdpUpstream,
};
use std::{
    collections::HashSet,
    io,
    net::SocketAddr,
    path::Path,
    thread,
    time::{Duration, Instant},
};

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        (2..=3).contains(&args.len()),
        "Usage: gpux_probe config.xml echo-ip:port [second-echo-ip:port]"
    );
    let config = AppConfig::load(Path::new(&args[0]))?;
    ensure!(
        config.udp_transport == UdpTransportKind::Gpux,
        "Probe requires GPUX UDP transport"
    );
    let targets: Vec<SocketAddr> = args[1..]
        .iter()
        .map(|value| value.parse().context("Invalid echo target"))
        .collect::<Result<_>>()?;
    let upstream = UdpUpstream::start(&config)?;
    let sessions = [upstream.open_session()?, upstream.open_session()?];
    let mut expected = HashSet::new();
    for sequence in 0..12 {
        for (session_id, session) in sessions.iter().enumerate() {
            for target in &targets {
                let payload = format!("gpux-probe:{session_id}:{target}:{sequence}").into_bytes();
                let captured_at = Instant::now();
                loop {
                    match session.send_to(&payload, *target, captured_at) {
                        Ok(size) if size == payload.len() => break,
                        Ok(_) => bail!("Probe datagram expired or exceeded MTU"),
                        Err(error)
                            if error
                                .downcast_ref::<io::Error>()
                                .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock) =>
                        {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => return Err(error),
                    }
                }
                expected.insert((session_id, *target, payload));
            }
        }
    }
    let packet_count = expected.len();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buffer = [0; 65535];
    while !expected.is_empty() {
        ensure!(
            Instant::now() < deadline,
            "Missing {} echo replies",
            expected.len()
        );
        for (session_id, session) in sessions.iter().enumerate() {
            session.check_alive()?;
            loop {
                match session.recv_from(&mut buffer) {
                    Ok((length, source)) => {
                        ensure!(
                            expected.remove(&(session_id, source, buffer[..length].to_vec())),
                            "Unexpected, duplicate or misrouted GPUX response"
                        );
                    }
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock) =>
                    {
                        break
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
    drop(sessions);
    upstream.stop();
    println!(
        "GPUX interop passed: {packet_count} replies, 2 sessions, {} targets",
        targets.len()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
