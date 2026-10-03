use anyhow::{bail, Context, Result};
use rnetch::{
    backend,
    config::{AppConfig, BackendKind},
    metrics::{self, Metrics},
    socks5,
};
use std::{
    io,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

const HELP: &str = concat!(
    "rnetch ", env!("CARGO_PKG_VERSION"),
    " (Rust)\n\nUsage: rnetch [config.xml] [--backend netfilter|windivert] [--check-config]\n\n  --backend       Override the XML capture driver (legacy default: netfilter)\n  --check-config  Validate configuration without loading any driver\n  --help, -h      Show this help\n  --version, -V   Show version\n\nUDP transport is selected in XML: socks5 (default) or gpux. TCP uses SOCKS5.\nRun on Windows x64 as Administrator. Press Enter or Ctrl+C to stop.\n"
);

#[derive(Debug, Default)]
struct Options {
    config: PathBuf,
    backend: Option<BackendKind>,
    check: bool,
    help: bool,
    version: bool,
}

fn parse_args(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Options> {
    let mut options = Options {
        config: PathBuf::from("config.xml"),
        ..Options::default()
    };
    let mut args = args.into_iter();
    let mut has_path = false;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--backend") => {
                options.backend = Some(
                    args.next()
                        .context("--backend requires a value")?
                        .to_str()
                        .context("Backend name must be UTF-8")?
                        .parse()?,
                )
            }
            Some("--check-config") => options.check = true,
            Some("--help" | "-h") => options.help = true,
            Some("--version" | "-V") => options.version = true,
            Some(value) if value.starts_with('-') => bail!("Unknown option {value}"),
            _ if !has_path => {
                options.config = PathBuf::from(arg);
                has_path = true;
            }
            _ => bail!("Only one configuration path may be supplied"),
        }
    }
    Ok(options)
}

fn run() -> Result<()> {
    let options = parse_args(std::env::args_os().skip(1))?;
    if options.help {
        print!("{HELP}");
        return Ok(());
    }
    if options.version {
        println!("rnetch {} (Rust)", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let mut config = AppConfig::load(&options.config)?;
    if let Some(backend) = options.backend {
        config.backend = backend;
    }
    if options.check {
        println!(
            "Configuration valid: backend={}, udp_transport={}, rules={}",
            config.backend,
            config.udp_transport,
            config.rules.len()
        );
        return Ok(());
    }
    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))
        .context("Cannot install shutdown handler")?;
    if config.needs_socks5() {
        socks5::resolve_proxy(&config.socks5)?;
    }
    metrics::status(
        "starting",
        &format!(
            "Starting Rust core with {} capture driver and {} UDP transport",
            config.backend, config.udp_transport
        ),
    );
    let metrics = Arc::new(Metrics::default());
    let mut backend = backend::start(Arc::new(config), Arc::clone(&metrics), Arc::clone(&stop))?;
    let reporter = metrics.spawn(Arc::clone(&stop));
    let signal = Arc::clone(&stop);
    // Electron owns this pipe and sends a newline; EOF also stops the child.
    thread::spawn(move || {
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
        signal.store(true, Ordering::Release);
    });
    metrics::status("running", "Rnetch started. Press Enter or Ctrl+C to stop.");
    while !stop.load(Ordering::Acquire) {
        if let Err(error) = backend.check_health() {
            metrics.fail(&format!("Shared UDP upstream stopped: {error:#}"));
            stop.store(true, Ordering::Release);
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    metrics::status("stopping", "Stopping forwarding workers");
    backend.stop();
    reporter.thread().unpark();
    let _ = reporter.join();
    if let Some(error) = metrics.failure() {
        bail!("{error}");
    }
    metrics::status("stopped", "Rnetch stopped");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        metrics::status("error", &format!("{error:#}"));
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Result<Options> {
        parse_args(values.iter().map(std::ffi::OsString::from))
    }
    #[test]
    fn parses_legacy_and_extended_cli() {
        assert_eq!(args(&[]).unwrap().config, PathBuf::from("config.xml"));
        let opts = args(&["配置.xml", "--backend", "windivert", "--check-config"]).unwrap();
        assert_eq!(opts.config, PathBuf::from("配置.xml"));
        assert_eq!(opts.backend, Some(BackendKind::Windivert));
        assert!(opts.check);
        for values in [
            &["--backend"][..],
            &["--backend", "oops"],
            &["a", "b"],
            &["--wat"],
        ] {
            assert!(args(values).is_err());
        }
    }
}
