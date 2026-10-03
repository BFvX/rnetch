use serde_json::{json, Value};
use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Default)]
pub struct Metrics {
    pub tcp_up: AtomicU64,
    pub tcp_down: AtomicU64,
    pub udp_up: AtomicU64,
    pub udp_down: AtomicU64,
    failure: std::sync::Mutex<Option<String>>,
}

pub fn emit(value: Value) {
    // One locked line preserves the Electron stdout protocol across worker threads.
    let mut output = io::stdout().lock();
    let _ = writeln!(output, "{value}");
    let _ = output.flush();
}

pub fn status(state: &str, message: &str) {
    emit(json!({"type":"status", "state":state, "message":message}));
}

impl Metrics {
    /// Record a terminal worker error so shutdown cannot turn it into success.
    pub fn fail(&self, message: &str) {
        let mut failure = self
            .failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if failure.is_none() {
            *failure = Some(message.to_owned());
        }
        status("error", message);
    }

    pub fn failure(&self) -> Option<String> {
        self.failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn snapshot(&self) -> [u64; 4] {
        [&self.tcp_up, &self.tcp_down, &self.udp_up, &self.udp_down]
            .map(|v| v.load(Ordering::Relaxed))
    }

    pub fn emit(&self, rates: [u64; 4]) {
        let totals = self.snapshot();
        emit(json!({"type":"metrics",
            "tcpUpBps":rates[0], "tcpDownBps":rates[1], "udpUpBps":rates[2], "udpDownBps":rates[3],
            "totalUpBps":rates[0].saturating_add(rates[2]), "totalDownBps":rates[1].saturating_add(rates[3]),
            "tcpUpBytes":totals[0], "tcpDownBytes":totals[1], "udpUpBytes":totals[2], "udpDownBytes":totals[3]}));
    }

    pub fn spawn(self: &Arc<Self>, stop: Arc<AtomicBool>) -> JoinHandle<()> {
        let metrics = Arc::clone(self);
        thread::spawn(move || {
            let mut previous = metrics.snapshot();
            let mut at = Instant::now();
            while !stop.load(Ordering::Acquire) {
                thread::park_timeout(Duration::from_secs(1));
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let now = Instant::now();
                let current = metrics.snapshot();
                let elapsed = now.duration_since(at).as_secs_f64();
                let rates = std::array::from_fn(|i| {
                    (current[i].saturating_sub(previous[i]) as f64 / elapsed) as u64
                });
                metrics.emit(rates);
                previous = current;
                at = now;
            }
            metrics.emit([0; 4]);
        })
    }
}
