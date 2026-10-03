#[cfg(all(windows, not(target_arch = "x86_64")))]
compile_error!("rnetch driver backends require the x86_64-pc-windows-msvc target");

pub mod backend;
pub mod config;
pub mod gpux;
pub mod metrics;
pub mod socks5;
pub mod upstream;
