use crate::{config::AppConfig, metrics::Metrics};
use anyhow::Result;
use std::sync::{atomic::AtomicBool, Arc};

#[cfg(windows)]
pub mod netfilter;
#[cfg(windows)]
pub(crate) mod process;
#[cfg(windows)]
pub mod windivert;

pub trait RunningBackend {
    /// Release interception first, then wake and join forwarding workers.
    fn stop(&mut self);

    /// Shared transport failure is terminal, unlike an individual UDP flow error.
    fn check_health(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
struct WithUpstream {
    driver: Box<dyn RunningBackend>,
    upstream: Arc<crate::upstream::UdpUpstream>,
}

#[cfg(windows)]
impl RunningBackend for WithUpstream {
    fn stop(&mut self) {
        self.driver.stop();
        self.upstream.stop();
    }

    fn check_health(&self) -> Result<()> {
        self.upstream.check_alive()
    }
}

#[cfg(windows)]
impl Drop for WithUpstream {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start(
    config: Arc<AppConfig>,
    metrics: Arc<Metrics>,
    stop: Arc<AtomicBool>,
) -> Result<Box<dyn RunningBackend>> {
    #[cfg(windows)]
    {
        use crate::config::BackendKind;
        let upstream = Arc::new(crate::upstream::UdpUpstream::start(&config)?);
        let driver = match config.backend {
            BackendKind::Netfilter => netfilter::start(config, metrics, stop, upstream.clone()),
            BackendKind::Windivert => windivert::start(config, metrics, stop, upstream.clone()),
        }?;
        Ok(Box::new(WithUpstream { driver, upstream }))
    }
    #[cfg(not(windows))]
    {
        let _ = (config, metrics, stop);
        anyhow::bail!("Traffic interception requires Windows x64");
    }
}
