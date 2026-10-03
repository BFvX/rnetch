//! Driver-neutral UDP sessions. Protocol sockets and liveness stay behind this boundary.
use crate::{
    config::{AppConfig, Socks5Config, UdpTransportKind},
    gpux::{GpuxRuntime, GpuxSession},
    socks5::{self, UdpAssociation},
};
use anyhow::{bail, Result};
use std::{
    io,
    net::{Shutdown, SocketAddr},
    sync::Arc,
    time::Instant,
};

pub enum UdpUpstream {
    Socks5(Socks5Config),
    Gpux(Arc<GpuxRuntime>),
}

impl UdpUpstream {
    pub fn start(config: &AppConfig) -> Result<Self> {
        match config.udp_transport {
            UdpTransportKind::Socks5 => Ok(Self::Socks5(config.socks5.clone())),
            UdpTransportKind::Gpux => Ok(Self::Gpux(GpuxRuntime::start(&config.gpux)?)),
        }
    }

    pub fn open_session(&self) -> Result<UdpSession> {
        match self {
            Self::Socks5(config) => {
                let association = UdpAssociation::connect(config)?;
                association.socket.set_nonblocking(true)?;
                Ok(UdpSession::Socks5(association))
            }
            Self::Gpux(runtime) => Ok(UdpSession::Gpux(runtime.open_session()?)),
        }
    }

    /// Exclude the tunnel server independently of selected process rules.
    pub fn endpoint_addresses(&self) -> Result<Vec<SocketAddr>> {
        match self {
            Self::Socks5(config) => socks5::resolve_proxy(config),
            Self::Gpux(runtime) => Ok(runtime.endpoint_addresses()),
        }
    }

    pub fn stop(&self) {
        if let Self::Gpux(runtime) = self {
            runtime.stop();
        }
    }

    pub fn check_alive(&self) -> Result<()> {
        match self {
            Self::Socks5(_) => Ok(()),
            Self::Gpux(runtime) => runtime.check_alive(),
        }
    }
}

pub enum UdpSession {
    Socks5(UdpAssociation),
    Gpux(GpuxSession),
}

impl UdpSession {
    /// Returns payload bytes accepted; zero means an intentional GPUX deadline/MTU drop.
    pub fn send_to(
        &self,
        payload: &[u8],
        target: SocketAddr,
        captured_at: Instant,
    ) -> Result<usize> {
        match self {
            Self::Socks5(association) => association.send_to(payload, target),
            Self::Gpux(session) => session.send_to(payload, target, captured_at),
        }
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        match self {
            Self::Socks5(association) => association.recv_from(buf),
            Self::Gpux(session) => session.recv_from(buf),
        }
    }

    pub fn check_alive(&self) -> Result<()> {
        match self {
            Self::Socks5(association) => match association.control.peek(&mut [0]) {
                Ok(0) => bail!("SOCKS5 UDP control connection closed"),
                Ok(_) => bail!("Unexpected data on SOCKS5 UDP control connection"),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
                Err(error) => Err(error.into()),
            },
            Self::Gpux(session) => session.check_alive(),
        }
    }

    /// SOCKS5 sockets are registered before sends to prevent recursive interception.
    pub fn local_addresses(&self) -> Result<Vec<SocketAddr>> {
        match self {
            Self::Socks5(association) => Ok(vec![
                association.socket.local_addr()?,
                association.control.local_addr()?,
            ]),
            Self::Gpux(_) => Ok(Vec::new()),
        }
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        if let Self::Socks5(association) = self {
            let _ = association.control.shutdown(Shutdown::Both);
        }
    }
}
