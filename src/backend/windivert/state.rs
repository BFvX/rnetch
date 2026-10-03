use super::packet::Flow;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

pub(super) const MAX_TCP_FLOWS: usize = 1024;
const CLOSED_RETENTION: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug)]
pub(super) struct Mapping {
    pub flow: Flow,
    pub token: u16,
    pub relay_port: u16,
    pub syn_sequence: u32,
    pub accepted: bool,
    pub closed: bool,
    pub touched: Instant,
}

pub(super) struct Nat {
    // Reverse mappings survive reuse of the application tuple. Late relay
    // FIN/RST packets must not escape onto the real network.
    flows: HashMap<Flow, u16>,
    tokens: HashMap<u16, Mapping>,
    next: u16,
}

impl Nat {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            tokens: HashMap::new(),
            next: 1024,
        }
    }

    pub fn get(&mut self, flow: Flow) -> Option<Mapping> {
        let token = self.flows.get(&flow)?;
        let mapping = self.tokens.get_mut(token)?;
        if !mapping.closed {
            mapping.touched = Instant::now();
        }
        Some(*mapping)
    }

    /// Caller revalidates ownership for every SYN. Equal initial sequence numbers
    /// are retransmissions; a changed ISN starts a distinct connection generation.
    pub fn begin(&mut self, flow: Flow, relay_port: u16, syn_sequence: u32) -> Option<Mapping> {
        if let Some(mapping) = self.get(flow) {
            if !mapping.closed && mapping.syn_sequence == syn_sequence {
                return Some(mapping);
            }
        }
        self.forget(flow);
        self.reap();
        if self.tokens.len() >= MAX_TCP_FLOWS {
            return None;
        }
        for _ in 1024..=u16::MAX {
            let token = self.next;
            self.next = if self.next == u16::MAX {
                1024
            } else {
                self.next + 1
            };
            if self.tokens.contains_key(&token) {
                continue;
            }
            let mapping = Mapping {
                flow,
                token,
                relay_port,
                syn_sequence,
                accepted: false,
                closed: false,
                touched: Instant::now(),
            };
            self.flows.insert(flow, token);
            self.tokens.insert(token, mapping);
            return Some(mapping);
        }
        None
    }

    /// Drop the forward route while retaining reverse translation of delayed
    /// packets, so a new unselected process cannot inherit an old connection.
    pub fn forget(&mut self, flow: Flow) {
        self.flows.remove(&flow);
    }

    pub fn reverse(&mut self, local: SocketAddr, peer: SocketAddr) -> Option<Mapping> {
        let mapping = self.tokens.get_mut(&peer.port())?;
        let flow = mapping.flow;
        if flow.remote.ip() != peer.ip()
            || flow.local.ip() != local.ip()
            || mapping.relay_port != local.port()
        {
            return None;
        }
        if !mapping.closed {
            mapping.touched = Instant::now();
        }
        Some(*mapping)
    }

    pub fn accept(&mut self, local: SocketAddr, peer: SocketAddr) -> Option<Mapping> {
        let mapping = self.reverse(local, peer)?;
        if mapping.accepted
            || mapping.closed
            || self.flows.get(&mapping.flow) != Some(&mapping.token)
        {
            return None;
        }
        self.tokens.get_mut(&mapping.token)?.accepted = true;
        Some(mapping)
    }

    pub fn finish(&mut self, mapping: Mapping) {
        if let Some(current) = self.tokens.get_mut(&mapping.token) {
            current.closed = true;
            current.touched = Instant::now();
        }
    }

    pub fn reap(&mut self) {
        self.tokens.retain(|_, mapping| {
            (mapping.accepted && !mapping.closed) || mapping.touched.elapsed() < CLOSED_RETENTION
        });
        self.flows
            .retain(|_, token| self.tokens.contains_key(token));
    }
}

pub(super) fn normalize(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::new(ip.into(), address.port()))
            .unwrap_or(address),
        _ => address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn different_destination_ports_do_not_alias() {
        let mut nat = Nat::new();
        let first = Flow {
            local: "192.0.2.1:50000".parse().unwrap(),
            remote: "8.8.8.8:80".parse().unwrap(),
        };
        let second = Flow {
            remote: "8.8.8.8:443".parse().unwrap(),
            ..first
        };
        let a = nat.begin(first, 40000, 100).unwrap();
        let b = nat.begin(second, 40000, 100).unwrap();
        assert_ne!(a.token, b.token);
        let local = "192.0.2.1:40000".parse().unwrap();
        let peer = SocketAddr::new(first.remote.ip(), a.token);
        assert_eq!(nat.accept(local, peer).unwrap().flow, first);
        assert!(nat.accept(local, peer).is_none());
        assert!(nat
            .reverse("192.0.2.1:40001".parse().unwrap(), peer)
            .is_none());
        assert!(nat
            .reverse(local, SocketAddr::new("9.9.9.9".parse().unwrap(), a.token))
            .is_none());
        nat.finish(a);
        assert_eq!(nat.reverse(local, peer).unwrap().flow, first);
    }

    #[test]
    fn retained_closed_mapping_expires_and_active_mapping_survives() {
        let mut nat = Nat::new();
        let flow = Flow {
            local: "192.0.2.1:1".parse().unwrap(),
            remote: "8.8.8.8:2".parse().unwrap(),
        };
        let mapping = nat.begin(flow, 40000, 100).unwrap();
        let entry = nat.tokens.get_mut(&mapping.token).unwrap();
        entry.touched = Instant::now() - Duration::from_secs(121);
        entry.accepted = true;
        nat.reap();
        assert!(nat.flows.contains_key(&flow));
        nat.tokens.get_mut(&mapping.token).unwrap().closed = true;
        nat.reap();
        assert!(!nat.flows.contains_key(&flow));
        assert!(!nat.tokens.contains_key(&mapping.token));
    }

    #[test]
    fn tuple_reuse_cannot_inherit_a_previous_generation() {
        let mut nat = Nat::new();
        let flow = Flow {
            local: "192.0.2.1:50000".parse().unwrap(),
            remote: "8.8.8.8:443".parse().unwrap(),
        };
        let old = nat.begin(flow, 40000, 100).unwrap();
        assert_eq!(nat.begin(flow, 40000, 100).unwrap().token, old.token);
        let new = nat.begin(flow, 40000, 200).unwrap();
        assert_ne!(old.token, new.token);
        nat.finish(old);
        assert!(!nat.get(flow).unwrap().closed);
        nat.forget(flow);
        assert!(nat.get(flow).is_none());
        assert_eq!(
            nat.reverse(
                "192.0.2.1:40000".parse().unwrap(),
                SocketAddr::new(flow.remote.ip(), old.token)
            )
            .unwrap()
            .token,
            old.token
        );
        assert!(nat
            .accept(
                "192.0.2.1:40000".parse().unwrap(),
                SocketAddr::new(flow.remote.ip(), new.token)
            )
            .is_none());
    }
}
