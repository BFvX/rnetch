//! Bounds-checked packet parsing and TCP reflection. All wire fields use network order.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct Flow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Packet {
    pub flow: Flow,
    pub protocol: u8,
    pub transport: usize,
    pub payload: usize,
    pub length: usize,
    pub tcp_flags: u8,
    pub tcp_sequence: u32,
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

impl Packet {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let (local, remote, mut protocol, mut transport, length) = match bytes.first()? >> 4 {
            4 => {
                if bytes.len() < 20 {
                    return None;
                }
                let header = (bytes[0] as usize & 15) * 4;
                let length = word(bytes, 2) as usize;
                // Never interpret a fragment as an independent transport packet.
                if header < 20
                    || length < header
                    || length > bytes.len()
                    || word(bytes, 6) & 0x3fff != 0
                {
                    return None;
                }
                (
                    IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                    IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                    bytes[9],
                    header,
                    length,
                )
            }
            6 => {
                if bytes.len() < 40 {
                    return None;
                }
                let length = 40 + word(bytes, 4) as usize;
                if length > bytes.len() || length == 40 {
                    return None;
                }
                (
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)),
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?)),
                    bytes[6],
                    40,
                    length,
                )
            }
            _ => return None,
        };
        // RFC 8200 hop-by-hop, routing and destination option extension headers.
        for _ in 0..16 {
            if !matches!(protocol, 0 | 43 | 60) {
                break;
            }
            if transport + 2 > length {
                return None;
            }
            let next = bytes[transport];
            transport += (bytes[transport + 1] as usize + 1) * 8;
            if transport > length {
                return None;
            }
            protocol = next;
        }
        let (payload, tcp_flags) = match protocol {
            6 => {
                if transport + 20 > length {
                    return None;
                }
                let header = (bytes[transport + 12] as usize >> 4) * 4;
                if header < 20 || transport + header > length {
                    return None;
                }
                (transport + header, bytes[transport + 13])
            }
            17 => {
                if transport + 8 > length {
                    return None;
                }
                let udp_length = word(bytes, transport + 4) as usize;
                if udp_length < 8 || transport + udp_length != length {
                    return None;
                }
                (transport + 8, 0)
            }
            _ => return None,
        };
        Some(Self {
            flow: Flow {
                local: SocketAddr::new(local, word(bytes, transport)),
                remote: SocketAddr::new(remote, word(bytes, transport + 2)),
            },
            protocol,
            transport,
            payload,
            length,
            tcp_flags,
            tcp_sequence: if protocol == 6 {
                u32::from_be_bytes(bytes[transport + 4..transport + 8].try_into().ok()?)
            } else {
                0
            },
        })
    }

    pub fn initial_syn(&self) -> bool {
        self.protocol == 6 && self.tcp_flags & 0x12 == 0x02
    }

    /// Swap IPs and set transport ports; caller recalculates checksums and injects inbound.
    pub fn reflect(&self, bytes: &mut [u8], source_port: u16, destination_port: u16) {
        let (source, destination, size) = if self.flow.local.is_ipv4() {
            (12, 16, 4)
        } else {
            (8, 24, 16)
        };
        for offset in 0..size {
            bytes.swap(source + offset, destination + offset);
        }
        bytes[self.transport..self.transport + 2].copy_from_slice(&source_port.to_be_bytes());
        bytes[self.transport + 2..self.transport + 4]
            .copy_from_slice(&destination_port.to_be_bytes());
    }
}

/// Build a fresh datagram rather than copying stale IPv4 options / IPv6 extensions.
pub(super) fn udp_reply(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let header = if source.is_ipv4() && destination.is_ipv4() {
        20
    } else if source.is_ipv6() && destination.is_ipv6() {
        40
    } else {
        return None;
    };
    let length = header + 8 + payload.len();
    if length > 65535 {
        return None;
    }
    let mut bytes = vec![0; length];
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&(length as u16).to_be_bytes());
            bytes[8] = 64;
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&source.octets());
            bytes[16..20].copy_from_slice(&destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
            bytes[6] = 17;
            bytes[7] = 64;
            bytes[8..24].copy_from_slice(&source.octets());
            bytes[24..40].copy_from_slice(&destination.octets());
        }
        _ => return None,
    }
    bytes[header..header + 2].copy_from_slice(&source.port().to_be_bytes());
    bytes[header + 2..header + 4].copy_from_slice(&destination.port().to_be_bytes());
    bytes[header + 4..header + 6].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    bytes[header + 8..].copy_from_slice(payload);
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_round_trip_both_families() {
        for (source, destination) in [
            ("8.8.8.8:53", "192.0.2.1:50000"),
            ("[2001:4860::1]:53", "[2001:db8::1]:50000"),
        ] {
            let source: SocketAddr = source.parse().unwrap();
            let destination: SocketAddr = destination.parse().unwrap();
            let bytes = udp_reply(source, destination, b"payload").unwrap();
            let packet = Packet::parse(&bytes).unwrap();
            assert_eq!(
                packet.flow,
                Flow {
                    local: source,
                    remote: destination
                }
            );
            assert_eq!(&bytes[packet.payload..packet.length], b"payload");
            for length in 0..bytes.len() {
                assert!(Packet::parse(&bytes[..length]).is_none());
            }
        }
    }

    #[test]
    fn reject_fragments_and_invalid_udp_length() {
        let mut bytes = udp_reply(
            "8.8.8.8:53".parse().unwrap(),
            "192.0.2.1:9".parse().unwrap(),
            b"x",
        )
        .unwrap();
        bytes[6] = 0x20;
        assert!(Packet::parse(&bytes).is_none());
        bytes[6] = 0;
        bytes[25] = 7;
        assert!(Packet::parse(&bytes).is_none());
        assert!(udp_reply(
            "8.8.8.8:53".parse().unwrap(),
            "[::1]:9".parse().unwrap(),
            b"x"
        )
        .is_none());
    }

    #[test]
    fn tcp_reflection_is_reversible_and_preserves_payload() {
        for (source, destination) in [
            ("192.0.2.1:50000", "8.8.8.8:443"),
            ("[2001:db8::1]:50000", "[2001:4860::1]:443"),
        ] {
            let source = source.parse().unwrap();
            let destination = destination.parse().unwrap();
            let mut bytes = udp_reply(source, destination, &[0; 16]).unwrap();
            let header = if source.is_ipv4() {
                bytes[9] = 6;
                20
            } else {
                bytes[6] = 6;
                40
            };
            bytes[header + 12] = 0x50;
            bytes[header + 13] = 2;
            let original = Packet::parse(&bytes).unwrap();
            assert!(original.initial_syn());
            original.reflect(&mut bytes, 12000, 35000);
            let reflected = Packet::parse(&bytes).unwrap();
            assert_eq!(
                reflected.flow.local,
                SocketAddr::new(destination.ip(), 12000)
            );
            assert_eq!(reflected.flow.remote, SocketAddr::new(source.ip(), 35000));
            reflected.reflect(&mut bytes, source.port(), destination.port());
            assert_eq!(Packet::parse(&bytes).unwrap().flow, original.flow);
        }
    }

    #[test]
    fn ipv6_extension_headers_are_checked() {
        let mut bytes = udp_reply(
            "[2001:db8::1]:2".parse().unwrap(),
            "[2001:db8::2]:3".parse().unwrap(),
            b"x",
        )
        .unwrap();
        bytes.splice(40..40, [17, 0, 0, 0, 0, 0, 0, 0]);
        bytes[6] = 60;
        bytes[4..6].copy_from_slice(&17u16.to_be_bytes());
        assert_eq!(Packet::parse(&bytes).unwrap().transport, 48);
        bytes[41] = 255;
        assert!(Packet::parse(&bytes).is_none());
    }
}
