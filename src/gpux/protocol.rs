//! GPUX/1 wire format, compatible with the reference C++ implementation.
//!
//! Sequence numbers are 48-bit big-endian values. The entire outer header is
//! authenticated; client and server use separate nonce domains (0 and 1).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, bail, ensure, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use sha2::{Digest, Sha256};

pub const OUTER_HEADER_SIZE: usize = 47;
pub const AUTH_TAG_SIZE: usize = 16;
pub const INNER_LEGACY_HEADER_SIZE: usize = 8;
pub const INNER_EXTENDED_HEADER_SIZE: usize = 13;
pub const MAX_PACKET_SIZE: usize = 65_507;
pub const MAX_PACKET_SEQ: u64 = (1 << 48) - 1;
const PLAINTEXT_FLAG: u8 = 1;
const ENCRYPTED_FLAG: u8 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Chlo = 1,
    Data = 3,
    Ack = 4,
    Parity = 5,
    FlowOpen = 10,
    FlowClose = 11,
    #[default]
    Close = 13,
}

impl TryFrom<u8> for PacketType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Chlo),
            3 => Ok(Self::Data),
            4 => Ok(Self::Ack),
            5 => Ok(Self::Parity),
            10 => Ok(Self::FlowOpen),
            11 => Ok(Self::FlowClose),
            13 => Ok(Self::Close),
            _ => bail!("unsupported GPUX packet type"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Packet {
    pub packet_type: PacketType,
    pub path_id: u8,
    pub connection_id: u64,
    pub packet_seq: u64,
    pub send_time_us: u32,
    pub ack_base: u64,
    pub ack_bitmap: u64,
    pub fec_group_id: u32,
    pub fec_k: u8,
    pub fec_n: u8,
    pub fec_index: u8,
    pub payload: Vec<u8>,
}

// Do not derive Debug: this material is derived from the authentication token.
#[derive(Clone)]
pub struct AeadKey {
    key: [u8; 32],
    nonce_salt: [u8; 4],
}

pub fn derive_key(token: &str, connection_id: u64) -> Result<AeadKey> {
    ensure!(
        !token.is_empty(),
        "encrypted GPUX requires a non-empty token"
    );
    ensure!(token.len() <= 255, "GPUX token exceeds 255 bytes");
    let hash = |label: &[u8]| -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(label);
        digest.update(token.as_bytes());
        digest.update(connection_id.to_be_bytes());
        digest.finalize().into()
    };
    let key = hash(b"GUPA-RT/1.0 key");
    let salt_hash = hash(b"GUPA-RT/1.0 nonce");
    let mut nonce_salt = [0; 4];
    nonce_salt.copy_from_slice(&salt_hash[..4]);
    Ok(AeadKey { key, nonce_salt })
}

fn nonce(key: &AeadKey, domain: u8, path_id: u8, packet_seq: u64) -> [u8; 12] {
    let mut result = [0; 12];
    result[..4].copy_from_slice(&key.nonce_salt);
    result[4] = domain;
    result[5] = path_id;
    result[6..].copy_from_slice(&packet_seq.to_be_bytes()[2..]);
    result
}

fn validate_packet(packet: &Packet) -> Result<()> {
    ensure!(
        packet.packet_seq <= MAX_PACKET_SEQ,
        "GPUX sequence exhausted"
    );
    ensure!(
        packet.ack_base <= MAX_PACKET_SEQ,
        "GPUX ACK base exceeds 48 bits"
    );
    ensure!(
        packet.payload.len() <= MAX_PACKET_SIZE - OUTER_HEADER_SIZE - AUTH_TAG_SIZE,
        "GPUX packet exceeds maximum UDP datagram size"
    );
    if packet.fec_group_id == 0 {
        ensure!(
            packet.fec_k == 0 && packet.fec_n == 0 && packet.fec_index == 0,
            "FEC fields without a group"
        );
        ensure!(
            packet.packet_type != PacketType::Parity,
            "PARITY without a FEC group"
        );
    } else {
        ensure!(
            packet.fec_k > 0 && packet.fec_k.checked_add(1) == Some(packet.fec_n),
            "unsupported GPUX XOR FEC dimensions"
        );
        match packet.packet_type {
            PacketType::Data => {
                ensure!(packet.fec_index < packet.fec_k, "invalid FEC source index")
            }
            PacketType::Parity => {
                ensure!(packet.fec_index == packet.fec_k, "invalid FEC parity index")
            }
            _ => bail!("FEC metadata on a control packet"),
        }
    }
    Ok(())
}

pub fn encode(packet: &Packet, key: Option<&AeadKey>, nonce_domain: u8) -> Result<Vec<u8>> {
    validate_packet(packet)?;
    let mut wire = Vec::with_capacity(OUTER_HEADER_SIZE + packet.payload.len() + AUTH_TAG_SIZE);
    wire.extend_from_slice(b"GPUX");
    wire.extend_from_slice(&[
        1,
        packet.packet_type as u8,
        if key.is_some() {
            ENCRYPTED_FLAG
        } else {
            PLAINTEXT_FLAG
        },
        packet.path_id,
    ]);
    wire.extend_from_slice(&packet.connection_id.to_be_bytes());
    append_u48(&mut wire, packet.packet_seq);
    wire.extend_from_slice(&packet.send_time_us.to_be_bytes());
    append_u48(&mut wire, packet.ack_base);
    wire.extend_from_slice(&packet.ack_bitmap.to_be_bytes());
    wire.extend_from_slice(&packet.fec_group_id.to_be_bytes());
    wire.extend_from_slice(&[packet.fec_k, packet.fec_n, packet.fec_index]);
    if let Some(key) = key {
        let cipher = ChaCha20Poly1305::new((&key.key).into());
        let nonce = nonce(key, nonce_domain, packet.path_id, packet.packet_seq);
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &packet.payload,
                    aad: &wire,
                },
            )
            .map_err(|_| anyhow!("GPUX encryption failed"))?;
        // RustCrypto appends the 16-byte tag, matching the donor outer format.
        wire.extend_from_slice(&encrypted);
    } else {
        wire.extend_from_slice(&packet.payload);
        wire.extend_from_slice(&[0; AUTH_TAG_SIZE]);
    }
    Ok(wire)
}

pub fn decode(wire: &[u8], key: Option<&AeadKey>, nonce_domain: u8) -> Result<Packet> {
    ensure!(
        wire.len() >= OUTER_HEADER_SIZE + AUTH_TAG_SIZE,
        "short GPUX packet"
    );
    ensure!(wire.len() <= MAX_PACKET_SIZE, "oversized GPUX packet");
    let mut reader = Reader::new(wire);
    ensure!(reader.take(4)? == b"GPUX", "invalid GPUX magic");
    ensure!(reader.u8()? == 1, "unsupported GPUX version");
    let packet_type = PacketType::try_from(reader.u8()?)?;
    let flags = reader.u8()?;
    ensure!(
        flags
            == if key.is_some() {
                ENCRYPTED_FLAG
            } else {
                PLAINTEXT_FLAG
            },
        "GPUX encryption profile mismatch"
    );
    let mut packet = Packet {
        packet_type,
        path_id: reader.u8()?,
        connection_id: reader.u64()?,
        packet_seq: reader.u48()?,
        send_time_us: reader.u32()?,
        ack_base: reader.u48()?,
        ack_bitmap: reader.u64()?,
        fec_group_id: reader.u32()?,
        fec_k: reader.u8()?,
        fec_n: reader.u8()?,
        fec_index: reader.u8()?,
        payload: Vec::new(),
    };
    if let Some(key) = key {
        let cipher = ChaCha20Poly1305::new((&key.key).into());
        let nonce = nonce(key, nonce_domain, packet.path_id, packet.packet_seq);
        packet.payload = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &wire[OUTER_HEADER_SIZE..],
                    aad: &wire[..OUTER_HEADER_SIZE],
                },
            )
            .map_err(|_| anyhow!("GPUX authentication failed"))?;
    } else {
        let payload_end = wire.len() - AUTH_TAG_SIZE;
        ensure!(
            wire[payload_end..].iter().all(|byte| *byte == 0),
            "invalid GPUX plaintext tag"
        );
        packet
            .payload
            .extend_from_slice(&wire[OUTER_HEADER_SIZE..payload_end]);
    }
    validate_packet(&packet)?;
    Ok(packet)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Chlo {
    pub connection_id: u64,
    pub timestamp_us: u64,
    pub token: String,
}

pub fn encode_chlo(connection_id: u64, token: &str, now_us: u64) -> Result<Vec<u8>> {
    ensure!(token.len() <= 255, "GPUX token exceeds 255 bytes");
    let mut payload = Vec::with_capacity(17 + token.len());
    payload.extend_from_slice(&connection_id.to_be_bytes());
    payload.extend_from_slice(&now_us.to_be_bytes());
    payload.push(token.len() as u8);
    payload.extend_from_slice(token.as_bytes());
    Ok(payload)
}

pub fn decode_chlo(payload: &[u8]) -> Result<Chlo> {
    let mut reader = Reader::new(payload);
    let connection_id = reader.u64()?;
    let timestamp_us = reader.u64()?;
    let token_len = reader.u8()? as usize;
    let token = std::str::from_utf8(reader.take(token_len)?)?.to_owned();
    reader.finish()?;
    Ok(Chlo {
        connection_id,
        timestamp_us,
        token,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub struct FlowOpen {
    pub flow_id: u32,
    pub target: SocketAddr,
    pub creation_time_us: u64,
    pub profile: String,
}

pub fn encode_flow_open(
    flow_id: u32,
    target: SocketAddr,
    now_us: u64,
    profile: &str,
) -> Result<Vec<u8>> {
    ensure!(profile.len() <= 255, "GPUX profile exceeds 255 bytes");
    let mut payload = Vec::with_capacity(33 + profile.len());
    payload.extend_from_slice(&flow_id.to_be_bytes());
    payload.push(17); // IPPROTO_UDP
    payload.push(if target.is_ipv4() { 1 } else { 4 });
    payload.extend_from_slice(&target.port().to_be_bytes());
    match target.ip() {
        IpAddr::V4(ip) => payload.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => payload.extend_from_slice(&ip.octets()),
    }
    payload.extend_from_slice(&now_us.to_be_bytes());
    payload.push(profile.len() as u8);
    payload.extend_from_slice(profile.as_bytes());
    Ok(payload)
}

pub fn decode_flow_open(payload: &[u8]) -> Result<FlowOpen> {
    let mut reader = Reader::new(payload);
    let flow_id = reader.u32()?;
    ensure!(reader.u8()? == 17, "GPUX supports only UDP flows");
    let address_type = reader.u8()?;
    let port = reader.u16()?;
    let ip = match address_type {
        1 => IpAddr::V4(Ipv4Addr::from(reader.array::<4>()?)),
        4 => IpAddr::V6(Ipv6Addr::from(reader.array::<16>()?)),
        _ => bail!("unsupported GPUX FLOW_OPEN address type"),
    };
    let creation_time_us = reader.u64()?;
    let profile_len = reader.u8()? as usize;
    let profile = std::str::from_utf8(reader.take(profile_len)?)?.to_owned();
    reader.finish()?;
    Ok(FlowOpen {
        flow_id,
        target: SocketAddr::new(ip, port),
        creation_time_us,
        profile,
    })
}

pub fn encode_flow_close(flow_id: u32, reason: u8) -> Vec<u8> {
    let mut payload = flow_id.to_be_bytes().to_vec();
    payload.push(reason);
    payload
}

pub fn decode_flow_close(payload: &[u8]) -> Result<(u32, u8)> {
    let mut reader = Reader::new(payload);
    let flow_id = reader.u32()?;
    let reason = reader.u8()?;
    reader.finish()?;
    Ok((flow_id, reason))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InnerDatagram {
    pub flow_id: u32,
    pub direction: u8,
    pub deadline_class: u8,
    pub ttl_us: Option<u32>,
    pub payload: Vec<u8>,
}

pub fn encode_inner(
    flow_id: u32,
    direction: u8,
    deadline_class: u8,
    ttl_us: Option<u32>,
    payload: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= u16::MAX as usize,
        "oversized GPUX inner datagram"
    );
    ensure!(direction <= 1, "invalid GPUX inner direction");
    ensure!(
        ttl_us.is_some() || deadline_class != 0,
        "legacy deadline class 0 is reserved"
    );
    let header_size = if ttl_us.is_some() {
        INNER_EXTENDED_HEADER_SIZE
    } else {
        INNER_LEGACY_HEADER_SIZE
    };
    let mut inner = Vec::with_capacity(header_size + payload.len());
    inner.extend_from_slice(&flow_id.to_be_bytes());
    inner.push(direction);
    inner.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    if let Some(ttl_us) = ttl_us {
        inner.extend_from_slice(&[0, deadline_class]);
        inner.extend_from_slice(&ttl_us.to_be_bytes());
    } else {
        inner.push(deadline_class);
    }
    inner.extend_from_slice(payload);
    Ok(inner)
}

pub fn decode_inners(payload: &[u8]) -> Result<Vec<InnerDatagram>> {
    ensure!(
        payload.len() <= MAX_PACKET_SIZE,
        "oversized GPUX DATA payload"
    );
    let mut reader = Reader::new(payload);
    let mut inners = Vec::new();
    while !reader.remaining().is_empty() {
        let flow_id = reader.u32()?;
        let direction = reader.u8()?;
        ensure!(direction <= 1, "invalid GPUX inner direction");
        let payload_len = reader.u16()? as usize;
        let mut deadline_class = reader.u8()?;
        let ttl_us = if deadline_class == 0 {
            deadline_class = reader.u8()?;
            Some(reader.u32()?)
        } else {
            None
        };
        let payload = reader.take(payload_len)?.to_vec();
        inners.push(InnerDatagram {
            flow_id,
            direction,
            deadline_class,
            ttl_us,
            payload,
        });
    }
    Ok(inners)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FecSource {
    pub fec_index: u8,
    pub packet_seq: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FecSourceInfo {
    pub fec_index: u8,
    pub packet_seq: u64,
    pub payload_len: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FecParity {
    pub sources: Vec<FecSourceInfo>,
    pub parity_bytes: Vec<u8>,
}

fn validate_fec(parity: &FecParity) -> Result<()> {
    ensure!(
        !parity.sources.is_empty() && parity.sources.len() <= 255,
        "invalid FEC source count"
    );
    let mut indices = [false; 256];
    for (offset, info) in parity.sources.iter().enumerate() {
        ensure!(
            !indices[info.fec_index as usize],
            "duplicate FEC source index"
        );
        indices[info.fec_index as usize] = true;
        ensure!(
            info.packet_seq <= MAX_PACKET_SEQ,
            "FEC sequence exceeds 48 bits"
        );
        ensure!(
            !parity.sources[..offset]
                .iter()
                .any(|other| other.packet_seq == info.packet_seq),
            "duplicate FEC source sequence"
        );
        ensure!(
            info.payload_len as usize <= parity.parity_bytes.len(),
            "FEC source exceeds parity length"
        );
    }
    let maximum_len = parity
        .sources
        .iter()
        .map(|info| info.payload_len as usize)
        .max()
        .unwrap_or(0);
    ensure!(
        maximum_len == parity.parity_bytes.len(),
        "invalid FEC parity length"
    );
    ensure!(
        4 + parity.sources.len() * 9 + parity.parity_bytes.len()
            <= MAX_PACKET_SIZE - OUTER_HEADER_SIZE - AUTH_TAG_SIZE,
        "oversized FEC parity payload"
    );
    Ok(())
}

pub fn encode_fec(sources: &[FecSource]) -> Result<Vec<u8>> {
    ensure!(
        !sources.is_empty() && sources.len() <= 255,
        "invalid FEC source count"
    );
    let parity_len = sources
        .iter()
        .map(|source| source.payload.len())
        .max()
        .unwrap_or(0);
    ensure!(
        parity_len <= u16::MAX as usize,
        "oversized FEC source payload"
    );
    let mut parity = FecParity {
        sources: Vec::with_capacity(sources.len()),
        parity_bytes: vec![0; parity_len],
    };
    for source in sources {
        parity.sources.push(FecSourceInfo {
            fec_index: source.fec_index,
            packet_seq: source.packet_seq,
            payload_len: source.payload.len() as u16,
        });
        for (parity_byte, source_byte) in parity.parity_bytes.iter_mut().zip(&source.payload) {
            *parity_byte ^= source_byte;
        }
    }
    validate_fec(&parity)?;
    let mut payload = Vec::with_capacity(4 + sources.len() * 9 + parity_len);
    payload.extend_from_slice(&[1, sources.len() as u8]);
    for info in parity.sources {
        payload.push(info.fec_index);
        append_u48(&mut payload, info.packet_seq);
        payload.extend_from_slice(&info.payload_len.to_be_bytes());
    }
    payload.extend_from_slice(&(parity_len as u16).to_be_bytes());
    payload.extend_from_slice(&parity.parity_bytes);
    Ok(payload)
}

pub fn decode_fec(payload: &[u8]) -> Result<FecParity> {
    ensure!(payload.len() <= MAX_PACKET_SIZE, "oversized FEC payload");
    let mut reader = Reader::new(payload);
    ensure!(reader.u8()? == 1, "unsupported FEC parity version");
    let source_count = reader.u8()? as usize;
    ensure!(source_count > 0, "empty FEC parity group");
    let mut sources = Vec::with_capacity(source_count);
    for _ in 0..source_count {
        sources.push(FecSourceInfo {
            fec_index: reader.u8()?,
            packet_seq: reader.u48()?,
            payload_len: reader.u16()?,
        });
    }
    let parity_len = reader.u16()? as usize;
    let parity_bytes = reader.take(parity_len)?.to_vec();
    reader.finish()?;
    let parity = FecParity {
        sources,
        parity_bytes,
    };
    validate_fec(&parity)?;
    Ok(parity)
}

/// Recovers exactly one missing source. Partial groups use the parity metadata,
/// even when earlier DATA headers advertised a larger group before a flush.
pub fn recover_fec(parity: &FecParity, known_sources: &[FecSource]) -> Result<Option<FecSource>> {
    validate_fec(parity)?;
    let mut recovered = parity.parity_bytes.clone();
    let mut missing: Option<&FecSourceInfo> = None;
    let mut missing_count = 0;
    for info in &parity.sources {
        let mut matched = known_sources
            .iter()
            .filter(|source| source.fec_index == info.fec_index);
        if let Some(source) = matched.next() {
            ensure!(matched.next().is_none(), "duplicate known FEC source");
            ensure!(
                source.packet_seq == info.packet_seq,
                "FEC source sequence mismatch"
            );
            ensure!(
                source.payload.len() == info.payload_len as usize,
                "FEC source length mismatch"
            );
            for (parity_byte, source_byte) in recovered.iter_mut().zip(&source.payload) {
                *parity_byte ^= source_byte;
            }
        } else {
            missing = Some(info);
            missing_count += 1;
        }
    }
    if missing_count != 1 {
        return Ok(None);
    }
    if let Some(info) = missing {
        recovered.truncate(info.payload_len as usize);
        Ok(Some(FecSource {
            fec_index: info.fec_index,
            packet_seq: info.packet_seq,
            payload: recovered,
        }))
    } else {
        Ok(None)
    }
}

fn append_u48(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes()[2..]);
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn remaining(&self) -> &'a [u8] {
        self.remaining
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        ensure!(length <= self.remaining.len(), "truncated GPUX payload");
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        bytes.copy_from_slice(self.take(N)?);
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u48(&mut self) -> Result<u64> {
        let mut bytes = [0; 8];
        bytes[2..].copy_from_slice(self.take(6)?);
        Ok(u64::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<()> {
        ensure!(self.remaining.is_empty(), "trailing bytes in GPUX payload");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated by compiling the unmodified donor gpux_protocol.cpp with MSVC
    // and fixing only the caller-supplied header timestamp to 0x11223344.
    const PLAIN: &str = "47505558010301020000000000001234000000000008112233440000000000070000000000000003000000000000000000000900000208686900000000000000000000000000000000";
    const ENCRYPTED_UP: &str = "4750555801030202000000000000123400000000000811223344000000000007000000000000000300000000000000b98e7c074bb3284a3347c0271b0eafbcb2271af740519ce6fb04";
    const ENCRYPTED_DOWN: &str = "47505558010302020000000000001234000000000008112233440000000000070000000000000003000000000000003165a50314eb9086407ea585232d7bed6bbab2d0259306914137";
    const FEC: &str =
        "01040000000000000a00030100000000000b00020200000000000c00040300000000000d0001000409600b69";

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
            .collect()
    }

    fn packet() -> Packet {
        Packet {
            packet_type: PacketType::Data,
            path_id: 2,
            connection_id: 0x1234,
            packet_seq: 8,
            send_time_us: 0x11223344,
            ack_base: 7,
            ack_bitmap: 3,
            payload: encode_inner(9, 0, 8, None, b"hi").unwrap(),
            ..Packet::default()
        }
    }

    fn sources() -> Vec<FecSource> {
        [b"abc".as_slice(), b"de", b"fghi", b"j"]
            .into_iter()
            .enumerate()
            .map(|(index, payload)| FecSource {
                fec_index: index as u8,
                packet_seq: 10 + index as u64,
                payload: payload.to_vec(),
            })
            .collect()
    }

    #[test]
    fn donor_plaintext_and_crypto_vectors_match_exactly() {
        let packet = packet();
        assert_eq!(encode(&packet, None, 0).unwrap(), bytes(PLAIN));
        assert_eq!(decode(&bytes(PLAIN), None, 0).unwrap(), packet);
        let key = derive_key("secret-token", 0x1234).unwrap();
        assert_eq!(
            key.key.to_vec(),
            bytes("94c811e751cf92f0f39c354f172c20c8988e42bdcef17c5197ea95e444c72aa5")
        );
        assert_eq!(key.nonce_salt.to_vec(), bytes("24954509"));
        assert_eq!(encode(&packet, Some(&key), 0).unwrap(), bytes(ENCRYPTED_UP));
        assert_eq!(
            encode(&packet, Some(&key), 1).unwrap(),
            bytes(ENCRYPTED_DOWN)
        );
        assert_eq!(decode(&bytes(ENCRYPTED_UP), Some(&key), 0).unwrap(), packet);
        assert_eq!(
            decode(&bytes(ENCRYPTED_DOWN), Some(&key), 1).unwrap(),
            packet
        );
    }

    #[test]
    fn encryption_rejects_tampering_wrong_token_and_downgrades() {
        let key = derive_key("secret-token", 0x1234).unwrap();
        let wrong_key = derive_key("wrong-token", 0x1234).unwrap();
        let wire = bytes(ENCRYPTED_UP);
        assert!(decode(&wire, Some(&key), 1).is_err());
        assert!(decode(&wire, Some(&wrong_key), 0).is_err());
        assert!(decode(&wire, None, 0).is_err());
        assert!(decode(&bytes(PLAIN), Some(&key), 0).is_err());
        for index in [5, 7, 8, 16, 22, 26, 32, 47, wire.len() - 1] {
            let mut changed = wire.clone();
            changed[index] ^= 1;
            assert!(
                decode(&changed, Some(&key), 0).is_err(),
                "accepted tampering at {index}"
            );
        }
        assert!(derive_key("", 1).is_err());
        assert!(derive_key(&"t".repeat(256), 1).is_err());
    }

    #[test]
    fn ack_fields_preserve_the_full_48_bit_sequence_and_64_bit_bitmap() {
        let packet = Packet {
            packet_type: PacketType::Ack,
            connection_id: 1,
            packet_seq: MAX_PACKET_SEQ,
            ack_base: MAX_PACKET_SEQ - 1,
            ack_bitmap: u64::MAX,
            ..Packet::default()
        };
        assert_eq!(
            decode(&encode(&packet, None, 0).unwrap(), None, 0).unwrap(),
            packet
        );
        let mut invalid = packet.clone();
        invalid.packet_seq += 1;
        assert!(encode(&invalid, None, 0).is_err());
        invalid = packet;
        invalid.ack_base = MAX_PACKET_SEQ + 1;
        assert!(encode(&invalid, None, 0).is_err());
    }

    #[test]
    fn donor_flow_open_ipv4_and_ipv6_vectors_match() {
        let cases = [
            (9, "127.0.0.1:30000", 1, "00000009110175307f00000100000000000000010a6f70617175655f667073"),
            (10, "[2001:db8::1]:443", 2, "0000000a110401bb20010db800000000000000000000000100000000000000020a6f70617175655f667073"),
        ];
        for (flow_id, target, creation_time_us, expected) in cases {
            let target = target.parse().unwrap();
            let payload =
                encode_flow_open(flow_id, target, creation_time_us, "opaque_fps").unwrap();
            assert_eq!(payload, bytes(expected));
            assert_eq!(
                decode_flow_open(&payload).unwrap(),
                FlowOpen {
                    flow_id,
                    target,
                    creation_time_us,
                    profile: "opaque_fps".into()
                }
            );
            for end in 0..payload.len() {
                assert!(decode_flow_open(&payload[..end]).is_err());
            }
            let mut trailing = payload;
            trailing.push(0);
            assert!(decode_flow_open(&trailing).is_err());
        }
    }

    #[test]
    fn chlo_and_flow_close_require_complete_metadata() {
        let wire = encode_chlo(0x1234, "token", 7).unwrap();
        assert_eq!(wire, bytes("0000000000001234000000000000000705746f6b656e"));
        assert_eq!(
            decode_chlo(&wire).unwrap(),
            Chlo {
                connection_id: 0x1234,
                timestamp_us: 7,
                token: "token".into()
            }
        );
        for end in 0..wire.len() {
            assert!(decode_chlo(&wire[..end]).is_err());
        }
        assert!(encode_chlo(1, &"x".repeat(256), 1).is_err());
        let wire = encode_flow_close(9, 2);
        assert_eq!(wire, bytes("0000000902"));
        assert_eq!(decode_flow_close(&wire).unwrap(), (9, 2));
        assert!(decode_flow_close(&wire[..4]).is_err());
        assert!(decode_flow_close(&[0, 0, 0, 9, 2, 0]).is_err());
    }

    #[test]
    fn mixed_legacy_and_extended_deadlines_match_donor_vectors() {
        let legacy = encode_inner(9, 0, 8, None, b"hi").unwrap();
        let extended = encode_inner(10, 1, 6, Some(1234), b"hi").unwrap();
        assert_eq!(legacy, bytes("00000009000002086869"));
        assert_eq!(extended, bytes("0000000a0100020006000004d26869"));
        let joined = [legacy.clone(), extended.clone()].concat();
        assert_eq!(
            decode_inners(&joined).unwrap(),
            vec![
                InnerDatagram {
                    flow_id: 9,
                    direction: 0,
                    deadline_class: 8,
                    ttl_us: None,
                    payload: b"hi".to_vec()
                },
                InnerDatagram {
                    flow_id: 10,
                    direction: 1,
                    deadline_class: 6,
                    ttl_us: Some(1234),
                    payload: b"hi".to_vec()
                },
            ]
        );
        for wire in [legacy, extended] {
            for end in 1..wire.len() {
                assert!(decode_inners(&wire[..end]).is_err());
            }
            assert!(decode_inners(&[wire, vec![0]].concat()).is_err());
        }
        assert!(encode_inner(1, 2, 8, None, b"").is_err());
        assert!(encode_inner(1, 0, 0, None, b"").is_err());
        assert!(encode_inner(1, 0, 8, None, &vec![0; 65_536]).is_err());
        assert_eq!(
            decode_inners(&encode_inner(1, 0, 8, Some(0), b"").unwrap()).unwrap()[0].ttl_us,
            Some(0)
        );
    }

    #[test]
    fn donor_xor_fec_recovers_each_missing_source_and_partial_groups() {
        let sources = sources();
        let payload = encode_fec(&sources).unwrap();
        assert_eq!(payload, bytes(FEC));
        let parity = decode_fec(&payload).unwrap();
        for index in 0..sources.len() {
            let known: Vec<_> = sources
                .iter()
                .enumerate()
                .filter(|(offset, _)| *offset != index)
                .map(|(_, source)| source.clone())
                .collect();
            assert_eq!(
                recover_fec(&parity, &known).unwrap(),
                Some(sources[index].clone())
            );
        }
        assert!(recover_fec(&parity, &sources).unwrap().is_none());
        assert!(recover_fec(&parity, &sources[..2]).unwrap().is_none());
        let partial = encode_fec(&sources[..1]).unwrap();
        assert_eq!(partial, bytes("01010000000000000a00030003616263"));
        assert_eq!(
            recover_fec(&decode_fec(&partial).unwrap(), &[]).unwrap(),
            Some(sources[0].clone())
        );

        // A source can advertise 4+1 before a timer flush produces 1+1 parity.
        let data_packet = Packet {
            fec_group_id: 7,
            fec_k: 4,
            fec_n: 5,
            fec_index: 0,
            ..packet()
        };
        let parity_packet = Packet {
            packet_type: PacketType::Parity,
            fec_group_id: 7,
            fec_k: 1,
            fec_n: 2,
            fec_index: 1,
            payload: partial,
            ..packet()
        };
        assert!(decode(&encode(&data_packet, None, 0).unwrap(), None, 0).is_ok());
        assert!(decode(&encode(&parity_packet, None, 0).unwrap(), None, 0).is_ok());
    }

    #[test]
    fn fec_rejects_inconsistent_metadata_and_malformed_lengths() {
        let payload = bytes(FEC);
        for end in 0..payload.len() {
            assert!(decode_fec(&payload[..end]).is_err());
        }
        let mut duplicated = payload.clone();
        duplicated[11] = duplicated[2];
        assert!(decode_fec(&duplicated).is_err());
        let mut too_long = payload.clone();
        too_long[10] = 255;
        assert!(decode_fec(&too_long).is_err());
        assert!(decode_fec(&[payload.clone(), vec![0]].concat()).is_err());
        assert!(encode_fec(&[]).is_err());
        let parity = decode_fec(&payload).unwrap();
        let mut known = sources();
        known[0].packet_seq += 1;
        assert!(recover_fec(&parity, &known[..3]).is_err());
        known = sources();
        known[0].payload.pop();
        assert!(recover_fec(&parity, &known[..3]).is_err());
        known = sources();
        known.push(known[0].clone());
        assert!(recover_fec(&parity, &known).is_err());
    }

    #[test]
    fn malformed_outer_packets_are_bounded_and_rejected() {
        let wire = bytes(PLAIN);
        for end in 0..OUTER_HEADER_SIZE + AUTH_TAG_SIZE {
            assert!(decode(&wire[..end], None, 0).is_err());
        }
        for (index, value) in [
            (0, 0),
            (4, 99),
            (5, 99),
            (6, 3),
            (44, 1),
            (wire.len() - 1, 1),
        ] {
            let mut changed = wire.clone();
            changed[index] = value;
            assert!(decode(&changed, None, 0).is_err());
        }
        assert!(decode(&vec![0; MAX_PACKET_SIZE + 1], None, 0).is_err());
        let invalid = Packet {
            payload: vec![0; MAX_PACKET_SIZE],
            ..packet()
        };
        assert!(encode(&invalid, None, 0).is_err());
    }
}
