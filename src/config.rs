use anyhow::{bail, ensure, Context, Result};
use std::{fmt, net::IpAddr, path::Path, str::FromStr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackendKind {
    #[default]
    Netfilter,
    Windivert,
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Netfilter => "netfilter",
            Self::Windivert => "windivert",
        })
    }
}

impl FromStr for BackendKind {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "netfilter" => Ok(Self::Netfilter),
            "windivert" => Ok(Self::Windivert),
            _ => bail!("Unknown backend '{value}'; expected netfilter or windivert"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UdpTransportKind {
    #[default]
    Socks5,
    Gpux,
}

impl fmt::Display for UdpTransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Socks5 => "socks5",
            Self::Gpux => "gpux",
        })
    }
}

impl FromStr for UdpTransportKind {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "socks5" => Ok(Self::Socks5),
            "gpux" => Ok(Self::Gpux),
            _ => bail!("Unknown UDP transport '{value}'; expected socks5 or gpux"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GpuxEncryption {
    Plaintext,
    #[default]
    Chacha20Poly1305,
}

impl fmt::Display for GpuxEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Plaintext => "plaintext",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
        })
    }
}

impl FromStr for GpuxEncryption {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plaintext" => Ok(Self::Plaintext),
            "chacha20-poly1305" => Ok(Self::Chacha20Poly1305),
            _ => bail!("GPUX encryption must be plaintext or chacha20-poly1305"),
        }
    }
}

// Deliberately omit Debug: tokens must never be printed by diagnostics.
#[derive(Clone)]
pub struct GpuxConfig {
    pub host: String,
    pub port: u16,
    pub token: String,
    pub encryption: GpuxEncryption,
    pub mtu_payload: u16,
    pub deadline_ms: u32,
    pub batch_window_us: u32,
    pub pacing_interval_us: u32,
    pub queue_limit: usize,
    pub fec_uplink: u8,
    pub fec_group_max_us: u32,
}

impl Default for GpuxConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_owned(),
            port: 40000,
            token: String::new(),
            encryption: GpuxEncryption::default(),
            mtu_payload: 1200,
            deadline_ms: 8,
            batch_window_us: 0,
            pacing_interval_us: 0,
            queue_limit: 512,
            fec_uplink: 0,
            fec_group_max_us: 2000,
        }
    }
}

// Deliberately omit Debug: credentials must never be printed by diagnostics.
#[derive(Clone)]
pub struct Socks5Config {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_owned(),
            port: 1080,
            user: String::new(),
            pass: String::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub process_names: Vec<String>,
    pub accelerate_tcp: bool,
    pub accelerate_udp: bool,
}

#[derive(Clone)]
pub struct AppConfig {
    pub backend: BackendKind,
    pub socks5: Socks5Config,
    pub udp_transport: UdpTransportKind,
    pub gpux: GpuxConfig,
    pub rules: Vec<Rule>,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let xml = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read config {}", path.display()))?;
        Self::from_xml(&xml).with_context(|| format!("Invalid config {}", path.display()))
    }

    pub fn from_xml(xml: &str) -> Result<Self> {
        let doc = roxmltree::Document::parse(xml).context("Invalid XML")?;
        let root = doc.root_element();
        ensure!(root.tag_name().name() == "config", "Missing <config> root");
        for node in root.children().filter(roxmltree::Node::is_element) {
            ensure!(
                ["backend", "socks5", "udp_transport", "gpux", "rules"]
                    .contains(&node.tag_name().name()),
                "Unknown <{}> element",
                node.tag_name().name()
            );
            if !node.has_tag_name("rules") {
                ensure!(
                    !node.children().any(|child| child.is_element()),
                    "<{}> cannot contain child elements",
                    node.tag_name().name()
                );
            }
        }
        let child = |tag: &str| -> Result<Option<roxmltree::Node<'_, '_>>> {
            let mut nodes = root.children().filter(|node| node.has_tag_name(tag));
            let first = nodes.next();
            ensure!(nodes.next().is_none(), "Duplicate <{tag}> element");
            Ok(first)
        };
        let backend = match child("backend")? {
            Some(node) => node
                .attribute("type")
                .context("<backend> requires type")?
                .parse()?,
            None => BackendKind::default(),
        };
        let udp_transport = match child("udp_transport")? {
            Some(node) => node
                .attribute("type")
                .context("<udp_transport> requires type")?
                .parse()?,
            None => UdpTransportKind::default(),
        };
        let socks_node = child("socks5")?;
        let socks5 = match socks_node {
            Some(node) => parse_socks5(node)?,
            None => Socks5Config::default(),
        };
        let gpux_node = child("gpux")?;
        let gpux = match gpux_node {
            Some(node) => parse_gpux(node)?,
            None => GpuxConfig::default(),
        };
        if udp_transport == UdpTransportKind::Gpux {
            ensure!(gpux_node.is_some(), "Missing <gpux> element");
            validate_gpux(&gpux)?;
        }
        let container = child("rules")?.context("Missing <rules> element")?;
        let mut rules = Vec::new();
        for node in container.children().filter(roxmltree::Node::is_element) {
            ensure!(
                node.has_tag_name("rule"),
                "Unknown <{}> in <rules>",
                node.tag_name().name()
            );
            ensure!(
                !node.children().any(|child| child.is_element()),
                "<rule> cannot contain child elements"
            );
            let names = node
                .attribute("names")
                .filter(|v| !v.trim().is_empty())
                .or_else(|| node.attribute("name"))
                .unwrap_or("");
            let process_names: Vec<_> = names
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect();
            ensure!(!process_names.is_empty(), "<rule> requires name or names");
            for name in &process_names {
                ensure!(
                    !name.contains('\0') && name.encode_utf16().count() < 260,
                    "Process rule must contain 1..259 UTF-16 code units without NUL"
                );
            }
            rules.push(Rule {
                process_names,
                accelerate_tcp: parse_bool(node.attribute("tcp"))?,
                accelerate_udp: parse_bool(node.attribute("udp"))?,
            });
        }
        ensure!(!rules.is_empty(), "No process rules configured");
        ensure!(
            rules.iter().any(|r| r.accelerate_tcp || r.accelerate_udp),
            "At least one rule must enable TCP or UDP"
        );
        let config = Self {
            backend,
            socks5,
            udp_transport,
            gpux,
            rules,
        };
        ensure!(
            socks_node.is_some() || !config.needs_socks5(),
            "Missing <socks5> element: TCP and SOCKS5 UDP require it"
        );
        Ok(config)
    }

    pub fn needs_socks5(&self) -> bool {
        self.udp_transport == UdpTransportKind::Socks5
            || self.rules.iter().any(|rule| rule.accelerate_tcp)
    }

    pub fn matches_process(&self, path: &str, tcp: bool) -> bool {
        let normalized = path.replace('/', "\\").to_lowercase();
        let basename = normalized.rsplit('\\').next().unwrap_or(&normalized);
        self.rules.iter().any(|rule| {
            (if tcp {
                rule.accelerate_tcp
            } else {
                rule.accelerate_udp
            }) && rule.process_names.iter().any(|pattern| {
                let pattern = pattern.replace('/', "\\").to_lowercase();
                wildcard_matches(
                    &pattern,
                    if pattern.contains('\\') {
                        &normalized
                    } else {
                        basename
                    },
                )
            })
        })
    }
}

fn parse_socks5(node: roxmltree::Node<'_, '_>) -> Result<Socks5Config> {
    let host = node.attribute("host").unwrap_or("").trim().to_owned();
    ensure!(
        !host.is_empty() && !host.contains('\0'),
        "SOCKS5 host is required and cannot contain NUL"
    );
    let port = node
        .attribute("port")
        .context("SOCKS5 port is required")?
        .parse::<u16>()
        .context("SOCKS5 port must be 1..65535")?;
    ensure!(port != 0, "SOCKS5 port must be 1..65535");
    let user = node.attribute("user").unwrap_or("").to_owned();
    let pass = node.attribute("pass").unwrap_or("").to_owned();
    ensure!(
        user.len() <= 255 && pass.len() <= 255,
        "SOCKS5 credentials exceed 255 UTF-8 bytes"
    );
    ensure!(
        !user.contains('\0') && !pass.contains('\0'),
        "SOCKS5 credentials cannot contain NUL"
    );
    ensure!(
        user.is_empty() == pass.is_empty(),
        "SOCKS5 username and password must both be set or both empty"
    );
    Ok(Socks5Config {
        host,
        port,
        user,
        pass,
    })
}

fn parse_gpux(node: roxmltree::Node<'_, '_>) -> Result<GpuxConfig> {
    let defaults = GpuxConfig::default();
    Ok(GpuxConfig {
        host: node.attribute("host").unwrap_or("").trim().to_owned(),
        port: parse_number(node, "port", defaults.port)?,
        token: node.attribute("token").unwrap_or("").to_owned(),
        encryption: node
            .attribute("encryption")
            .unwrap_or("chacha20-poly1305")
            .parse()?,
        mtu_payload: parse_number(node, "mtu_payload", defaults.mtu_payload)?,
        deadline_ms: parse_number(node, "deadline_ms", defaults.deadline_ms)?,
        batch_window_us: parse_number(node, "batch_window_us", defaults.batch_window_us)?,
        pacing_interval_us: parse_number(node, "pacing_interval_us", defaults.pacing_interval_us)?,
        queue_limit: parse_number(node, "queue_limit", defaults.queue_limit)?,
        fec_uplink: parse_number(node, "fec_uplink", defaults.fec_uplink)?,
        fec_group_max_us: parse_number(node, "fec_group_max_us", defaults.fec_group_max_us)?,
    })
}

fn parse_number<T: FromStr>(node: roxmltree::Node<'_, '_>, name: &str, default: T) -> Result<T> {
    match node.attribute(name) {
        Some(value) => {
            ensure!(
                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                "GPUX {name} must be an unsigned integer"
            );
            value
                .parse()
                .map_err(|_| anyhow::anyhow!("GPUX {name} is outside its integer range"))
        }
        None => Ok(default),
    }
}

fn validate_gpux(config: &GpuxConfig) -> Result<()> {
    ensure!(
        !config.host.is_empty() && !config.host.contains('\0'),
        "GPUX host is required and cannot contain NUL"
    );
    ensure!(config.port != 0, "GPUX port must be 1..65535");
    ensure!(
        (1..=255).contains(&config.token.len()) && !config.token.contains('\0'),
        "GPUX token must contain 1..255 UTF-8 bytes without NUL"
    );
    ensure!(
        (128..=65507).contains(&config.mtu_payload),
        "GPUX mtu_payload must be 128..65507"
    );
    ensure!(
        usize::from(config.mtu_payload) >= 80 + config.token.len(),
        "GPUX mtu_payload must fit CHLO: at least {} bytes for this token",
        80 + config.token.len()
    );
    ensure!(
        (1..=1000).contains(&config.deadline_ms),
        "GPUX deadline_ms must be 1..1000"
    );
    ensure!(
        config.batch_window_us <= 1_000_000,
        "GPUX batch_window_us must be 0..1000000"
    );
    ensure!(
        config.pacing_interval_us <= 1_000_000,
        "GPUX pacing_interval_us must be 0..1000000"
    );
    ensure!(
        (1..=65536).contains(&config.queue_limit),
        "GPUX queue_limit must be 1..65536"
    );
    ensure!(config.fec_uplink <= 1, "GPUX fec_uplink must be 0 or 1");
    ensure!(
        (1..=1_000_000).contains(&config.fec_group_max_us),
        "GPUX fec_group_max_us must be 1..1000000"
    );
    Ok(())
}

fn parse_bool(value: Option<&str>) -> Result<bool> {
    match value
        .unwrap_or("false")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => bail!("Rule tcp/udp must be true, false, 1 or 0"),
    }
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<_> = pattern.chars().collect();
    let value: Vec<_> = value.chars().collect();
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(s) = star {
            p = s + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

pub fn is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_private_or_local(v4.into());
            }
            let first = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn xml(extra: &str, rule: &str) -> String {
        format!(
            r#"<config>{extra}<socks5 host="127.0.0.1" port="10808"/><rules>{rule}</rules></config>"#
        )
    }
    #[test]
    fn legacy_config_and_process_matching() {
        let cfg = AppConfig::from_xml(&xml(
            "",
            r#"<rule names=" GAME.exe,助手?.exe " tcp="1" udp="false"/>"#,
        ))
        .unwrap();
        assert_eq!(cfg.backend, BackendKind::Netfilter);
        assert_eq!(cfg.udp_transport, UdpTransportKind::Socks5);
        assert!(cfg.needs_socks5());
        assert!(cfg.matches_process(r"C:\games\game.EXE", true));
        assert!(cfg.matches_process(r"C:\games\助手甲.exe", true));
        assert!(!cfg.matches_process("othergame.exe", true));
        assert!(!cfg.matches_process("game.exe", false));
    }
    #[test]
    fn validates_backend_rules_and_credentials() {
        let good = xml(
            r#"<backend type="windivert"/>"#,
            r#"<rule name="*.exe" udp="true"/>"#,
        );
        assert_eq!(
            AppConfig::from_xml(&good).unwrap().backend,
            BackendKind::Windivert
        );
        for bad in [
            good.replace("windivert", "unknown"),
            good.replace("10808", "0"),
            good.replace("true", "yes"),
            good.replace("*.exe", ""),
            good.replace("<socks5", "<socks5 user=\"u\""),
            good.replace("<rules>", "<backend type=\"netfilter\"/><rules>"),
        ] {
            assert!(AppConfig::from_xml(&bad).is_err());
        }
    }
    #[test]
    fn gpux_udp_only_has_independent_transport_and_encrypted_defaults() {
        let config = AppConfig::from_xml(
            r#"<config><backend type="windivert"/><udp_transport type="gpux"/>
            <gpux host="example.invalid" port="40000" token="test-token"/>
            <rules><rule name="game.exe" udp="1"/></rules></config>"#,
        )
        .unwrap();
        assert_eq!(config.backend, BackendKind::Windivert);
        assert_eq!(config.udp_transport, UdpTransportKind::Gpux);
        assert!(!config.needs_socks5());
        assert_eq!(config.socks5.host, "127.0.0.1");
        assert_eq!(config.socks5.port, 1080);
        assert_eq!(config.gpux.encryption, GpuxEncryption::Chacha20Poly1305);
        assert_eq!(config.gpux.deadline_ms, 8);
        assert_eq!(config.gpux.mtu_payload, 1200);
    }

    #[test]
    fn gpux_validates_tunables_and_tcp_still_requires_socks5() {
        let good = r#"<config><udp_transport type="gpux"/><gpux host="example.invalid"
            port="40000" token="test-token" encryption="plaintext" mtu_payload="1200"
            deadline_ms="8" batch_window_us="0" pacing_interval_us="0" queue_limit="512"
            fec_uplink="1" fec_group_max_us="2000"/>
            <rules><rule name="game.exe" udp="1"/></rules></config>"#;
        assert!(AppConfig::from_xml(good).is_ok());
        for (from, to) in [
            ("type=\"gpux\"", "type=\"unknown\""),
            ("host=\"example.invalid\"", "host=\"\""),
            ("port=\"40000\"", "port=\"0\""),
            ("token=\"test-token\"", "token=\"\""),
            ("encryption=\"plaintext\"", "encryption=\"unknown\""),
            ("mtu_payload=\"1200\"", "mtu_payload=\"127\""),
            ("mtu_payload=\"1200\"", "mtu_payload=\"65508\""),
            ("deadline_ms=\"8\"", "deadline_ms=\"0\""),
            ("deadline_ms=\"8\"", "deadline_ms=\"1001\""),
            ("batch_window_us=\"0\"", "batch_window_us=\"1000001\""),
            ("pacing_interval_us=\"0\"", "pacing_interval_us=\"-1\""),
            ("queue_limit=\"512\"", "queue_limit=\"0\""),
            ("fec_uplink=\"1\"", "fec_uplink=\"2\""),
            ("fec_group_max_us=\"2000\"", "fec_group_max_us=\"0\""),
            ("udp=\"1\"", "udp=\"1\" tcp=\"1\""),
        ] {
            assert!(
                AppConfig::from_xml(&good.replace(from, to)).is_err(),
                "accepted replacement {from} -> {to}"
            );
        }
        let max_token = good.replace("test-token", &"密".repeat(85));
        assert!(AppConfig::from_xml(&max_token).is_ok());
        assert!(AppConfig::from_xml(&good.replace("test-token", &"密".repeat(86))).is_err());
        let small_mtu = good.replace("mtu_payload=\"1200\"", "mtu_payload=\"128\"");
        assert!(AppConfig::from_xml(&small_mtu.replace("test-token", &"a".repeat(48))).is_ok());
        assert!(AppConfig::from_xml(&small_mtu.replace("test-token", &"a".repeat(49))).is_err());
        let with_socks = good
            .replace(
                "<rules>",
                "<socks5 host=\"127.0.0.1\" port=\"1080\"/><rules>",
            )
            .replace("udp=\"1\"", "udp=\"1\" tcp=\"1\"");
        assert!(AppConfig::from_xml(&with_socks).unwrap().needs_socks5());
    }

    #[test]
    fn rejects_unknown_and_duplicate_config_elements() {
        let base = xml("", r#"<rule name="game.exe" udp="1"/>"#);
        for extra in [
            "<unknown/>",
            "<socks5 host=\"127.0.0.1\" port=\"1080\"/>",
            "<udp_transport type=\"socks5\"/><udp_transport type=\"gpux\"/>",
            "<gpux/><gpux/>",
            "<rules><rule name=\"other.exe\" tcp=\"1\"/></rules>",
            "<backend type=\"netfilter\"><unknown/></backend>",
        ] {
            assert!(
                AppConfig::from_xml(&base.replace("<config>", &format!("<config>{extra}")))
                    .is_err()
            );
        }
        assert!(AppConfig::from_xml(&base.replace("<rules>", "<rules><unknown/>")).is_err());
        assert!(AppConfig::from_xml(&base.replace(
            "<rule name=\"game.exe\" udp=\"1\"/>",
            "<rule name=\"game.exe\" udp=\"1\"><unknown/></rule>"
        ))
        .is_err());
    }
    #[test]
    fn bypasses_local_addresses() {
        for ip in [
            "127.0.0.1",
            "10.2.3.4",
            "172.16.1.1",
            "192.168.2.1",
            "169.254.1.2",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_private_or_local(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "172.32.0.1", "2606:4700:4700::1111"] {
            assert!(!is_private_or_local(ip.parse().unwrap()), "{ip}");
        }
    }
}
