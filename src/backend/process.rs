//! Discover local proxy daemons before their forwarding can trigger interception.
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream};
use std::ptr;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
};

static LOCAL_PROXIES: OnceLock<Mutex<HashMap<u32, u64>>> = OnceLock::new();

fn proxies() -> &'static Mutex<HashMap<u32, u64>> {
    LOCAL_PROXIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Does this PID still identify a previously observed local proxy daemon?
/// Creation time prevents an unrelated process from inheriting an old exemption.
pub(crate) fn is_local_proxy(pid: u32) -> bool {
    let identity = proxies()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&pid)
        .copied();
    let Some(identity) = identity else {
        return false;
    };
    match process_identity(pid) {
        Ok(current) if current == identity => true,
        Ok(_) => {
            let mut registry = proxies().lock().unwrap_or_else(|error| error.into_inner());
            if registry.get(&pid) == Some(&identity) {
                registry.remove(&pid);
            }
            false
        }
        // If a known proxy becomes inaccessible, preserve the exemption rather
        // than risk a forwarding loop. A future accessible PID is revalidated.
        Err(_) => true,
    }
}

pub(crate) fn register_proxy_connection(stream: &TcpStream) -> Result<()> {
    let client = normalize(stream.local_addr()?);
    let server = normalize(stream.peer_addr()?);
    let owners = connection_owners(server, client)
        .context("Resolve local SOCKS5 server process before forwarding")?;
    let Some(&pid) = owners.first() else {
        return Ok(());
    }; // Remote SOCKS server.
    if owners.iter().any(|owner| *owner != pid) {
        bail!("Local SOCKS5 server TCP endpoint has ambiguous process ownership");
    }
    let identity =
        process_identity(pid).context("Identify local SOCKS5 server process lifetime")?;
    proxies()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(pid, identity);
    Ok(())
}

/// A connected UDP socket supplies its routed local address. Only same-host
/// servers qualify, so an unrelated wildcard socket cannot exempt a remote VPS.
pub(crate) fn register_udp_proxy(server: SocketAddr, client_local: SocketAddr) -> Result<()> {
    let server = normalize(server);
    let client_local = normalize(client_local);
    if !server.ip().is_loopback() && server.ip() != client_local.ip() {
        return Ok(());
    }
    let owners = udp_owners(server).context("Resolve local GPUX server process")?;
    let Some(&pid) = owners.first() else {
        return Ok(());
    };
    if owners.iter().any(|owner| *owner != pid) {
        bail!("Local GPUX server UDP endpoint has ambiguous process ownership");
    }
    let identity = process_identity(pid).context("Identify local GPUX server process lifetime")?;
    proxies()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(pid, identity);
    Ok(())
}

fn udp_owners(server: SocketAddr) -> io::Result<Vec<u32>> {
    if server.is_ipv4() {
        let table = endpoint_table(AF_INET as u32, false)?;
        let owners: Vec<_> = rows::<MIB_UDPROW_OWNER_PID>(&table)
            .filter(|row| udp_bound_matches(v4(row.dwLocalAddr, row.dwLocalPort), server))
            .map(|row| row.dwOwningPid)
            .collect();
        if !owners.is_empty() {
            return Ok(owners);
        }
    }
    let table = endpoint_table(AF_INET6 as u32, false)?;
    Ok(rows::<MIB_UDP6ROW_OWNER_PID>(&table)
        .filter(|row| {
            udp_bound_matches(
                v6(row.ucLocalAddr, row.dwLocalPort, row.dwLocalScopeId),
                server,
            )
        })
        .map(|row| row.dwOwningPid)
        .collect())
}

fn udp_bound_matches(bound: SocketAddr, server: SocketAddr) -> bool {
    bound.port() == server.port() && (bound.ip().is_unspecified() || bound == server)
}

fn process_identity(pid: u32) -> io::Result<u64> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut created: FILETIME = std::mem::zeroed();
        let mut exited: FILETIME = std::mem::zeroed();
        let mut kernel: FILETIME = std::mem::zeroed();
        let mut user: FILETIME = std::mem::zeroed();
        let success = GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user);
        let error = io::Error::last_os_error();
        CloseHandle(process);
        if success == 0 {
            return Err(error);
        }
        Ok(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64)
    }
}

fn normalize(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => match address.ip().to_ipv4_mapped() {
            Some(ip) => SocketAddr::new(ip.into(), address.port()),
            None => SocketAddr::V6(SocketAddrV6::new(
                *address.ip(),
                address.port(),
                0,
                address.scope_id(),
            )),
        },
        _ => address,
    }
}

fn v4(address: u32, port: u32) -> SocketAddr {
    SocketAddr::new(
        Ipv4Addr::from(address.to_ne_bytes()).into(),
        u16::from_be(port as u16),
    )
}

fn v6(address: [u8; 16], port: u32, scope: u32) -> SocketAddr {
    normalize(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(address),
        u16::from_be(port as u16),
        0,
        scope,
    )))
}

fn connection_owners(local: SocketAddr, remote: SocketAddr) -> io::Result<Vec<u32>> {
    if local.is_ipv6() {
        let table = tcp_table(AF_INET6 as u32)?;
        return Ok(rows::<MIB_TCP6ROW_OWNER_PID>(&table)
            .filter(|row| {
                v6(row.ucLocalAddr, row.dwLocalPort, row.dwLocalScopeId) == local
                    && v6(row.ucRemoteAddr, row.dwRemotePort, row.dwRemoteScopeId) == remote
            })
            .map(|row| row.dwOwningPid)
            .collect());
    }
    let table = tcp_table(AF_INET as u32)?;
    let owners: Vec<_> = rows::<MIB_TCPROW_OWNER_PID>(&table)
        .filter(|row| {
            v4(row.dwLocalAddr, row.dwLocalPort) == local
                && v4(row.dwRemoteAddr, row.dwRemotePort) == remote
        })
        .map(|row| row.dwOwningPid)
        .collect();
    if !owners.is_empty() {
        return Ok(owners);
    }
    // Dual-stack listeners may expose their IPv4 connections as mapped IPv6 rows.
    let table = tcp_table(AF_INET6 as u32)?;
    Ok(rows::<MIB_TCP6ROW_OWNER_PID>(&table)
        .filter(|row| {
            v6(row.ucLocalAddr, row.dwLocalPort, row.dwLocalScopeId) == local
                && v6(row.ucRemoteAddr, row.dwRemotePort, row.dwRemoteScopeId) == remote
        })
        .map(|row| row.dwOwningPid)
        .collect())
}

fn tcp_table(family: u32) -> io::Result<Vec<u8>> {
    endpoint_table(family, true)
}

fn endpoint_table(family: u32, tcp: bool) -> io::Result<Vec<u8>> {
    let mut length = 0;
    let read_table = |buffer, length: &mut u32| unsafe {
        if tcp {
            GetExtendedTcpTable(buffer, length, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
        } else {
            GetExtendedUdpTable(buffer, length, 0, family, UDP_TABLE_OWNER_PID, 0)
        }
    };
    let first = read_table(ptr::null_mut(), &mut length);
    if first != 0 && first != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::from_raw_os_error(first as i32));
    }
    for _ in 0..4 {
        if length > 32 * 1024 * 1024 {
            return Err(io::Error::other(
                "Proxy endpoint table exceeds memory limit",
            ));
        }
        let mut storage = vec![0u64; (length as usize).div_ceil(8).max(1)];
        let result = read_table(storage.as_mut_ptr().cast(), &mut length);
        if result == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        return Ok(
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast(), length as usize) }
                .to_vec(),
        );
    }
    Err(io::Error::other("Proxy endpoint table changed repeatedly"))
}

fn rows<T: Copy>(bytes: &[u8]) -> impl Iterator<Item = T> + '_ {
    let count = bytes
        .get(..4)
        .map(|bytes| u32::from_ne_bytes(bytes.try_into().unwrap()) as usize)
        .unwrap_or(0);
    bytes
        .get(4..)
        .unwrap_or_default()
        .chunks_exact(size_of::<T>())
        .take(count)
        .map(|row| unsafe { ptr::read_unaligned(row.as_ptr().cast()) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn discover_local_udp_proxy_without_driver_or_packets() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let server = UdpSocket::bind(bind).unwrap();
            let client = UdpSocket::bind(bind).unwrap();
            client.connect(server.local_addr().unwrap()).unwrap();
            assert!(udp_owners(server.local_addr().unwrap())
                .unwrap()
                .contains(&std::process::id()));
            register_udp_proxy(client.peer_addr().unwrap(), client.local_addr().unwrap()).unwrap();
            assert!(is_local_proxy(std::process::id()));
        }
        assert!(udp_bound_matches(
            "0.0.0.0:40000".parse().unwrap(),
            "127.0.0.1:40000".parse().unwrap()
        ));
        assert!(!udp_bound_matches(
            "0.0.0.0:40001".parse().unwrap(),
            "127.0.0.1:40000".parse().unwrap()
        ));
    }

    #[test]
    fn discover_reverse_side_of_loopback_proxy_connection() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(bind).unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            register_proxy_connection(&client).unwrap();
            let (_server, _) = listener.accept().unwrap();
            assert!(is_local_proxy(std::process::id()));
            assert!(
                connection_owners(client.peer_addr().unwrap(), client.local_addr().unwrap())
                    .unwrap()
                    .contains(&std::process::id())
            );
        }
    }

    #[test]
    fn normalize_mapped_ipv4_and_preserve_native_ipv6_scope() {
        assert_eq!(
            normalize("[::ffff:127.0.0.1]:1234".parse().unwrap()),
            "127.0.0.1:1234".parse::<SocketAddr>().unwrap()
        );
        let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 7, 3));
        assert_eq!(
            normalize(scoped),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 3))
        );
        assert_eq!(
            v4(u32::from_ne_bytes([127, 0, 0, 1]), 80u16.to_be() as u32),
            "127.0.0.1:80".parse().unwrap()
        );
    }
}
