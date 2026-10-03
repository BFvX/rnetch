//! NETWORK does not provide a PID. Resolve the captured 5-tuple via IP Helper.
use super::packet::Flow;
use std::{
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    },
};

fn table(tcp: bool, ipv6: bool) -> io::Result<Vec<u8>> {
    let family = if ipv6 { AF_INET6 } else { AF_INET } as u32;
    let mut length = 0;
    let call = |buffer, length: &mut u32| unsafe {
        if tcp {
            GetExtendedTcpTable(buffer, length, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
        } else {
            GetExtendedUdpTable(buffer, length, 0, family, UDP_TABLE_OWNER_PID, 0)
        }
    };
    let result = call(ptr::null_mut(), &mut length);
    if result != 0 && result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    for _ in 0..4 {
        if length > 32 * 1024 * 1024 {
            return Err(io::Error::other("IP Helper table exceeds limit"));
        }
        // u64 storage provides alignment for the C API. Rows are read unaligned below.
        let mut storage = vec![0u64; (length as usize).div_ceil(8).max(1)];
        let result = call(storage.as_mut_ptr().cast(), &mut length);
        if result == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        return Ok(unsafe {
            std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length as usize)
        }
        .to_vec());
    }
    Err(io::Error::other("IP Helper table changed repeatedly"))
}

fn rows<T: Copy>(bytes: &[u8]) -> impl Iterator<Item = T> + '_ {
    let count = bytes
        .get(..4)
        .map(|n| u32::from_ne_bytes(n.try_into().unwrap()) as usize)
        .unwrap_or(0);
    bytes
        .get(4..)
        .unwrap_or_default()
        .chunks_exact(size_of::<T>())
        .take(count)
        .map(|row| unsafe { ptr::read_unaligned(row.as_ptr().cast::<T>()) })
}

fn v4(address: u32, port: u32) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(address.to_ne_bytes())),
        u16::from_be(port as u16),
    )
}
fn v6(address: [u8; 16], port: u32) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(address)),
        u16::from_be(port as u16),
    )
}

pub(super) fn process(flow: Flow, tcp: bool) -> io::Result<Option<u32>> {
    let bytes = table(tcp, flow.local.is_ipv6())?;
    let matches: Vec<u32> = match (tcp, flow.local.is_ipv6()) {
        (true, false) => rows::<MIB_TCPROW_OWNER_PID>(&bytes)
            .filter(|r| {
                v4(r.dwLocalAddr, r.dwLocalPort) == flow.local
                    && v4(r.dwRemoteAddr, r.dwRemotePort) == flow.remote
            })
            .map(|r| r.dwOwningPid)
            .collect(),
        (true, true) => rows::<MIB_TCP6ROW_OWNER_PID>(&bytes)
            .filter(|r| {
                v6(r.ucLocalAddr, r.dwLocalPort) == flow.local
                    && v6(r.ucRemoteAddr, r.dwRemotePort) == flow.remote
            })
            .map(|r| r.dwOwningPid)
            .collect(),
        (false, false) => rows::<MIB_UDPROW_OWNER_PID>(&bytes)
            .filter(|r| udp_matches(v4(r.dwLocalAddr, r.dwLocalPort), flow.local))
            .map(|r| r.dwOwningPid)
            .collect(),
        (false, true) => rows::<MIB_UDP6ROW_OWNER_PID>(&bytes)
            .filter(|r| udp_matches(v6(r.ucLocalAddr, r.dwLocalPort), flow.local))
            .map(|r| r.dwOwningPid)
            .collect(),
    };
    // Shared UDP ports can belong to unrelated processes. Never guess their owner.
    Ok(matches
        .first()
        .copied()
        .filter(|pid| matches.iter().all(|candidate| candidate == pid)))
}

fn udp_matches(bound: SocketAddr, source: SocketAddr) -> bool {
    bound.port() == source.port() && (bound.ip() == source.ip() || bound.ip().is_unspecified())
}

pub(super) fn preflight() -> io::Result<()> {
    for tcp in [true, false] {
        for ipv6 in [false, true] {
            table(tcp, ipv6)?;
        }
    }
    Ok(())
}

pub(super) fn path(pid: u32) -> io::Result<String> {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u16; 32768];
        let mut length = buffer.len() as u32;
        let result = QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length);
        let error = io::Error::last_os_error();
        CloseHandle(process);
        if result == 0 {
            Err(error)
        } else {
            Ok(String::from_utf16_lossy(&buffer[..length as usize]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_order_and_wildcard_binding() {
        assert_eq!(
            v4(u32::from_ne_bytes([192, 0, 2, 3]), 443u16.to_be() as u32),
            "192.0.2.3:443".parse().unwrap()
        );
        assert!(udp_matches(
            "0.0.0.0:53".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap()
        ));
        assert!(!udp_matches(
            "192.0.2.2:53".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap()
        ));
    }

    #[test]
    fn windows_owner_tables_identify_live_tcp_and_udp_sockets() {
        use std::net::{TcpListener, TcpStream, UdpSocket};
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(address).unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (_accepted, _) = listener.accept().unwrap();
            let flow = Flow {
                local: stream.local_addr().unwrap(),
                remote: stream.peer_addr().unwrap(),
            };
            assert_eq!(process(flow, true).unwrap(), Some(std::process::id()));
            let socket = UdpSocket::bind(address).unwrap();
            let flow = Flow {
                local: socket.local_addr().unwrap(),
                remote: flow.remote,
            };
            assert_eq!(process(flow, false).unwrap(), Some(std::process::id()));
        }
        assert!(path(std::process::id())
            .unwrap()
            .to_ascii_lowercase()
            .ends_with(".exe"));
    }
}
