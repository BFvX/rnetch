//! NetFilter SDK C ABI. Layouts come from deps/netfilter/include/{nfdriver,nfevents}.h.
//! Windows unsigned long is 32 bits, and all SDK structures use pack(1).
use anyhow::{Context, Result};
use libloading::Library;
use std::path::Path;

pub const FILTER: u32 = 2;
pub const CONNECT_REQUESTS: u32 = 16;
pub const PEND_CONNECT: u32 = 64;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcpInfo {
    pub filtering_flag: u32,
    pub process_id: u32,
    pub direction: u8,
    pub ip_family: u16,
    pub local_address: [u8; 28],
    pub remote_address: [u8; 28],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct UdpInfo {
    pub process_id: u32,
    pub ip_family: u16,
    pub local_address: [u8; 28],
}

#[repr(C, packed)]
pub struct UdpRequest {
    pub filtering_flag: u32,
    pub process_id: u32,
    pub ip_family: u16,
    pub local_address: [u8; 28],
    pub remote_address: [u8; 28],
}

#[repr(C, packed)]
pub struct UdpOptions {
    pub flags: u32,
    pub options_length: i32,
    pub options: [u8; 1],
}

#[repr(C, packed)]
pub struct RuleEx {
    pub protocol: i32,
    pub process_id: u32,
    pub direction: u8,
    pub local_port: u16,
    pub remote_port: u16,
    pub ip_family: u16,
    pub local_ip: [u8; 16],
    pub local_mask: [u8; 16],
    pub remote_ip: [u8; 16],
    pub remote_mask: [u8; 16],
    pub filtering_flag: u32,
    pub process_name: [u16; 260],
    pub local_port_range: [u16; 2],
    pub remote_port_range: [u16; 2],
    pub redirect_to: [u8; 28],
    pub local_proxy_process_id: u32,
}

impl Default for RuleEx {
    fn default() -> Self {
        // All fields are integers/arrays; zero denotes an unconstrained SDK rule.
        unsafe { std::mem::zeroed() }
    }
}

type TcpData = unsafe extern "C" fn(u64, *const u8, i32);
type UdpData = unsafe extern "C" fn(u64, *const u8, *const u8, i32, *mut UdpOptions);

#[repr(C, packed)]
pub struct EventHandler {
    pub thread_start: unsafe extern "C" fn(),
    pub thread_end: unsafe extern "C" fn(),
    pub tcp_connect_request: unsafe extern "C" fn(u64, *mut TcpInfo),
    pub tcp_connected: unsafe extern "C" fn(u64, *mut TcpInfo),
    pub tcp_closed: unsafe extern "C" fn(u64, *mut TcpInfo),
    pub tcp_receive: TcpData,
    pub tcp_send: TcpData,
    pub tcp_can_receive: unsafe extern "C" fn(u64),
    pub tcp_can_send: unsafe extern "C" fn(u64),
    pub udp_created: unsafe extern "C" fn(u64, *mut UdpInfo),
    pub udp_connect_request: unsafe extern "C" fn(u64, *mut UdpRequest),
    pub udp_closed: unsafe extern "C" fn(u64, *mut UdpInfo),
    pub udp_receive: UdpData,
    pub udp_send: UdpData,
    pub udp_can_receive: unsafe extern "C" fn(u64),
    pub udp_can_send: unsafe extern "C" fn(u64),
}

pub struct Api {
    pub init: unsafe extern "C" fn(*const u8, *mut EventHandler) -> i32,
    pub free: unsafe extern "C" fn(),
    pub set_options: unsafe extern "C" fn(u32, u32),
    pub add_rule: unsafe extern "C" fn(*mut RuleEx, i32) -> i32,
    pub delete_rules: unsafe extern "C" fn() -> i32,
    pub process_name: unsafe extern "C" fn(u32, *mut u16, u32) -> i32,
    pub tcp_complete: unsafe extern "C" fn(u64, *mut TcpInfo) -> i32,
    pub tcp_close: unsafe extern "C" fn(u64) -> i32,
    pub tcp_post_receive: unsafe extern "C" fn(u64, *const u8, i32) -> i32,
    pub tcp_post_send: unsafe extern "C" fn(u64, *const u8, i32) -> i32,
    pub tcp_disable: unsafe extern "C" fn(u64) -> i32,
    pub udp_disable: unsafe extern "C" fn(u64) -> i32,
    pub udp_post_receive:
        unsafe extern "C" fn(u64, *const u8, *const u8, i32, *mut UdpOptions) -> i32,
    pub udp_post_send: unsafe extern "C" fn(u64, *const u8, *const u8, i32, *mut UdpOptions) -> i32,
    _library: Option<Library>,
}

impl Api {
    #[cfg(test)]
    pub(super) fn test_stub() -> Self {
        unsafe extern "C" fn init(_: *const u8, _: *mut EventHandler) -> i32 {
            0
        }
        unsafe extern "C" fn free() {}
        unsafe extern "C" fn options(_: u32, _: u32) {}
        unsafe extern "C" fn rule(_: *mut RuleEx, _: i32) -> i32 {
            0
        }
        unsafe extern "C" fn rules() -> i32 {
            0
        }
        unsafe extern "C" fn name(_: u32, out: *mut u16, size: u32) -> i32 {
            let value: Vec<u16> = "mock-game.exe\0".encode_utf16().collect();
            assert!(size as usize >= value.len());
            unsafe {
                std::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len());
            }
            1
        }
        unsafe extern "C" fn connection(_: u64, _: *mut TcpInfo) -> i32 {
            0
        }
        unsafe extern "C" fn id(_: u64) -> i32 {
            0
        }
        unsafe extern "C" fn tcp(_: u64, _: *const u8, _: i32) -> i32 {
            0
        }
        unsafe extern "C" fn udp(
            _: u64,
            _: *const u8,
            _: *const u8,
            _: i32,
            _: *mut UdpOptions,
        ) -> i32 {
            0
        }
        Self {
            init,
            free,
            set_options: options,
            add_rule: rule,
            delete_rules: rules,
            process_name: name,
            tcp_complete: connection,
            tcp_close: id,
            tcp_post_receive: tcp,
            tcp_post_send: tcp,
            tcp_disable: id,
            udp_disable: id,
            udp_post_receive: udp,
            udp_post_send: udp,
            _library: None,
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        // Resolve an explicit absolute path; never search PATH for a kernel SDK DLL.
        let library = unsafe { Library::new(path) }
            .with_context(|| format!("Cannot load {}", path.display()))?;
        unsafe {
            Ok(Self {
                init: *library.get(b"nf_init\0")?,
                free: *library.get(b"nf_free\0")?,
                set_options: *library.get(b"nf_setOptions\0")?,
                add_rule: *library.get(b"nf_addRuleEx\0")?,
                delete_rules: *library.get(b"nf_deleteRules\0")?,
                process_name: *library.get(b"nf_getProcessNameW\0")?,
                tcp_complete: *library.get(b"nf_completeTCPConnectRequest\0")?,
                tcp_close: *library.get(b"nf_tcpClose\0")?,
                tcp_post_receive: *library.get(b"nf_tcpPostReceive\0")?,
                tcp_post_send: *library.get(b"nf_tcpPostSend\0")?,
                tcp_disable: *library.get(b"nf_tcpDisableFiltering\0")?,
                udp_disable: *library.get(b"nf_udpDisableFiltering\0")?,
                udp_post_receive: *library.get(b"nf_udpPostReceive\0")?,
                udp_post_send: *library.get(b"nf_udpPostSend\0")?,
                _library: Some(library),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn bundled_sdk_abi_layout() {
        assert_eq!(size_of::<TcpInfo>(), 67);
        assert_eq!(offset_of!(TcpInfo, remote_address), 39);
        assert_eq!(size_of::<UdpInfo>(), 34);
        assert_eq!(size_of::<UdpRequest>(), 66);
        assert_eq!(size_of::<UdpOptions>(), 9);
        assert_eq!(size_of::<RuleEx>(), 643);
        assert_eq!(offset_of!(RuleEx, filtering_flag), 79);
        assert_eq!(offset_of!(RuleEx, process_name), 83);
        assert_eq!(size_of::<EventHandler>(), 16 * size_of::<usize>());
        assert_eq!(align_of::<EventHandler>(), 1);
        assert_eq!(align_of::<TcpInfo>(), 1);
        assert_eq!(align_of::<RuleEx>(), 1);
    }
}
