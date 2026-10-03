//! WinDivert 2.x ABI, verified against upstream include/windivert.h.
use anyhow::{bail, Context, Result};
use libloading::Library;
use std::{
    ffi::{c_char, c_void, CString},
    io,
    path::PathBuf,
    sync::Arc,
};

type Handle = *mut c_void;
type Open = unsafe extern "system" fn(*const c_char, i32, i16, u64) -> Handle;
type Recv = unsafe extern "system" fn(Handle, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type Send = unsafe extern "system" fn(Handle, *const c_void, u32, *mut u32, *const Address) -> i32;
type Shutdown = unsafe extern "system" fn(Handle, i32) -> i32;
type Close = unsafe extern "system" fn(Handle) -> i32;
type Checksums = unsafe extern "system" fn(*mut c_void, u32, *mut Address, u64) -> i32;
type GetParam = unsafe extern "system" fn(Handle, i32, *mut u64) -> i32;

/// Header is 16 bytes; union reserves 64 bytes and has 8-byte alignment.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub(super) struct Address {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    data: [u8; 64],
}

impl Default for Address {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
}

impl Address {
    pub fn outbound(&self) -> bool {
        self.flags & (1 << 17) != 0
    }
    pub fn inbound(&mut self) {
        // New injection is a network packet, not an impostor / loopback packet.
        self.flags &= !((1 << 17) | (1 << 18) | (1 << 19));
    }
    pub fn for_reply(&self, ipv6: bool) -> Self {
        let mut reply = Self::default();
        reply.data[..8].copy_from_slice(&self.data[..8]);
        if ipv6 {
            reply.flags |= 1 << 20;
        }
        reply
    }
}

struct Api {
    _library: Library,
    recv: Recv,
    send: Send,
    shutdown: Shutdown,
    close: Close,
    checksums: Checksums,
}

pub(super) struct Driver {
    api: Api,
    handle: Handle,
}

// WinDivert explicitly supports concurrent Recv/Send/Shutdown on one handle.
// The DLL and handle outlive every Arc clone, and Close runs exactly once.
unsafe impl std::marker::Send for Driver {}
unsafe impl Sync for Driver {}

impl Driver {
    pub fn open(filter: &str) -> Result<Arc<Self>> {
        let directory = std::env::current_exe()?
            .parent()
            .context("executable has no parent")?
            .to_path_buf();
        let mut candidates = vec![
            directory.join("WinDivert.dll"),
            directory.join("deps/windivert/WinDivert.dll"),
        ];
        // Cargo development builds keep the SDK under the project root.
        candidates
            .push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deps/windivert/WinDivert.dll"));
        let path = candidates.into_iter().find(|path| path.is_file()).context("WinDivert.dll missing: place the WinDivert 2.2 x64 DLL and WinDivert64.sys beside rnetch.exe, or in deps/windivert")?.canonicalize()?;
        let filter = CString::new(filter)?;
        // Only load an explicit absolute path, never the working-directory DLL search path.
        unsafe {
            let library =
                Library::new(&path).with_context(|| format!("load {}", path.display()))?;
            let open: Open = *library.get(b"WinDivertOpen\0")?;
            let get_param: GetParam = *library.get(b"WinDivertGetParam\0")?;
            let api = Api {
                recv: *library.get(b"WinDivertRecv\0")?,
                send: *library.get(b"WinDivertSend\0")?,
                shutdown: *library.get(b"WinDivertShutdown\0")?,
                close: *library.get(b"WinDivertClose\0")?,
                checksums: *library.get(b"WinDivertHelperCalcChecksums\0")?,
                _library: library,
            };
            let handle = open(filter.as_ptr(), 0, 100, 0);
            if handle as isize == -1 {
                return Err(io::Error::last_os_error()).context("WinDivertOpen failed; run elevated and verify the signed WinDivert64.sys is beside WinDivert.dll");
            }
            let driver = Arc::new(Self { api, handle });
            let mut version = 0;
            if get_param(handle, 3, &mut version) == 0 || version != 2 {
                bail!("WinDivert driver API 2.x is required (reported major {version})");
            }
            Ok(driver)
        }
    }

    pub fn recv(&self, packet: &mut [u8], address: &mut Address) -> io::Result<usize> {
        let mut length = 0;
        let ok = unsafe {
            (self.api.recv)(
                self.handle,
                packet.as_mut_ptr().cast(),
                packet.len() as u32,
                &mut length,
                address,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(length as usize)
        }
    }

    pub fn send(&self, packet: &[u8], address: &Address) -> io::Result<()> {
        let mut length = 0;
        let ok = unsafe {
            (self.api.send)(
                self.handle,
                packet.as_ptr().cast(),
                packet.len() as u32,
                &mut length,
                address,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != packet.len() {
            return Err(io::Error::other("WinDivertSend sent a partial packet"));
        }
        Ok(())
    }

    pub fn send_modified(&self, packet: &mut [u8], address: &mut Address) -> io::Result<()> {
        if unsafe {
            (self.api.checksums)(packet.as_mut_ptr().cast(), packet.len() as u32, address, 0)
        } == 0
        {
            return Err(io::Error::other("WinDivert checksum calculation failed"));
        }
        self.send(packet, address)
    }

    /// Stop capture and unblock Recv, retaining Send while the captured queue drains.
    pub fn shutdown_receive(&self) {
        unsafe {
            (self.api.shutdown)(self.handle, 1);
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        unsafe {
            (self.api.close)(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windivert_2_address_layout() {
        assert_eq!(std::mem::size_of::<Address>(), 80);
        assert_eq!(std::mem::align_of::<Address>(), 8);
        assert_eq!(std::mem::offset_of!(Address, data), 16);
        let mut address = Address {
            flags: 1 << 17,
            ..Address::default()
        };
        assert!(address.outbound());
        address.inbound();
        assert!(!address.outbound());
    }
}
