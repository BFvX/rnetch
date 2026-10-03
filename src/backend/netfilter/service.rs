//! Minimal, owned Windows SCM handles. Existing running services are not stopped.
use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::time::{Duration, Instant};

type Handle = *mut c_void;
const RUNNING: u32 = 4;
const STOPPED: u32 = 1;
const QUERY: u32 = 4;
const START: u32 = 16;
const STOP: u32 = 32;

#[repr(C)]
#[derive(Default)]
struct Status {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_exit_code: u32,
    checkpoint: u32,
    wait_hint: u32,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> Handle;
    fn OpenServiceW(manager: Handle, name: *const u16, access: u32) -> Handle;
    fn CreateServiceW(
        manager: Handle,
        name: *const u16,
        display: *const u16,
        access: u32,
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary: *const u16,
        group: *const u16,
        tag: *mut u32,
        dependencies: *const u16,
        account: *const u16,
        password: *const u16,
    ) -> Handle;
    fn ChangeServiceConfigW(
        service: Handle,
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary: *const u16,
        group: *const u16,
        tag: *mut u32,
        dependencies: *const u16,
        account: *const u16,
        password: *const u16,
        display: *const u16,
    ) -> i32;
    fn QueryServiceStatus(service: Handle, status: *mut Status) -> i32;
    fn StartServiceW(service: Handle, count: u32, arguments: *const *const u16) -> i32;
    fn ControlService(service: Handle, control: u32, status: *mut Status) -> i32;
    fn CloseServiceHandle(handle: Handle) -> i32;
}

struct ServiceHandle(Handle);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

impl ServiceHandle {
    fn state(&self) -> Result<u32> {
        let mut status = Status::default();
        if unsafe { QueryServiceStatus(self.0, &mut status) } == 0 {
            return Err(std::io::Error::last_os_error()).context("Query NetFilter service");
        }
        Ok(status.current_state)
    }

    fn wait(&self, expected: u32) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if self.state()? == expected {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("NetFilter service state transition timed out");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

pub struct DriverService {
    service: ServiceHandle,
    started_here: bool,
}

impl DriverService {
    pub fn start(driver: &Path) -> Result<Self> {
        let driver = driver.canonicalize().context("nfdriver.sys is missing")?;
        // SCM accepts DOS paths; canonicalize on Windows prepends the extended path prefix.
        let path = driver
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_owned();
        let binary: Vec<u16> = std::ffi::OsStr::new(&path)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let name: Vec<u16> = "netfilter2\0".encode_utf16().collect();
        let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), 1 | 2) };
        if manager.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("Open SCM; administrator rights are required");
        }
        let manager = ServiceHandle(manager);
        let access = QUERY | START | STOP | 2;
        let mut service = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
        if service.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(1060) {
                return Err(error).context("Open NetFilter driver service");
            }
            service = unsafe {
                CreateServiceW(
                    manager.0,
                    name.as_ptr(),
                    name.as_ptr(),
                    access,
                    1,
                    3,
                    1,
                    binary.as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                )
            };
            if service.is_null() {
                return Err(std::io::Error::last_os_error())
                    .context("Create NetFilter driver service");
            }
        }
        let service = ServiceHandle(service);
        let state = service.state()?;
        if state == RUNNING {
            return Ok(Self {
                service,
                started_here: false,
            });
        }
        if state == 2 {
            service.wait(RUNNING)?;
            return Ok(Self {
                service,
                started_here: false,
            });
        }
        if state != STOPPED {
            service.wait(STOPPED)?;
        }
        if unsafe {
            ChangeServiceConfigW(
                service.0,
                1,
                3,
                1,
                binary.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error()).context("Configure NetFilter driver path");
        }
        let started = unsafe { StartServiceW(service.0, 0, ptr::null()) } != 0;
        if !started && std::io::Error::last_os_error().raw_os_error() != Some(1056) {
            return Err(std::io::Error::last_os_error())
                .context("Start NetFilter driver; check driver signing and administrator rights");
        }
        let result = Self {
            service,
            started_here: started,
        };
        result.service.wait(RUNNING)?;
        Ok(result)
    }
}

impl Drop for DriverService {
    fn drop(&mut self) {
        if self.started_here {
            let mut status = Status::default();
            if unsafe { ControlService(self.service.0, 1, &mut status) } == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(1062) {
                    eprintln!("Stop NetFilter service: {error}");
                }
            }
        }
    }
}
