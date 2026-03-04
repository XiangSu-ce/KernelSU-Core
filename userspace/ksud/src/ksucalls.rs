#![allow(clippy::unreadable_literal)]
use libc::{_IO, _IOR, _IOW, _IOWR};
use std::fs;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

// Event constants
const EVENT_POST_FS_DATA: u32 = 1;
const EVENT_BOOT_COMPLETED: u32 = 2;
const EVENT_MODULE_MOUNTED: u32 = 3;

const K: u32 = b'K' as u32;
const KSU_IOCTL_GRANT_ROOT: i32 = _IO(K, 1);
const KSU_IOCTL_GET_INFO: i32 = _IOR::<()>(K, 2);
const KSU_IOCTL_REPORT_EVENT: i32 = _IOW::<()>(K, 3);
const KSU_IOCTL_SET_SEPOLICY: i32 = _IOWR::<()>(K, 4);
const KSU_IOCTL_CHECK_SAFEMODE: i32 = _IOR::<()>(K, 5);
const KSU_IOCTL_GET_FEATURE: i32 = _IOWR::<()>(K, 13);
const KSU_IOCTL_SET_FEATURE: i32 = _IOW::<()>(K, 14);
const KSU_IOCTL_GET_WRAPPER_FD: i32 = _IOW::<()>(K, 15);
const KSU_IOCTL_MANAGE_MARK: i32 = _IOWR::<()>(K, 16);
const KSU_IOCTL_NUKE_EXT4_SYSFS: i32 = _IOW::<()>(K, 17);
const KSU_IOCTL_ADD_TRY_UMOUNT: i32 = _IOW::<()>(K, 18);
const KSU_IOCTL_STEALTH_IPC: i32 = _IOWR::<()>(K, 19);
const KSU_IOCTL_STEALTH_PID: i32 = _IOW::<()>(K, 20);
const KSU_IOCTL_STEALTH_REGISTER_MOD: i32 = _IOW::<()>(K, 21);
const KSU_IOCTL_STEALTH_EXEC: i32 = _IO(K, 22);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GetInfoCmd {
    version: u32,
    flags: u32,
    features: u32,
}

#[repr(C)]
struct ReportEventCmd {
    event: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SetSepolicyCmd {
    pub cmd: u64,
    pub arg: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CheckSafemodeCmd {
    in_safe_mode: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GetFeatureCmd {
    feature_id: u32,
    value: u64,
    supported: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SetFeatureCmd {
    feature_id: u32,
    value: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct GetWrapperFdCmd {
    fd: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ManageMarkCmd {
    operation: u32,
    pid: i32,
    result: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NukeExt4SysfsCmd {
    pub arg: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct AddTryUmountCmd {
    arg: u64,   // char ptr, this is the mountpoint
    flags: u32, // this is the flag we use for it
    mode: u8,   // denotes what to do with it 0:wipe_list 1:add_to_list 2:delete_entry
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StealthIpcCmd {
    module_id: [u8; 64],
    subcmd: u32,
    data: u64,
    data_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StealthPidCmd {
    operation: u32,
    pid: i32,
    fake_comm: [u8; 128],
    fake_exe: [u8; 128],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StealthRegisterModCmd {
    name: [u8; 64],
}

// Mark operation constants
const KSU_MARK_GET: u32 = 1;
const KSU_MARK_MARK: u32 = 2;
const KSU_MARK_UNMARK: u32 = 3;
const KSU_MARK_REFRESH: u32 = 4;

const STEALTH_PID_MARK: u32 = 0;
const STEALTH_PID_UNMARK: u32 = 1;
const STEALTH_PID_MARK_SELF: u32 = 2;
const STEALTH_PID_DISGUISE: u32 = 3;

// Umount operation constants
const KSU_UMOUNT_WIPE: u8 = 0;
const KSU_UMOUNT_ADD: u8 = 1;
const KSU_UMOUNT_DEL: u8 = 2;

// Global driver fd cache (-1 means not initialized / invalid)
static DRIVER_FD: AtomicI32 = AtomicI32::new(-1);
const KSU_DRIVER_FD_NAMES: [&str; 2] = ["[ksu_driver]", "[timerfd]"];

const KSU_INSTALL_MAGIC1: u32 = 0xDEADBEEF;
const KSU_INSTALL_MAGIC2: u32 = 0xCAFEBABE;

struct DriverFd {
    fd: RawFd,
    // true when created by reboot install path; false when discovered from /proc/self/fd
    owned: bool,
}

fn is_valid_driver_fd(fd: RawFd) -> bool {
    let mut cmd = CheckSafemodeCmd::default();
    unsafe { libc::ioctl(fd as libc::c_int, KSU_IOCTL_CHECK_SAFEMODE, &raw mut cmd) == 0 }
}

fn scan_driver_fd() -> Option<DriverFd> {
    let fd_dir = fs::read_dir("/proc/self/fd").ok()?;

    for entry in fd_dir.flatten() {
        if let Ok(fd_num) = entry.file_name().to_string_lossy().parse::<i32>() {
            let link_path = format!("/proc/self/fd/{fd_num}");
            if let Ok(target) = fs::read_link(&link_path) {
                let target_str = target.to_string_lossy();
                if KSU_DRIVER_FD_NAMES
                    .iter()
                    .any(|name| target_str.contains(name))
                    && is_valid_driver_fd(fd_num)
                {
                    return Some(DriverFd {
                        fd: fd_num,
                        owned: false,
                    });
                }
            }
        }
    }

    None
}

// Get cached driver fd
fn init_driver_fd() -> Option<DriverFd> {
    let fd = scan_driver_fd();
    if fd.is_none() {
        let mut fd = -1;
        unsafe {
            libc::syscall(
                libc::SYS_reboot,
                KSU_INSTALL_MAGIC1,
                KSU_INSTALL_MAGIC2,
                0,
                &mut fd,
            );
        };
        if fd >= 0 {
            Some(DriverFd { fd, owned: true })
        } else {
            None
        }
    } else {
        fd
    }
}

fn get_driver_fd() -> std::io::Result<RawFd> {
    let cached = DRIVER_FD.load(Ordering::Acquire);
    if cached >= 0 {
        return Ok(cached);
    }

    if let Some(driver_fd) = init_driver_fd() {
        let fd = driver_fd.fd;
        let _ = DRIVER_FD.compare_exchange(-1, fd, Ordering::AcqRel, Ordering::Acquire);
        let now = DRIVER_FD.load(Ordering::Acquire);
        if now >= 0 {
            if driver_fd.owned && now != fd {
                unsafe {
                    libc::close(fd);
                }
            }
            return Ok(now);
        }
        return Ok(fd);
    }

    Err(std::io::Error::from_raw_os_error(libc::ENODEV))
}

// ioctl wrapper using libc
fn ksuctl<T>(request: i32, arg: *mut T) -> std::io::Result<i32> {
    use std::io;

    unsafe fn ioctl_once<T>(fd: RawFd, request: i32, arg: *mut T) -> std::io::Result<i32> {
        let ret = unsafe { libc::ioctl(fd as libc::c_int, request, arg) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }

    let fd = get_driver_fd()?;
    match unsafe { ioctl_once(fd, request, arg) } {
        Ok(ret) => Ok(ret),
        Err(err) if matches!(err.raw_os_error(), Some(libc::EBADF) | Some(libc::ENOTTY)) => {
            // Cached fd may be stale after process lifecycle changes.
            DRIVER_FD.store(-1, Ordering::Release);
            let new_fd = get_driver_fd()?;
            unsafe { ioctl_once(new_fd, request, arg) }
        }
        Err(err) => Err(err),
    }
}

fn write_cstr_fixed(dst: &mut [u8], value: &str) -> std::io::Result<()> {
    if value.as_bytes().contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "string contains NUL byte",
        ));
    }
    if value.len() >= dst.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "string too long for fixed-size field",
        ));
    }

    dst.fill(0);
    dst[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}

// API implementations
fn get_info() -> GetInfoCmd {
    let mut cmd = GetInfoCmd {
        version: 0,
        flags: 0,
        features: 0,
    };
    let _ = ksuctl(KSU_IOCTL_GET_INFO, &raw mut cmd);
    cmd
}

pub fn get_version() -> i32 {
    get_info().version as i32
}

pub fn grant_root() -> std::io::Result<()> {
    ksuctl(KSU_IOCTL_GRANT_ROOT, std::ptr::null_mut::<u8>())?;
    Ok(())
}

fn report_event(event: u32) {
    let mut cmd = ReportEventCmd { event };
    let _ = ksuctl(KSU_IOCTL_REPORT_EVENT, &raw mut cmd);
}

pub fn report_post_fs_data() {
    report_event(EVENT_POST_FS_DATA);
}

pub fn report_boot_complete() {
    report_event(EVENT_BOOT_COMPLETED);
}

pub fn report_module_mounted() {
    report_event(EVENT_MODULE_MOUNTED);
}

pub fn check_kernel_safemode() -> bool {
    let mut cmd = CheckSafemodeCmd { in_safe_mode: 0 };
    let _ = ksuctl(KSU_IOCTL_CHECK_SAFEMODE, &raw mut cmd);
    cmd.in_safe_mode != 0
}

pub fn set_sepolicy(cmd: &SetSepolicyCmd) -> std::io::Result<()> {
    let mut ioctl_cmd = *cmd;
    ksuctl(KSU_IOCTL_SET_SEPOLICY, &raw mut ioctl_cmd)?;
    Ok(())
}

/// Get feature value and support status from kernel
/// Returns (value, supported)
pub fn get_feature(feature_id: u32) -> std::io::Result<(u64, bool)> {
    let mut cmd = GetFeatureCmd {
        feature_id,
        value: 0,
        supported: 0,
    };
    ksuctl(KSU_IOCTL_GET_FEATURE, &raw mut cmd)?;
    Ok((cmd.value, cmd.supported != 0))
}

/// Set feature value in kernel
pub fn set_feature(feature_id: u32, value: u64) -> std::io::Result<()> {
    let mut cmd = SetFeatureCmd { feature_id, value };
    ksuctl(KSU_IOCTL_SET_FEATURE, &raw mut cmd)?;
    Ok(())
}

pub fn get_wrapped_fd(fd: RawFd) -> std::io::Result<RawFd> {
    let mut cmd = GetWrapperFdCmd { fd, flags: 0 };
    let result = ksuctl(KSU_IOCTL_GET_WRAPPER_FD, &raw mut cmd)?;
    Ok(result)
}

/// Get mark status for a process (pid=0 returns total marked count)
pub fn mark_get(pid: i32) -> std::io::Result<u32> {
    let mut cmd = ManageMarkCmd {
        operation: KSU_MARK_GET,
        pid,
        result: 0,
    };
    ksuctl(KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(cmd.result)
}

/// Mark a process (pid=0 marks all processes)
pub fn mark_set(pid: i32) -> std::io::Result<()> {
    let mut cmd = ManageMarkCmd {
        operation: KSU_MARK_MARK,
        pid,
        result: 0,
    };
    ksuctl(KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Unmark a process (pid=0 unmarks all processes)
pub fn mark_unset(pid: i32) -> std::io::Result<()> {
    let mut cmd = ManageMarkCmd {
        operation: KSU_MARK_UNMARK,
        pid,
        result: 0,
    };
    ksuctl(KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Refresh mark for all running processes
pub fn mark_refresh() -> std::io::Result<()> {
    let mut cmd = ManageMarkCmd {
        operation: KSU_MARK_REFRESH,
        pid: 0,
        result: 0,
    };
    ksuctl(KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

pub fn nuke_ext4_sysfs(mnt: &str) -> anyhow::Result<()> {
    let c_mnt = std::ffi::CString::new(mnt)?;
    let mut ioctl_cmd = NukeExt4SysfsCmd {
        arg: c_mnt.as_ptr() as u64,
    };
    ksuctl(KSU_IOCTL_NUKE_EXT4_SYSFS, &raw mut ioctl_cmd)?;
    Ok(())
}

/// Wipe all entries from umount list
pub fn umount_list_wipe() -> std::io::Result<()> {
    let mut cmd = AddTryUmountCmd {
        arg: 0,
        flags: 0,
        mode: KSU_UMOUNT_WIPE,
    };
    ksuctl(KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Add mount point to umount list
pub fn umount_list_add(path: &str, flags: u32) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = AddTryUmountCmd {
        arg: c_path.as_ptr() as u64,
        flags,
        mode: KSU_UMOUNT_ADD,
    };
    ksuctl(KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Delete mount point from umount list
pub fn umount_list_del(path: &str) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = AddTryUmountCmd {
        arg: c_path.as_ptr() as u64,
        flags: 0,
        mode: KSU_UMOUNT_DEL,
    };
    ksuctl(KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Mark a specific PID as stealth.
pub fn stealth_pid_mark(pid: i32) -> std::io::Result<()> {
    let mut cmd = StealthPidCmd {
        operation: STEALTH_PID_MARK,
        pid,
        fake_comm: [0; 128],
        fake_exe: [0; 128],
    };
    ksuctl(KSU_IOCTL_STEALTH_PID, &raw mut cmd)?;
    Ok(())
}

/// Unmark a specific PID from stealth state.
pub fn stealth_pid_unmark(pid: i32) -> std::io::Result<()> {
    let mut cmd = StealthPidCmd {
        operation: STEALTH_PID_UNMARK,
        pid,
        fake_comm: [0; 128],
        fake_exe: [0; 128],
    };
    ksuctl(KSU_IOCTL_STEALTH_PID, &raw mut cmd)?;
    Ok(())
}

/// Mark current process as stealth.
pub fn stealth_pid_mark_self() -> std::io::Result<()> {
    let mut cmd = StealthPidCmd {
        operation: STEALTH_PID_MARK_SELF,
        pid: 0,
        fake_comm: [0; 128],
        fake_exe: [0; 128],
    };
    ksuctl(KSU_IOCTL_STEALTH_PID, &raw mut cmd)?;
    Ok(())
}

/// Set stealth disguise fields for a PID.
pub fn stealth_pid_disguise(
    pid: i32,
    fake_comm: Option<&str>,
    fake_exe: Option<&str>,
) -> std::io::Result<()> {
    let mut cmd = StealthPidCmd {
        operation: STEALTH_PID_DISGUISE,
        pid,
        fake_comm: [0; 128],
        fake_exe: [0; 128],
    };

    if let Some(comm) = fake_comm {
        write_cstr_fixed(&mut cmd.fake_comm, comm)?;
    }
    if let Some(exe) = fake_exe {
        write_cstr_fixed(&mut cmd.fake_exe, exe)?;
    }

    ksuctl(KSU_IOCTL_STEALTH_PID, &raw mut cmd)?;
    Ok(())
}

/// Register a loaded module into stealth module registry.
pub fn stealth_register_module(name: &str) -> std::io::Result<()> {
    let mut cmd = StealthRegisterModCmd { name: [0; 64] };
    write_cstr_fixed(&mut cmd.name, name)?;
    ksuctl(KSU_IOCTL_STEALTH_REGISTER_MOD, &raw mut cmd)?;
    Ok(())
}

/// Mark current process as stealth through dedicated STEALTH_EXEC ioctl.
pub fn stealth_exec_mark_self() -> std::io::Result<()> {
    ksuctl(KSU_IOCTL_STEALTH_EXEC, std::ptr::null_mut::<u8>())?;
    Ok(())
}

/// Probe stealth IPC routing path.
/// A return code of ENOENT means IPC channel is reachable but no module handler is registered.
pub fn stealth_ipc_probe(module_id: &str) -> std::io::Result<()> {
    let mut cmd = StealthIpcCmd {
        module_id: [0; 64],
        subcmd: 0,
        data: 0,
        data_len: 0,
    };
    write_cstr_fixed(&mut cmd.module_id, module_id)?;
    ksuctl(KSU_IOCTL_STEALTH_IPC, &raw mut cmd)?;
    Ok(())
}
