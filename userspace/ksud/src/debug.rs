use anyhow::{Context, Result, bail, ensure};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

use crate::ksucalls;

const KERNEL_PARAM_PATH: &str = "/sys/module/kernelsu";

fn read_u32(path: &PathBuf) -> Result<u32> {
    let content = std::fs::read_to_string(path)?;
    let content = content.trim();
    let content = content.parse::<u32>()?;
    Ok(content)
}

fn set_kernel_param(uid: u32) -> Result<()> {
    let kernel_param_path = Path::new(KERNEL_PARAM_PATH).join("parameters");

    let ksu_debug_manager_uid = kernel_param_path.join("ksu_debug_manager_uid");
    let before_uid = read_u32(&ksu_debug_manager_uid)?;
    std::fs::write(&ksu_debug_manager_uid, uid.to_string())?;
    let after_uid = read_u32(&ksu_debug_manager_uid)?;

    println!("set manager uid: {before_uid} -> {after_uid}");

    Ok(())
}

fn get_pkg_uid(pkg: &str) -> Result<u32> {
    // stat /data/data/<pkg>
    let uid = rustix::fs::stat(format!("/data/data/{pkg}"))
        .with_context(|| format!("stat /data/data/{pkg}"))?
        .st_uid;
    Ok(uid)
}

pub fn set_manager(pkg: &str) -> Result<()> {
    ensure!(
        Path::new(KERNEL_PARAM_PATH).exists(),
        "CONFIG_KSU_DEBUG is not enabled"
    );

    let uid = get_pkg_uid(pkg)?;
    set_kernel_param(uid)?;
    // force-stop it
    let _ = Command::new("am").args(["force-stop", pkg]).status();
    Ok(())
}

/// Get mark status for a process
pub fn mark_get(pid: i32) -> Result<()> {
    let result = ksucalls::mark_get(pid)?;
    if pid == 0 {
        bail!("Please specify a pid to get its mark status");
    }
    println!(
        "Process {pid} mark status: {}",
        if result != 0 { "marked" } else { "unmarked" }
    );
    Ok(())
}

/// Mark a process
pub fn mark_set(pid: i32) -> Result<()> {
    ksucalls::mark_set(pid)?;
    if pid == 0 {
        println!("All processes marked successfully");
    } else {
        println!("Process {pid} marked successfully");
    }
    Ok(())
}

/// Unmark a process
pub fn mark_unset(pid: i32) -> Result<()> {
    ksucalls::mark_unset(pid)?;
    if pid == 0 {
        println!("All processes unmarked successfully");
    } else {
        println!("Process {pid} unmarked successfully");
    }
    Ok(())
}

/// Refresh mark for all running processes
pub fn mark_refresh() -> Result<()> {
    ksucalls::mark_refresh()?;
    println!("Refreshed mark for all running processes");
    Ok(())
}

pub fn stealth_pid_mark(pid: i32) -> Result<()> {
    ensure!(pid > 0, "pid must be greater than 0");
    ksucalls::stealth_pid_mark(pid)?;
    println!("Stealth PID mark success: {pid}");
    Ok(())
}

pub fn stealth_pid_unmark(pid: i32) -> Result<()> {
    ensure!(pid > 0, "pid must be greater than 0");
    ksucalls::stealth_pid_unmark(pid)?;
    println!("Stealth PID unmark success: {pid}");
    Ok(())
}

pub fn stealth_pid_mark_self() -> Result<()> {
    ksucalls::stealth_pid_mark_self()?;
    println!("Current process marked as stealth");
    Ok(())
}

pub fn stealth_pid_disguise(
    pid: i32,
    fake_comm: Option<&str>,
    fake_exe: Option<&str>,
) -> Result<()> {
    ensure!(pid > 0, "pid must be greater than 0");
    if let Some(comm) = fake_comm {
        ensure!(!comm.trim().is_empty(), "fake_comm must not be empty");
    }
    if let Some(exe) = fake_exe {
        ensure!(!exe.trim().is_empty(), "fake_exe must not be empty");
    }
    ksucalls::stealth_pid_disguise(pid, fake_comm, fake_exe)?;
    println!("Stealth disguise set for pid {pid}: comm={fake_comm:?}, exe={fake_exe:?}");
    Ok(())
}

pub fn stealth_register_module(name: &str) -> Result<()> {
    ensure!(!name.trim().is_empty(), "module name must not be empty");
    ksucalls::stealth_register_module(name)?;
    println!("Stealth module register success: {name}");
    Ok(())
}

pub fn stealth_exec_mark_self() -> Result<()> {
    ksucalls::stealth_exec_mark_self()?;
    println!("Stealth exec mark-self success");
    Ok(())
}

pub fn stealth_ipc_probe(module_id: &str) -> Result<()> {
    ensure!(!module_id.trim().is_empty(), "module_id must not be empty");
    match ksucalls::stealth_ipc_probe(module_id) {
        Ok(()) => {
            println!("Stealth IPC probe dispatched successfully for module '{module_id}'");
            Ok(())
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            println!(
                "Stealth IPC channel reachable; no handler registered for module '{module_id}' (ENOENT)"
            );
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

pub fn stealth_smoke(pid: i32, fake_comm: &str, fake_exe: &str, module_id: &str) -> Result<()> {
    ensure!(pid > 0, "pid must be greater than 0");
    ensure!(!fake_comm.trim().is_empty(), "fake_comm must not be empty");
    ensure!(!fake_exe.trim().is_empty(), "fake_exe must not be empty");
    ensure!(!module_id.trim().is_empty(), "module_id must not be empty");

    ksucalls::stealth_pid_mark(pid).context("stealth smoke: mark pid failed")?;
    let mut final_result: Result<()> =
        if let Err(e) = ksucalls::stealth_pid_disguise(pid, Some(fake_comm), Some(fake_exe)) {
            Err(e).context("stealth smoke: disguise failed")
        } else {
            Ok(())
        };

    if final_result.is_ok()
        && let Err(e) = ksucalls::stealth_ipc_probe(module_id)
        && e.raw_os_error() != Some(libc::ENOENT)
    {
        final_result = Err(e).context("stealth smoke: ipc probe failed");
    }

    if final_result.is_ok()
        && let Err(e) = ksucalls::stealth_exec_mark_self()
    {
        final_result = Err(e).context("stealth smoke: exec mark-self failed");
    }

    let cleanup_result = ksucalls::stealth_pid_unmark(pid);
    if let Err(e) = cleanup_result {
        if final_result.is_ok() {
            final_result = Err(e).context("stealth smoke: cleanup unmark failed");
        } else {
            eprintln!("warning: stealth smoke cleanup unmark failed for pid {pid}: {e}");
        }
    }

    final_result?;
    println!("Stealth smoke check success (pid={pid}, module_id={module_id})");
    Ok(())
}

pub fn apply_prop_spoof() -> Result<()> {
    crate::prop_spoof::apply_if_enabled()?;
    println!("prop_spoof apply finished (applies only when feature is enabled)");
    Ok(())
}
