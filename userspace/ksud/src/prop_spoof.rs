use anyhow::{Context, Result};
use log::{info, warn};
use std::process::Command;

use crate::{assets, ksucalls};

const PROP_SPOOF_FEATURE_ID: u32 = 2;

const SPOOF_RULES: [(&str, &str); 12] = [
    ("ro.debuggable", "0"),
    ("ro.secure", "1"),
    ("ro.boot.flash.locked", "1"),
    ("ro.boot.vbmeta.device_state", "locked"),
    ("ro.boot.verifiedbootstate", "green"),
    ("ro.boot.veritymode", "enforcing"),
    ("sys.oem_unlock_allowed", "0"),
    ("ro.build.type", "user"),
    ("ro.build.tags", "release-keys"),
    ("ro.build.selinux", "1"),
    ("ro.adb.secure", "1"),
    ("service.adb.root", "0"),
];

fn is_prop_spoof_enabled() -> Result<bool> {
    let (value, supported) = ksucalls::get_feature(PROP_SPOOF_FEATURE_ID)?;
    Ok(supported && value != 0)
}

pub fn apply_if_enabled() -> Result<()> {
    if !is_prop_spoof_enabled()? {
        info!("prop_spoof disabled, skip built-in property spoof apply");
        return Ok(());
    }

    assets::ensure_binaries(true)
        .with_context(|| "failed to ensure resetprop binary for prop_spoof apply")?;

    let mut applied = 0usize;
    let mut failed = 0usize;

    for (name, value) in SPOOF_RULES {
        match Command::new(assets::RESETPROP_PATH)
            .arg("-n")
            .arg(name)
            .arg(value)
            .status()
        {
            Ok(status) if status.success() => {
                applied += 1;
            }
            Ok(status) => {
                failed += 1;
                warn!("prop_spoof apply failed for {name}: exit={status}");
            }
            Err(e) => {
                failed += 1;
                warn!("prop_spoof apply failed for {name}: {e}");
            }
        }
    }

    if failed == 0 {
        info!("prop_spoof applied successfully ({applied} rules)");
    } else {
        warn!("prop_spoof applied with failures: success={applied}, failed={failed}");
    }

    Ok(())
}
