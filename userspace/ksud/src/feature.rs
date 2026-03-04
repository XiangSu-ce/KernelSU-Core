use anyhow::{Context, Result, bail};
use const_format::concatcp;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::defs;

const FEATURE_CONFIG_PATH: &str = concatcp!(defs::WORKING_DIR, ".feature_config");
#[allow(clippy::unreadable_literal)]
const FEATURE_MAGIC: u32 = 0x7f4b5355;
const FEATURE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FeatureId {
    SuCompat = 0,
    KernelUmount = 1,
    PropSpoof = 2,
    ProcHide = 3,
    DebugDisable = 4,
    LogSilent = 5,
    SymbolHide = 6,
    MountSanitize = 7,
    StealthFilterIo = 8,
    StealthModloader = 9,
    StealthExec = 10,
    StealthFileio = 11,
    StealthIpc = 12,
}

impl FeatureId {
    pub const ALL: [Self; 13] = [
        Self::SuCompat,
        Self::KernelUmount,
        Self::PropSpoof,
        Self::ProcHide,
        Self::DebugDisable,
        Self::LogSilent,
        Self::SymbolHide,
        Self::MountSanitize,
        Self::StealthFilterIo,
        Self::StealthModloader,
        Self::StealthExec,
        Self::StealthFileio,
        Self::StealthIpc,
    ];

    pub const fn from_u32(id: u32) -> Option<Self> {
        match id {
            0 => Some(Self::SuCompat),
            1 => Some(Self::KernelUmount),
            2 => Some(Self::PropSpoof),
            3 => Some(Self::ProcHide),
            4 => Some(Self::DebugDisable),
            5 => Some(Self::LogSilent),
            6 => Some(Self::SymbolHide),
            7 => Some(Self::MountSanitize),
            8 => Some(Self::StealthFilterIo),
            9 => Some(Self::StealthModloader),
            10 => Some(Self::StealthExec),
            11 => Some(Self::StealthFileio),
            12 => Some(Self::StealthIpc),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::SuCompat => "su_compat",
            Self::KernelUmount => "kernel_umount",
            Self::PropSpoof => "prop_spoof",
            Self::ProcHide => "proc_hide",
            Self::DebugDisable => "debug_disable",
            Self::LogSilent => "log_silent",
            Self::SymbolHide => "symbol_hide",
            Self::MountSanitize => "mount_sanitize",
            Self::StealthFilterIo => "stealth_filter_io",
            Self::StealthModloader => "stealth_modloader",
            Self::StealthExec => "stealth_exec",
            Self::StealthFileio => "stealth_fileio",
            Self::StealthIpc => "stealth_ipc",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::SuCompat => {
                "SU Compatibility Mode - allows authorized apps to gain root via traditional 'su' command"
            }
            Self::KernelUmount => {
                "Kernel Umount - controls whether kernel automatically unmounts modules when not needed"
            }
            Self::PropSpoof => {
                "Property Spoofing - masks root and bootloader related system properties"
            }
            Self::ProcHide => {
                "Process Hiding - filters /proc output to reduce root detection traces"
            }
            Self::DebugDisable => {
                "Debug Disable - restricts ptrace, dmesg, and kernel pointer exposure"
            }
            Self::LogSilent => "Log Silent - sanitizes kernel log output for untrusted readers",
            Self::SymbolHide => {
                "Symbol Hide - hides KernelSU-related symbols from public symbol tables"
            }
            Self::MountSanitize => {
                "Mount Sanitize - removes KernelSU mount traces from mount listings"
            }
            Self::StealthFilterIo => {
                "Stealth Filter I/O - filters stealth process I/O stats and lock visibility"
            }
            Self::StealthModloader => {
                "Stealth Modloader - controls stealth module loading and registration pipeline"
            }
            Self::StealthExec => {
                "Stealth Exec - controls stealth PID marking and disguised process execution"
            }
            Self::StealthFileio => {
                "Stealth File I/O - controls stealth file access trace suppression hooks"
            }
            Self::StealthIpc => {
                "Stealth IPC - controls stealth inter-process communication routing"
            }
        }
    }
}

fn parse_feature_id(name: &str) -> Result<FeatureId> {
    if let Ok(id) = name.parse::<u32>() {
        return FeatureId::from_u32(id).ok_or_else(|| anyhow::anyhow!("Unknown feature id: {id}"));
    }

    for feature in FeatureId::ALL {
        if feature.name() == name {
            return Ok(feature);
        }
    }

    bail!("Unknown feature: {name}")
}

pub fn load_binary_config() -> Result<HashMap<u32, u64>> {
    let path = Path::new(FEATURE_CONFIG_PATH);
    if !path.exists() {
        log::info!("Feature config not found, using defaults");
        return Ok(HashMap::new());
    }

    let mut file = File::open(path).with_context(|| "Failed to open feature config")?;

    let mut magic_buf = [0u8; 4];
    file.read_exact(&mut magic_buf)
        .with_context(|| "Failed to read magic")?;
    let magic = u32::from_le_bytes(magic_buf);

    if magic != FEATURE_MAGIC {
        bail!("Invalid feature config magic: expected 0x{FEATURE_MAGIC:08x}, got 0x{magic:08x}",);
    }

    let mut version_buf = [0u8; 4];
    file.read_exact(&mut version_buf)
        .with_context(|| "Failed to read version")?;
    let version = u32::from_le_bytes(version_buf);

    if version != FEATURE_VERSION {
        log::warn!(
            "Feature config version mismatch: expected {FEATURE_VERSION}, got {version
            }",
        );
    }

    let mut count_buf = [0u8; 4];
    file.read_exact(&mut count_buf)
        .with_context(|| "Failed to read count")?;
    let count = u32::from_le_bytes(count_buf);

    let mut features = HashMap::new();
    for _ in 0..count {
        let mut id_buf = [0u8; 4];
        let mut value_buf = [0u8; 8];

        file.read_exact(&mut id_buf)
            .with_context(|| "Failed to read feature id")?;
        file.read_exact(&mut value_buf)
            .with_context(|| "Failed to read feature value")?;

        let id = u32::from_le_bytes(id_buf);
        let value = u64::from_le_bytes(value_buf);

        features.insert(id, value);
    }

    log::info!("Loaded {} features from config", features.len());
    Ok(features)
}

pub fn save_binary_config(features: &HashMap<u32, u64>) -> Result<()> {
    crate::utils::ensure_dir_exists(Path::new(defs::WORKING_DIR))?;

    let path = Path::new(FEATURE_CONFIG_PATH);
    let mut file = File::create(path).with_context(|| "Failed to create feature config")?;

    file.write_all(&FEATURE_MAGIC.to_le_bytes())
        .with_context(|| "Failed to write magic")?;

    file.write_all(&FEATURE_VERSION.to_le_bytes())
        .with_context(|| "Failed to write version")?;

    let count = features.len() as u32;
    file.write_all(&count.to_le_bytes())
        .with_context(|| "Failed to write count")?;

    for (&id, &value) in features {
        file.write_all(&id.to_le_bytes())
            .with_context(|| format!("Failed to write feature id {id}"))?;
        file.write_all(&value.to_le_bytes())
            .with_context(|| format!("Failed to write feature value for id {id}"))?;
    }

    file.sync_all()
        .with_context(|| "Failed to sync feature config")?;

    log::info!("Saved {} features to config", features.len());
    Ok(())
}

pub fn apply_config(features: &HashMap<u32, u64>) {
    log::info!("Applying feature configuration to kernel...");

    let mut applied = 0;
    for (&id, &value) in features {
        match crate::ksucalls::set_feature(id, value) {
            Ok(()) => {
                if let Some(feature_id) = FeatureId::from_u32(id) {
                    log::info!("Set feature {} to {value}", feature_id.name());
                } else {
                    log::info!("Set feature {id} to {value}");
                }
                applied += 1;
            }
            Err(e) => {
                log::warn!("Failed to set feature {id}: {e}");
            }
        }
    }

    log::info!("Applied {applied} features successfully");
}

pub fn get_feature(id: &str) -> Result<()> {
    let feature_id = parse_feature_id(id)?;
    let (value, supported) = crate::ksucalls::get_feature(feature_id as u32)
        .with_context(|| format!("Failed to get feature {id}"))?;

    if !supported {
        println!("Feature '{id}' is not supported by kernel");
        return Ok(());
    }

    println!("Feature: {} ({})", feature_id.name(), feature_id as u32);
    println!("Description: {}", feature_id.description());
    println!("Value: {value}");
    println!(
        "Status: {}",
        if value != 0 { "enabled" } else { "disabled" }
    );

    Ok(())
}

pub fn get_feature_config(id: &str) -> Result<()> {
    let feature_id = parse_feature_id(id)?;

    let features = load_binary_config()?;
    let id_u32 = feature_id as u32;

    println!("Feature: {} ({})", feature_id.name(), id_u32);
    println!("Description: {}", feature_id.description());

    if let Some(value) = features.get(&id_u32) {
        println!("Value: {value}");
        println!(
            "Status: {}",
            if *value != 0 { "enabled" } else { "disabled" }
        );
    } else {
        println!("Not set in config");
    }

    Ok(())
}

pub fn set_feature(id: &str, value: u64) -> Result<()> {
    let feature_id = parse_feature_id(id)?;

    // Check if this feature is managed by any module
    if let Ok(managed_features_map) = crate::module::get_managed_features() {
        // Find which modules manage this feature
        let managing_modules: Vec<&String> = managed_features_map
            .iter()
            .filter(|(_, features)| features.iter().any(|f| f == feature_id.name()))
            .map(|(module_id, _)| module_id)
            .collect();

        if !managing_modules.is_empty() {
            // Feature is managed, check if caller is an authorized module
            let caller_module = std::env::var("KSU_MODULE").unwrap_or_default();

            if caller_module.is_empty() || !managing_modules.contains(&&caller_module) {
                bail!(
                    "Feature '{}' is managed by module(s): {}. Direct modification is not allowed.",
                    feature_id.name(),
                    managing_modules
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            log::info!(
                "Module '{caller_module}' is setting managed feature '{}'",
                feature_id.name()
            );
        }
    }

    crate::ksucalls::set_feature(feature_id as u32, value)
        .with_context(|| format!("Failed to set feature {id} to {value}"))?;

    if feature_id == FeatureId::PropSpoof && value != 0 {
        crate::prop_spoof::apply_if_enabled().with_context(|| {
            "prop_spoof was enabled but runtime property apply failed"
        })?;
    }

    println!(
        "Feature '{}' set to {value} ({})",
        feature_id.name(),
        if value != 0 { "enabled" } else { "disabled" }
    );

    Ok(())
}

pub fn list_features() {
    println!("Available Features:");
    println!("{}", "=".repeat(80));

    // Get managed features from modules
    let managed_features_map = crate::module::get_managed_features().unwrap_or_default();

    // Build a reverse map: feature_name -> Vec<module_id>
    let mut feature_to_modules: HashMap<String, Vec<String>> = HashMap::new();
    for (module_id, feature_list) in &managed_features_map {
        for feature_name in feature_list {
            feature_to_modules
                .entry(feature_name.clone())
                .or_default()
                .push(module_id.clone());
        }
    }

    for feature_id in &FeatureId::ALL {
        let id = *feature_id as u32;
        let (value, supported) = crate::ksucalls::get_feature(id).unwrap_or((0, false));

        let status = if !supported {
            "NOT_SUPPORTED".to_string()
        } else if value != 0 {
            format!("ENABLED ({value})")
        } else {
            "DISABLED".to_string()
        };

        let managed_by = feature_to_modules.get(feature_id.name());
        let managed_mark = if managed_by.is_some() {
            " [MODULE_MANAGED]"
        } else {
            ""
        };

        println!(
            "[{}] {} (ID={}){}",
            status,
            feature_id.name(),
            id,
            managed_mark
        );
        println!("    {}", feature_id.description());

        if let Some(modules) = managed_by {
            println!(
                "    [WARNING] Managed by module(s): {} (forced to 0 on initialization)",
                modules.join(", ")
            );
        }

        println!();
    }
}

pub fn load_config_and_apply() -> Result<()> {
    let features = load_binary_config()?;

    if features.is_empty() {
        println!("No features found in config file");
        return Ok(());
    }

    apply_config(&features);
    println!("Feature configuration loaded and applied");
    Ok(())
}

pub fn save_config() -> Result<()> {
    let mut features = HashMap::new();

    for feature_id in &FeatureId::ALL {
        let id = *feature_id as u32;
        if let Ok((value, supported)) = crate::ksucalls::get_feature(id)
            && supported
        {
            features.insert(id, value);
            log::info!("Saved feature {} = {value}", feature_id.name());
        }
    }

    save_binary_config(&features)?;
    println!(
        "Current feature states saved to config file ({} features)",
        features.len()
    );
    Ok(())
}

pub fn check_feature(id: &str) -> Result<()> {
    let feature_id = parse_feature_id(id)?;

    // Check if this feature is managed by any module
    let managed_features_map = crate::module::get_managed_features().unwrap_or_default();
    let is_managed = managed_features_map
        .values()
        .any(|features| features.iter().any(|f| f == feature_id.name()));

    if is_managed {
        println!("managed");
        return Ok(());
    }

    // Check if the feature is supported by kernel
    let (_value, supported) = crate::ksucalls::get_feature(feature_id as u32)
        .with_context(|| format!("Failed to get feature {id}"))?;

    if supported {
        println!("supported");
    } else {
        println!("unsupported");
    }

    Ok(())
}

pub fn init_features() -> Result<()> {
    log::info!("Initializing features from config...");

    let mut features = load_binary_config()?;

    // Get managed features from active modules and skip them during init
    if let Ok(managed_features_map) = crate::module::get_managed_features() {
        if !managed_features_map.is_empty() {
            log::info!(
                "Found {} modules managing features",
                managed_features_map.len()
            );

            // Build a set of all managed feature IDs to skip
            for (module_id, feature_list) in &managed_features_map {
                log::info!(
                    "Module '{module_id}' manages {} feature(s)",
                    feature_list.len()
                );

                for feature_name in feature_list {
                    if let Ok(feature_id) = parse_feature_id(feature_name) {
                        let feature_id_u32 = feature_id as u32;
                        // Remove managed features from config, let modules control them
                        if features.remove(&feature_id_u32).is_some() {
                            log::info!(
                                "  - Skipping managed feature '{feature_name}' (controlled by module: {module_id})",
                            );
                        } else {
                            log::info!(
                                "  - Feature '{feature_name}' is managed by module '{module_id}', skipping",
                            );
                        }
                    } else {
                        log::warn!(
                            "  - Unknown managed feature '{feature_name}' from module '{module_id}', ignoring",
                        );
                    }
                }
            }
        }
    } else {
        log::warn!(
            "Failed to get managed features from modules, continuing with normal initialization"
        );
    }

    if features.is_empty() {
        log::info!("No features to apply, skipping initialization");
        return Ok(());
    }

    apply_config(&features);

    // Save the configuration (excluding managed features)
    save_binary_config(&features)?;
    log::info!("Saved feature configuration to file");

    Ok(())
}
