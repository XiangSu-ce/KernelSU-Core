use crate::utils::ensure_dir_exists;
use crate::{defs, sepolicy};
use anyhow::{Context, Result, ensure};
use std::path::Path;

fn validate_profile_key(key: &str, field: &str) -> Result<()> {
    ensure!(!key.is_empty(), "{field} cannot be empty");
    ensure!(!key.contains('/'), "{field} cannot contain '/'");
    ensure!(!key.contains('\\'), "{field} cannot contain '\\\\'");
    ensure!(!key.contains(".."), "{field} cannot contain '..'");
    Ok(())
}

pub fn set_sepolicy(pkg: String, policy: String) -> Result<()> {
    validate_profile_key(&pkg, "package name")?;
    ensure_dir_exists(defs::PROFILE_SELINUX_DIR)?;
    let policy_file = Path::new(defs::PROFILE_SELINUX_DIR).join(pkg);
    std::fs::write(&policy_file, policy)?;
    sepolicy::apply_file(&policy_file)?;
    Ok(())
}

pub fn get_sepolicy(pkg: String) -> Result<()> {
    validate_profile_key(&pkg, "package name")?;
    let policy_file = Path::new(defs::PROFILE_SELINUX_DIR).join(pkg);
    let policy = std::fs::read_to_string(policy_file)?;
    println!("{policy}");
    Ok(())
}

// ksud doesn't guarteen the correctness of template, it just save
pub fn set_template(id: String, template: String) -> Result<()> {
    validate_profile_key(&id, "template id")?;
    ensure_dir_exists(defs::PROFILE_TEMPLATE_DIR)?;
    let template_file = Path::new(defs::PROFILE_TEMPLATE_DIR).join(id);
    std::fs::write(template_file, template)?;
    Ok(())
}

pub fn get_template(id: String) -> Result<()> {
    validate_profile_key(&id, "template id")?;
    let template_file = Path::new(defs::PROFILE_TEMPLATE_DIR).join(id);
    let template = std::fs::read_to_string(template_file)?;
    println!("{template}");
    Ok(())
}

pub fn delete_template(id: String) -> Result<()> {
    validate_profile_key(&id, "template id")?;
    let template_file = Path::new(defs::PROFILE_TEMPLATE_DIR).join(id);
    std::fs::remove_file(template_file)?;
    Ok(())
}

pub fn list_templates() -> Result<()> {
    let templates = std::fs::read_dir(defs::PROFILE_TEMPLATE_DIR);
    let Ok(templates) = templates else {
        return Ok(());
    };
    let mut names = Vec::new();
    for template in templates {
        let template = template?;
        if let Some(template) = template.file_name().to_str() {
            names.push(template.to_string());
        }
    }
    names.sort();
    for template in names {
        println!("{template}");
    }
    Ok(())
}

pub fn apply_sepolies() -> Result<()> {
    let path = Path::new(defs::PROFILE_SELINUX_DIR);
    if !path.exists() {
        log::info!("profile sepolicy dir not exists.");
        return Ok(());
    }

    let sepolicies =
        std::fs::read_dir(path).with_context(|| "profile sepolicy dir open failed.".to_string())?;
    let mut entries: Vec<_> = sepolicies.flatten().collect();
    entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    for sepolicy in entries {
        let sepolicy = sepolicy.path();
        if !sepolicy.is_file() {
            log::debug!("skip non-file entry: {}", sepolicy.display());
            continue;
        }
        if sepolicy::apply_file(&sepolicy).is_ok() {
            log::info!("profile sepolicy applied: {}", sepolicy.display());
        } else {
            log::info!("profile sepolicy apply failed: {}", sepolicy.display());
        }
    }
    Ok(())
}
