use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn get_git_version() -> Result<(u32, String), std::io::Error> {
    let output = Command::new("git")
        .args(["rev-list", "--count", "HEAD"])
        .output()?;

    let output = output.stdout;
    let version_code = String::from_utf8(output)
        .map_err(|_| std::io::Error::other("Failed to decode git count stdout"))?;
    let version_code: u32 = version_code
        .trim()
        .parse()
        .map_err(|_| std::io::Error::other("Failed to parse git count"))?;
    let version_code = 30000 + version_code;

    let version_name = String::from_utf8(
        Command::new("git")
            .args(["describe", "--tags", "--always"])
            .output()?
            .stdout,
    )
    .map_err(|_| std::io::Error::other("Failed to read git describe stdout"))?;
    let version_name = version_name.trim_start_matches('v').to_string();
    Ok((version_code, version_name))
}

fn main() {
    let (code, name) = match get_git_version() {
        Ok((code, name)) => (code, name),
        Err(_) => {
            // show warning if git is not installed
            println!("cargo:warning=Failed to get git version, using 0.0.0");
            (0, "0.0.0".to_string())
        }
    };
    let out_dir = match env::var("OUT_DIR") {
        Ok(v) => v,
        Err(e) => {
            println!("cargo:warning=Failed to get OUT_DIR: {e}");
            return;
        }
    };
    let out_dir = Path::new(&out_dir);
    if let Err(e) = File::create(Path::new(out_dir).join("VERSION_CODE"))
        .and_then(|mut f| f.write_all(code.to_string().as_bytes()))
    {
        println!("cargo:warning=Failed to write VERSION_CODE: {e}");
        return;
    }

    if let Err(e) = File::create(Path::new(out_dir).join("VERSION_NAME"))
        .and_then(|mut f| f.write_all(name.trim().as_bytes()))
    {
        println!("cargo:warning=Failed to write VERSION_NAME: {e}");
    }
}
