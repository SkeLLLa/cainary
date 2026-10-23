//! Where the CLI and the icons are (plan §4, I8). There is never a `PATH` lookup: a directory
//! earlier in `PATH` must not be able to stand in for the scanner.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Where the distro packages install the CLI.
pub const SYSTEM_CLI: &str = "/usr/bin/cainary";

/// The developer overrides (`CAINARY_CORE`, `CAINARY_SCAN_ARGS`) apply to debug builds, or to a
/// release build started with `--dev`.
pub fn dev_overrides(dev_flag: bool) -> bool {
    cfg!(debug_assertions) || dev_flag
}

/// The CLI to run: `CAINARY_CORE` (dev only), `cainary` next to this executable, then
/// [`SYSTEM_CLI`].
pub fn cli(dev_flag: bool) -> Option<PathBuf> {
    let env = dev_overrides(dev_flag)
        .then(|| std::env::var_os("CAINARY_CORE"))
        .flatten();
    let exe = std::fs::read_link("/proc/self/exe").ok();
    cli_from(env, exe.as_deref(), Path::new(SYSTEM_CLI))
}

/// [`cli`] with its inputs spelled out, for tests.
pub fn cli_from(env: Option<OsString>, exe: Option<&Path>, system: &Path) -> Option<PathBuf> {
    // A relative override would be resolved against the working directory (or invite a PATH
    // lookup downstream), so it is ignored.
    if let Some(path) = env.filter(|p| Path::new(p).is_absolute()) {
        // An explicit override is used even when broken, so the error says so instead of
        // quietly scanning with another binary.
        return Some(PathBuf::from(path));
    }
    let sibling = exe.and_then(Path::parent).map(|dir| dir.join("cainary"));
    sibling
        .into_iter()
        .chain([system.to_path_buf()])
        .find(|p| is_executable(p))
}

/// Extra scan arguments from `CAINARY_SCAN_ARGS` (dev only), split on whitespace.
pub fn scan_args(dev_flag: bool) -> Vec<OsString> {
    if !dev_overrides(dev_flag) {
        return Vec::new();
    }
    std::env::var("CAINARY_SCAN_ARGS")
        .unwrap_or_default()
        .split_whitespace()
        .map(OsString::from)
        .collect()
}

/// The icon theme directory to hand the tray host, for installs outside the system icon theme
/// (the tarball, a dev build). `CAINARY_ICON_THEME_PATH` wins; then `../share/icons` next to the
/// executable when it holds our icons. Empty means "use the system theme".
pub fn icon_theme_path() -> String {
    if let Some(p) = std::env::var_os("CAINARY_ICON_THEME_PATH").filter(|p| !p.is_empty()) {
        return p.to_string_lossy().into_owned();
    }
    let exe = std::fs::read_link("/proc/self/exe").ok();
    let Some(prefix) = exe.as_deref().and_then(Path::parent).and_then(Path::parent) else {
        return String::new();
    };
    // A system install finds its icons through the theme; only a private prefix needs this.
    if prefix == Path::new("/usr") {
        return String::new();
    }
    let icons = prefix.join("share/icons");
    let ours = icons.join(format!("hicolor/scalable/apps/{}.svg", crate::APP_ID));
    if ours.is_file() {
        icons.to_string_lossy().into_owned()
    } else {
        String::new()
    }
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_cli_is_in_usr_bin() {
        assert_eq!(SYSTEM_CLI, "/usr/bin/cainary");
    }

    #[test]
    fn without_an_override_or_a_sibling_the_system_path_is_used() {
        let dir = std::env::temp_dir().join(format!("cainary-locate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let system = dir.join("system-cainary");
        std::fs::write(&system, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&system, PermissionsExt::from_mode(0o755)).unwrap();
        let exe = dir.join("bin/cainary-tray");
        assert_eq!(cli_from(None, Some(&exe), &system), Some(system.clone()));
        // A sibling wins over the system path.
        let sibling = dir.join("bin/cainary");
        std::fs::write(&sibling, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&sibling, PermissionsExt::from_mode(0o755)).unwrap();
        assert_eq!(cli_from(None, Some(&exe), &system), Some(sibling));
        // Neither exists: nothing, and never a PATH lookup.
        let nowhere = Path::new("/nonexistent/cainary");
        assert_eq!(
            cli_from(None, Some(Path::new("/nonexistent/x")), nowhere),
            None
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
