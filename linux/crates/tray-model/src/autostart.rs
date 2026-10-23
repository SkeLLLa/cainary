//! Launch at login: the per-user XDG autostart entry
//! (`$XDG_CONFIG_HOME/autostart/ua.SkeLLLa.cAInary.desktop`). Off by default; packages never
//! install a system-wide one.

use std::io;
use std::path::{Path, PathBuf};

use crate::settings::write_atomic;

/// `linux/data/autostart.desktop.in`, with `Exec=` rewritten on write.
const TEMPLATE: &str = include_str!("../../../data/autostart.desktop.in");

/// `$XDG_CONFIG_HOME/autostart/ua.SkeLLLa.cAInary.desktop`.
pub fn default_path() -> Option<PathBuf> {
    crate::config_home().map(|d| d.join(format!("autostart/{}.desktop", crate::APP_ID)))
}

/// Whether the entry exists and isn't switched off.
pub fn is_enabled(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    !text
        .lines()
        .map(str::trim)
        .any(|l| l.eq_ignore_ascii_case("Hidden=true") || l == "X-GNOME-Autostart-enabled=false")
}

/// Writes or removes the entry. `exe` is what the entry starts: the absolute path of this
/// binary for private installs, or the bare name when it is on the system `PATH`.
pub fn set_enabled(path: &Path, enabled: bool, exe: &str) -> io::Result<()> {
    if enabled {
        write_atomic(path, entry(exe).as_bytes(), 0o644)
    } else {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// The desktop entry text for `exe`. `--autostart` follows the "Start minimized" setting and
/// leaves an already running instance alone.
pub fn entry(exe: &str) -> String {
    TEMPLATE
        .lines()
        .map(|line| {
            if line.starts_with("Exec=") {
                format!("Exec={} --autostart", quote(exe))
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// What the entry should run: `$APPIMAGE` for an AppImage (its mount point changes every run),
/// the bare name for a system install, else this executable's path.
pub fn current_exe() -> String {
    if let Some(appimage) = std::env::var_os("APPIMAGE").filter(|p| !p.is_empty()) {
        return appimage.to_string_lossy().into_owned();
    }
    match std::fs::read_link("/proc/self/exe") {
        Ok(p) if p.starts_with("/usr/bin") => "cainary-tray".to_owned(),
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => "cainary-tray".to_owned(),
    }
}

/// Desktop Entry `Exec` quoting: arguments with reserved characters go in double quotes, with
/// `"`, `` ` ``, `$` and `\` escaped, and a literal `%` written `%%`. The string-value rule
/// also halves backslashes, so a literal `\` takes four in the file.
fn quote(arg: &str) -> String {
    const RESERVED: &[char] = &[
        ' ', '\t', '\n', '"', '\'', '\\', '>', '<', '~', '|', '&', ';', '$', '*', '?', '#', '(',
        ')', '`', '%',
    ];
    if !arg.contains(RESERVED) {
        return arg.to_owned();
    }
    let mut out = String::from("\"");
    for c in arg.chars() {
        match c {
            '"' | '`' | '$' => {
                out.push('\\');
                out.push(c);
            }
            '\\' => out.push_str("\\\\\\\\"),
            // A literal percent is "%%" in Exec, quoted or not.
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn plain_arguments_stay_bare() {
        assert_eq!(quote("cainary-tray"), "cainary-tray");
        assert_eq!(
            quote("/home/me/.local/bin/cainary-tray"),
            "/home/me/.local/bin/cainary-tray"
        );
    }

    #[test]
    fn spaces_get_quotes() {
        assert_eq!(quote("/opt/my apps/tray"), "\"/opt/my apps/tray\"");
    }

    #[test]
    fn percent_is_doubled() {
        assert_eq!(quote("/tmp/100%/tray"), "\"/tmp/100%%/tray\"");
        assert_eq!(quote("50%"), "\"50%%\"");
    }

    #[test]
    fn quote_backtick_and_dollar_are_escaped() {
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote("a`b"), "\"a\\`b\"");
        assert_eq!(quote("$HOME/x"), "\"\\$HOME/x\"");
    }

    #[test]
    fn backslash_takes_four_in_the_file() {
        assert_eq!(quote("a\\b"), "\"a\\\\\\\\b\"");
    }

    #[test]
    fn entry_rewrites_only_exec() {
        let text = super::entry("/opt/a b/tray");
        assert!(text.contains("\nExec=\"/opt/a b/tray\" --autostart\n"));
        assert!(text.ends_with('\n'));
    }
}
