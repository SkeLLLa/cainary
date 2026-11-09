//! `cainary-hosts-helper`: replaces or removes the cAInary managed block in `/etc/hosts` (see
//! helper.rs for the contract and file.rs for the procedure). Run by `pkexec` on Linux and by the
//! app's signed root shell on macOS; the OS layer is os_linux.rs or os_macos.rs.

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod edit;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod file;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod helper;
#[cfg(target_os = "linux")]
mod os_linux;
#[cfg(target_os = "macos")]
mod os_macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod seam;

#[cfg(target_os = "linux")]
use os_linux as os;
#[cfg(target_os = "macos")]
use os_macos as os;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    helper::run();
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn main() {
    std::process::exit(2);
}
