//! `cainary-hosts-helper`: run by `pkexec`, replaces or removes the cAInary managed block in
//! `/etc/hosts` (see helper.rs for the contract and file.rs for the procedure). Linux only.

#[cfg(target_os = "linux")]
mod edit;
#[cfg(target_os = "linux")]
mod file;
#[cfg(target_os = "linux")]
mod helper;
#[cfg(target_os = "linux")]
mod seam;

#[cfg(target_os = "linux")]
fn main() {
    helper::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}
