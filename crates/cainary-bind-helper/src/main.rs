//! `cainary-bind-helper`: run by `pkexec`, binds `127.0.0.1:N` (and `[::1]:N`) for a port below
//! 1024 and passes the listening sockets to the tray over its stdout (see helper.rs). Linux only.

#[cfg(target_os = "linux")]
mod helper;

#[cfg(target_os = "linux")]
fn main() {
    helper::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}
