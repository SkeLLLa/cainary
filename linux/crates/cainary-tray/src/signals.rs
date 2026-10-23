//! SIGTERM and SIGINT end the app the same way the tray's Quit item does, so the event loop
//! returns normally, the bus name is released and the exit status is 0.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use async_channel::Sender;

use crate::controller::{AppCommand, AppMessage};

/// Write end of the self-pipe, read by [`install`]'s thread. -1 until installed.
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(_signal: libc::c_int) {
    let fd = WAKE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = 1u8;
        // SAFETY: write(2) is async-signal-safe; the descriptor stays open for the process's life.
        unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    }
}

/// Routes SIGTERM and SIGINT into `messages` as a Quit command.
pub fn install(messages: Sender<AppMessage>) -> Result<(), String> {
    let mut fds: [RawFd; 2] = [-1; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 returns.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let [read_fd, write_fd] = fds;
    WAKE_FD.store(write_fd, Ordering::Relaxed);
    std::thread::Builder::new()
        .name("cainary-signals".into())
        .spawn(move || {
            let mut byte = 0u8;
            loop {
                // SAFETY: reads one byte into a valid local.
                let n = unsafe { libc::read(read_fd, (&mut byte as *mut u8).cast(), 1) };
                if n == 1 {
                    let _ = messages.try_send(AppMessage::Command(AppCommand::Quit));
                } else if n == 0 {
                    return;
                }
            }
        })
        .map_err(|e| e.to_string())?;
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: a zeroed sigaction with a handler, an empty mask and SA_RESTART is valid.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
    }
    Ok(())
}
