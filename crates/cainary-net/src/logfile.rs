//! The log file: the only writer in this crate (design §8.4, §14.3).
//!
//! The file is opened `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and validated on the descriptor
//! (`fstat`), never by path afterwards, so there's no check-then-use window to race.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct LogFile {
    path: PathBuf,
    file: File,
    size: u64,
    max: u64,
    keep: u32,
}

const FLAGS: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.append(true).mode(0o600).custom_flags(FLAGS);
    o
}

fn shown(p: &Path) -> String {
    p.display().to_string()
}

fn check_parent(dir: &Path) -> Result<(), String> {
    let md =
        fs::metadata(dir).map_err(|e| format!("can't use log directory {}: {e}", shown(dir)))?;
    if !md.is_dir() {
        return Err(format!("log directory {} is not a directory", shown(dir)));
    }
    if md.uid() != euid() || md.mode() & 0o022 != 0 {
        return Err(format!(
            "log directory {} must be owned by you and not writable by group or others",
            shown(dir)
        ));
    }
    Ok(())
}

/// The descriptor must be a regular file we own with no other hard links.
fn check_file(f: &File, path: &Path) -> Result<u64, String> {
    let md = f
        .metadata()
        .map_err(|e| format!("can't stat log file {}: {e}", shown(path)))?;
    if !md.is_file() {
        return Err(format!("log file {} is not a regular file", shown(path)));
    }
    if md.uid() != euid() {
        return Err(format!("log file {} is not owned by you", shown(path)));
    }
    if md.nlink() != 1 {
        return Err(format!(
            "log file {} has more than one hard link",
            shown(path)
        ));
    }
    f.set_permissions(Permissions::from_mode(0o600))
        .map_err(|e| format!("can't set permissions on log file {}: {e}", shown(path)))?;
    Ok(md.len())
}

fn open_error(e: io::Error, path: &Path) -> String {
    if e.raw_os_error() == Some(libc::ELOOP) {
        format!("refusing to write through a symlink: {}", shown(path))
    } else {
        format!("can't open log file {}: {e}", shown(path))
    }
}

impl LogFile {
    pub fn open(path: &Path, max_bytes: u64, keep: u32) -> Result<LogFile, String> {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        if !parent.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| format!("can't create log directory {}: {e}", shown(parent)))?;
        }
        check_parent(parent)?;
        let file = options()
            .create(true)
            .open(path)
            .map_err(|e| open_error(e, path))?;
        let size = check_file(&file, path)?;
        Ok(LogFile {
            path: path.to_path_buf(),
            file,
            size,
            max: max_bytes,
            keep,
        })
    }

    fn numbered(&self, k: u32) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push(format!(".{k}"));
        PathBuf::from(s)
    }

    fn rotate(&mut self) -> io::Result<()> {
        if self.keep == 0 {
            self.file.set_len(0)?;
            self.size = 0;
            return Ok(());
        }
        for k in (2..=self.keep).rev() {
            match fs::rename(self.numbered(k - 1), self.numbered(k)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        fs::rename(&self.path, self.numbered(1))?;
        // create_new: anything already at the path now is unexpected, so stop rather than use it.
        let file = options().create_new(true).open(&self.path)?;
        check_file(&file, &self.path).map_err(io::Error::other)?;
        self.file = file;
        self.size = 0;
        Ok(())
    }

    /// Appends `line` (which carries its own newline), rotating first when it wouldn't fit.
    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        let len = line.len() as u64;
        if self.size > 0 && self.size + len > self.max {
            self.rotate()?;
        }
        self.file.write_all(line.as_bytes())?;
        self.size += len;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cainary-net-log-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }
    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_private_file_and_parents() {
        let d = tmp("create");
        let p = d.join("a/b/out.jsonl");
        let mut l = LogFile::open(&p, 1 << 20, 3).unwrap();
        l.write_line("one\n").unwrap();
        l.write_line("two\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "one\ntwo\n");
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(&d.join("a")), 0o700);
        assert_eq!(mode(&d.join("a/b")), 0o700);
        // Reopening appends and tightens a loose mode.
        drop(l);
        fs::set_permissions(&p, Permissions::from_mode(0o666)).unwrap();
        let mut l = LogFile::open(&p, 1 << 20, 3).unwrap();
        assert_eq!(mode(&p), 0o600);
        l.write_line("three\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "one\ntwo\nthree\n");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn refuses_symlinks_and_non_files() {
        let d = tmp("symlink");
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, Permissions::from_mode(0o700)).unwrap();
        let target = d.join("target");
        fs::write(&target, "x").unwrap();
        let link = d.join("link");
        symlink(&target, &link).unwrap();
        let e = LogFile::open(&link, 100, 1).err().unwrap();
        assert!(e.contains("symlink"), "{e}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "x");
        fs::create_dir(d.join("sub")).unwrap();
        let e = LogFile::open(&d.join("sub"), 100, 1).err().unwrap();
        assert!(e.contains("log file"), "{e}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn refuses_hard_links() {
        let d = tmp("hardlink");
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, Permissions::from_mode(0o700)).unwrap();
        let a = d.join("a");
        fs::write(&a, "x").unwrap();
        fs::hard_link(&a, d.join("b")).unwrap();
        let e = LogFile::open(&a, 100, 1).err().unwrap();
        assert!(e.contains("hard link"), "{e}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn refuses_a_writable_parent() {
        let d = tmp("parent");
        fs::create_dir_all(&d).unwrap();
        fs::set_permissions(&d, Permissions::from_mode(0o777)).unwrap();
        let e = LogFile::open(&d.join("x.jsonl"), 100, 1).err().unwrap();
        assert!(e.contains("not writable by group or others"), "{e}");
        fs::set_permissions(&d, Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rotates_and_keeps_private_modes() {
        let d = tmp("rotate");
        let p = d.join("out.jsonl");
        let mut l = LogFile::open(&p, 10, 2).unwrap();
        for line in ["aaaa\n", "bbbb\n", "cccc\n", "dddd\n", "eeee\n"] {
            l.write_line(line).unwrap();
        }
        let read = |s: &str| fs::read_to_string(d.join(s)).unwrap();
        assert_eq!(read("out.jsonl"), "eeee\n");
        assert_eq!(read("out.jsonl.1"), "cccc\ndddd\n");
        assert_eq!(read("out.jsonl.2"), "aaaa\nbbbb\n");
        assert!(!d.join("out.jsonl.3").exists());
        for f in ["out.jsonl", "out.jsonl.1", "out.jsonl.2"] {
            assert_eq!(mode(&d.join(f)), 0o600, "{f}");
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn keep_zero_truncates_and_big_lines_get_a_fresh_file() {
        let d = tmp("trunc");
        let p = d.join("out.jsonl");
        let mut l = LogFile::open(&p, 10, 0).unwrap();
        l.write_line("aaaa\n").unwrap();
        l.write_line("bbbb\n").unwrap();
        l.write_line("cccc\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "cccc\n");
        l.write_line("a line far longer than the limit\n").unwrap();
        assert_eq!(
            fs::read_to_string(&p).unwrap(),
            "a line far longer than the limit\n"
        );
        assert!(!d.join("out.jsonl.1").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rotation_failure_is_an_error_not_a_panic() {
        let d = tmp("unexpected");
        let p = d.join("out.jsonl");
        let mut l = LogFile::open(&p, 10, 1).unwrap();
        l.write_line("aaaaaaa\n").unwrap();
        // The rotation target is a non-empty directory, so the rename fails.
        fs::create_dir_all(d.join("out.jsonl.1/inner")).unwrap();
        assert!(l.write_line("bbbbbbb\n").is_err());
        fs::remove_dir_all(&d).unwrap();
    }
}
