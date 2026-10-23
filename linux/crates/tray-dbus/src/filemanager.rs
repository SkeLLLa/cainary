//! Reveal a file: `org.freedesktop.FileManager1.ShowItems` selects it in the user's file
//! manager (Dolphin, Nautilus, Nemo…). The caller falls back to opening the parent directory.

#[zbus::proxy(
    interface = "org.freedesktop.FileManager1",
    default_service = "org.freedesktop.FileManager1",
    default_path = "/org/freedesktop/FileManager1"
)]
trait FileManager1 {
    fn show_items(&self, uris: &[&str], startup_id: &str) -> zbus::Result<()>;
}

pub async fn show_item(conn: &zbus::Connection, path: &str) -> zbus::Result<()> {
    let proxy = FileManager1Proxy::new(conn).await?;
    proxy.show_items(&[&file_uri(path)], "").await
}

/// `file://` plus the path, percent-encoding everything outside the URI unreserved set.
pub fn file_uri(path: &str) -> String {
    let mut out = String::from("file://");
    for b in path.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
