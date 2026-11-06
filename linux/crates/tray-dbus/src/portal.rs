//! The xdg-desktop-portal SaveFile dialog. Kept on the D-Bus thread; no Qt file dialogs or GTK.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_lite::StreamExt;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

#[zbus::proxy(
    interface = "org.freedesktop.portal.FileChooser",
    default_service = "org.freedesktop.portal.Desktop",
    default_path = "/org/freedesktop/portal/desktop"
)]
trait FileChooser {
    fn save_file(
        &self,
        parent_window: &str,
        title: &str,
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "org.freedesktop.portal.Request",
    default_service = "org.freedesktop.portal.Desktop",
    default_path = "/org/freedesktop/portal/desktop"
)]
trait Request {
    #[zbus(signal)]
    fn response(&self, response: u32, results: HashMap<String, OwnedValue>) -> zbus::Result<()>;
}

pub async fn available(conn: &zbus::Connection) -> bool {
    let Ok(proxy) = zbus::fdo::DBusProxy::new(conn).await else {
        return false;
    };
    let Ok(name) = "org.freedesktop.portal.Desktop".try_into() else {
        return false;
    };
    proxy.name_has_owner(name).await.unwrap_or(false)
}

/// Opens the portal's native SaveFile UI and returns the selected local path.
pub async fn save_file(conn: &zbus::Connection) -> zbus::Result<Option<String>> {
    let chooser = FileChooserProxy::new(conn).await?;
    let token = format!(
        "cainary_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let mut options = HashMap::new();
    options.insert("handle_token", Value::from(token.as_str()));
    options.insert("current_name", Value::from("otel-debug.jsonl"));
    options.insert("accept_label", Value::from("Save"));
    let path = chooser
        .save_file("", "Save OTel debug log", options)
        .await?;
    let request = RequestProxy::builder(conn).path(path)?.build().await?;
    let mut responses = request.receive_response().await?;
    let Some(response) = responses.next().await else {
        return Ok(None);
    };
    let args = response.args()?;
    if args.response != 0 {
        return Ok(None);
    }
    let Some(uris) = args.results.get("uris").cloned() else {
        return Ok(None);
    };
    let Ok(uris) = Vec::<String>::try_from(uris) else {
        return Ok(None);
    };
    Ok(uris.first().and_then(|uri| file_uri_to_path(uri)))
}

fn file_uri_to_path(uri: &str) -> Option<String> {
    let encoded = uri.strip_prefix("file://")?;
    if !encoded.starts_with('/') {
        return None;
    }
    let mut bytes = Vec::with_capacity(encoded.len());
    let mut chars = encoded.as_bytes().iter().copied();
    while let Some(byte) = chars.next() {
        if byte == b'%' {
            let hi = hex(chars.next()?)?;
            let lo = hex(chars.next()?)?;
            bytes.push((hi << 4) | lo);
        } else {
            bytes.push(byte);
        }
    }
    let path = String::from_utf8(bytes).ok()?;
    (!path.contains('\0')).then_some(path)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::file_uri_to_path;

    #[test]
    fn decodes_only_local_file_uris() {
        assert_eq!(
            file_uri_to_path("file:///home/alice/log%20one.jsonl"),
            Some("/home/alice/log one.jsonl".into())
        );
        assert_eq!(file_uri_to_path("https://example.test/log.jsonl"), None);
        assert_eq!(file_uri_to_path("file://remote/home/log.jsonl"), None);
    }
}
