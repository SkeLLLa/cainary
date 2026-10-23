//! The tray icon's files and pixels. Each picture is written once per run as
//! `<dir>/hicolor/scalable/status/<name>.svg`, where `<dir>` is the icon theme path handed to
//! the tray host: hosts load it by name, so Plasma and GTK can recolor the panel-colored parts.
//! The same SVG rendered at a few sizes, in the desktop's text color, is the pixmap fallback for
//! hosts that don't.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cainary_tray_dbus::Pixmap;
use cainary_tray_model::settings::write_atomic;
use cainary_tray_model::tray_icon::{IconStyle, TrayIcon};
use cxx_qt_lib::QByteArray;

use crate::bridge::ffi::ffi;

const SIZES: [i32; 4] = [16, 22, 32, 48];
/// A theme index for the private directory, so lookups by name don't depend on the host
/// merging it with the system hicolor theme.
const INDEX_THEME: &str = "[Icon Theme]\nName=Hicolor\nComment=cAInary tray icons\n\
    Directories=scalable/status\n\n[scalable/status]\nSize=22\nMinSize=8\nMaxSize=512\n\
    Type=Scalable\nContext=Status\n";

pub struct TrayIcons {
    /// The icon theme path; `None` when it couldn't be created (the host gets pixmaps only).
    dir: Option<PathBuf>,
    /// The desktop's text color when the app started, for the pixmaps.
    text: String,
    rendered: Mutex<HashMap<String, Vec<Pixmap>>>,
}

impl TrayIcons {
    /// `$XDG_RUNTIME_DIR/cainary/icons`, else `$XDG_STATE_HOME/cainary/icons`. Call on the GUI
    /// thread, once the application exists.
    pub fn new() -> Self {
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|dir| dir.is_absolute())
            .or_else(cainary_tray_model::state_home)
            .map(|dir| dir.join("cainary/icons"));
        let dir = base.and_then(|base| {
            let index = base.join("hicolor/index.theme");
            match write_atomic(&index, INDEX_THEME.as_bytes(), 0o644) {
                Ok(()) => Some(base),
                Err(error) => {
                    eprintln!(
                        "cainary-tray: tray icons fall back to pixmaps, can't write {}: {error}",
                        index.display()
                    );
                    None
                }
            }
        });
        Self {
            dir,
            text: ffi::cainary_text_color().to_string(),
            rendered: Mutex::new(HashMap::new()),
        }
    }

    /// The icon theme path for the tray host; empty without one.
    pub fn theme_path(&self) -> String {
        self.dir
            .as_deref()
            .map(|dir| dir.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// The icon's name (empty when its file couldn't be written) and pixmaps.
    pub fn get(&self, icon: TrayIcon, style: IconStyle) -> (String, Vec<Pixmap>) {
        let name = icon.name(style);
        let mut rendered = self.rendered.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pixmaps) = rendered.get(&name) {
            return (self.named(&name), pixmaps.clone());
        }
        if let Some(dir) = &self.dir
            && let Err(error) = write_icon(dir, &name, &icon.svg(style))
        {
            eprintln!("cainary-tray: could not write the tray icon {name}: {error}");
        }
        let pixmaps = render(&icon.svg_with_text(style, &self.text));
        rendered.insert(name.clone(), pixmaps.clone());
        (self.named(&name), pixmaps)
    }

    fn named(&self, name: &str) -> String {
        match &self.dir {
            Some(dir) if icon_path(dir, name).is_file() => name.to_owned(),
            _ => String::new(),
        }
    }
}

fn icon_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("hicolor/scalable/status/{name}.svg"))
}

fn write_icon(dir: &Path, name: &str, svg: &str) -> std::io::Result<()> {
    write_atomic(&icon_path(dir, name), svg.as_bytes(), 0o644)
}

fn render(svg: &str) -> Vec<Pixmap> {
    let bytes = QByteArray::from(svg.as_bytes());
    SIZES
        .into_iter()
        .filter_map(|size| {
            let argb = ffi::cainary_svg_pixmap(&bytes, size);
            let argb: &[u8] = argb.as_ref();
            (argb.len() == (size * size * 4) as usize).then(|| Pixmap {
                width: size,
                height: size,
                argb: argb.to_vec(),
            })
        })
        .collect()
}
