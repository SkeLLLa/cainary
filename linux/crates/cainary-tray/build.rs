use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    let layer_shell = if env::var_os("CARGO_FEATURE_LAYER_SHELL").is_some() {
        Some(layer_shell_installation().unwrap_or_else(|| {
            panic!(
                "the layer-shell feature needs LayerShellQt (layer-shell-qt development files); \
                 install them or build with --no-default-features"
            )
        }))
    } else {
        None
    };
    let has_svg = qt_svg_development_files();
    if !has_svg {
        println!(
            "cargo:warning=Qt SVG development files were not found; SVG pixmaps will use the installed image plugin. Install with: dnf install qt6-qtsvg-devel"
        );
    }
    for variable in [
        "LAYERSHELLQT_INCLUDE_DIR",
        "LAYERSHELLQT_LIB_DIR",
        "QT_INCLUDE_DIR",
        "CAINARY_GIT_SHA",
        "CAINARY_BUILD_DATE",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    let qml = QmlModule::new("ua.SkeLLLa.cAInary")
        .depends([
            "QtQuick",
            "QtQuick.Controls",
            "QtQuick.Layouts",
            "QtQuick.Window",
        ])
        .qml_files([
            "qml/Main.qml",
            "qml/Popup.qml",
            "qml/Details.qml",
            "qml/SettingsWindow.qml",
            "qml/AboutWindow.qml",
            "qml/components/AppMenu.qml",
            "qml/components/AppRow.qml",
            "qml/components/ChangeRow.qml",
            "qml/components/EntryIcon.qml",
            "qml/components/FailureBanner.qml",
            "qml/components/FindingRow.qml",
            "qml/components/Legend.qml",
            "qml/components/LevelChip.qml",
            "qml/components/LevelIcon.qml",
            "qml/components/SupportLinks.qml",
            "qml/components/SystemColors.qml",
            "qml/components/ViewData.qml",
            "qml/components/style.js",
        ]);

    let mut builder = CxxQtBuilder::new_qml_module(qml)
        .files([
            "src/bridge/app_controller.rs",
            "src/bridge/settings_controller.rs",
            "src/bridge/ffi.rs",
        ])
        .qrc_resources(["qml/icons/refresh.svg"])
        .cpp_files(["cpp/icons.cpp", "cpp/qt_shims.cpp"])
        .qt_module("Quick")
        .qt_module("QuickControls2");

    if has_svg {
        builder = builder.qt_module("Svg");
    }

    if let Some(install) = &layer_shell {
        builder = builder
            .file("src/bridge/layer_shell.rs")
            .cpp_file("cpp/layershell.cpp");
        println!("cargo:rustc-link-lib=LayerShellQtInterface");
        println!(
            "cargo:rustc-link-search=native={}",
            install.lib_dir.display()
        );
    }

    let builder_layer_shell = layer_shell;
    // The C++ builder is the compiler abstraction supplied by cxx-qt-build.
    let builder = unsafe {
        builder.cc_builder(move |cc| {
            // GCC 16 warns pages of this from Qt's own headers.
            cc.flag_if_supported("-Wno-sfinae-incomplete");
            if has_svg {
                cc.define("CAINARY_HAVE_QTSVG", None);
            }
            if let Some(install) = &builder_layer_shell {
                cc.include(&install.include_dir);
                if install.has_set_screen {
                    cc.define("CAINARY_LSQ_HAS_SETSCREEN", None);
                }
                if install.has_activate_on_show {
                    cc.define("CAINARY_LSQ_HAS_ACTIVATEONSHOW", None);
                }
            }
        })
    };

    builder.build();
}

struct LayerShellInstallation {
    include_dir: PathBuf,
    lib_dir: PathBuf,
    /// `LayerShellQt::Window::setScreen` exists (LayerShellQt 6.1 and later).
    has_set_screen: bool,
    /// `LayerShellQt::Window::setActivateOnShow` exists.
    has_activate_on_show: bool,
}

fn layer_shell_installation() -> Option<LayerShellInstallation> {
    let mut include_dirs = Vec::new();
    if let Some(path) = env::var_os("LAYERSHELLQT_INCLUDE_DIR") {
        include_dirs.push(PathBuf::from(path));
    }
    include_dirs.extend([
        PathBuf::from("/usr/include"),
        PathBuf::from("/usr/include/qt6"),
        PathBuf::from("/usr/local/include"),
        PathBuf::from("/usr/local/include/qt6"),
    ]);

    let include_dir = include_dirs.into_iter().find(|dir| {
        let has_window_header = [
            "LayerShellQt/Window",
            "LayerShellQt/window.h",
            "LayerShellQt/Window.h",
        ]
        .iter()
        .any(|relative| dir.join(relative).is_file());
        let has_shell_header = [
            "LayerShellQt/Shell",
            "LayerShellQt/shell.h",
            "LayerShellQt/Shell.h",
        ]
        .iter()
        .any(|relative| dir.join(relative).is_file());
        has_window_header && has_shell_header
    })?;

    let mut lib_dirs = Vec::new();
    if let Some(path) = env::var_os("LAYERSHELLQT_LIB_DIR") {
        lib_dirs.push(PathBuf::from(path));
    }
    // Asking the C++ compiler covers every multiarch directory it searches.
    lib_dirs.extend(compiler_library_dir());
    let multiarch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => Some("x86_64-linux-gnu"),
        Ok("aarch64") => Some("aarch64-linux-gnu"),
        Ok("arm") => Some("arm-linux-gnueabihf"),
        Ok("riscv64") => Some("riscv64-linux-gnu"),
        _ => None,
    };
    lib_dirs.extend(multiarch.map(|triple| PathBuf::from("/usr/lib").join(triple)));
    lib_dirs.extend([
        PathBuf::from("/usr/lib64"),
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/local/lib64"),
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/usr/lib/qt6/lib"),
    ]);
    let lib_dir = lib_dirs
        .into_iter()
        .find(|dir| has_layer_shell_library(dir))?;

    let has_set_screen = compiles(&include_dir, "w->setScreen(nullptr)");
    let has_activate_on_show = compiles(&include_dir, "w->setActivateOnShow(true)");
    Some(LayerShellInstallation {
        include_dir,
        lib_dir,
        has_set_screen,
        has_activate_on_show,
    })
}

/// The directory where the C++ compiler finds `libLayerShellQtInterface.so`, if it does.
fn compiler_library_dir() -> Option<PathBuf> {
    let compiler = cc::Build::new().cpp(true).get_compiler();
    let output = std::process::Command::new(compiler.path())
        .arg("-print-file-name=libLayerShellQtInterface.so")
        .output()
        .ok()?;
    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    // An unknown file is echoed back as a bare name.
    path.canonicalize().ok()?.parent().map(Path::to_path_buf)
}

/// Whether `statement` (using a `LayerShellQt::Window *w`) compiles against the installed headers.
fn compiles(layer_shell_include: &Path, statement: &str) -> bool {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let source = out_dir.join("lsq_probe.cpp");
    fs::write(
        &source,
        format!(
            "#include <LayerShellQt/Window>\nvoid f(LayerShellQt::Window* w){{ {statement}; }}\n"
        ),
    )
    .expect("write the LayerShellQt probe");
    let mut include_dirs = vec![layer_shell_include.to_path_buf()];
    for root in qt_include_roots() {
        include_dirs.extend(["", "QtCore", "QtGui"].map(|module| root.join(module)));
    }
    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .pic(true)
        .includes(include_dirs)
        .file(&source)
        .out_dir(&out_dir)
        .cargo_metadata(false)
        .cargo_warnings(false)
        .try_compile("lsq_probe")
        .is_ok()
}

fn qt_include_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(path) = env::var_os("QT_INCLUDE_DIR") {
        roots.push(PathBuf::from(path));
    }
    roots.extend([
        PathBuf::from("/usr/include/qt6"),
        PathBuf::from("/usr/include/x86_64-linux-gnu/qt6"),
        PathBuf::from("/usr/include/aarch64-linux-gnu/qt6"),
        PathBuf::from("/usr/local/include/qt6"),
    ]);
    roots
}

fn qt_svg_development_files() -> bool {
    qt_include_roots()
        .into_iter()
        .chain([PathBuf::from("/usr/include")])
        .any(|dir| dir.join("QtSvg/QSvgRenderer").is_file())
}

fn has_layer_shell_library(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("libLayerShellQtInterface.so")
        })
    })
}
