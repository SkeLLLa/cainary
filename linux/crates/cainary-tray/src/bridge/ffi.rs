#[allow(clippy::module_inception)]
#[cxx::bridge(namespace = "cainary")]
pub mod ffi {
    #[namespace = ""]
    unsafe extern "C++" {
        include!("cxx-qt-lib/qbytearray.h");
        type QByteArray = cxx_qt_lib::QByteArray;
        include!("cxx-qt-lib/qqmlapplicationengine.h");
        type QQmlApplicationEngine = cxx_qt_lib::QQmlApplicationEngine;
        include!("cxx-qt-lib/qrect.h");
        type QRect = cxx_qt_lib::QRect;
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    // qt_shims.cpp
    unsafe extern "C++" {
        include!("cainary-tray/cpp/cainary.h");

        fn cainary_install_message_handler();
        fn cainary_clear_messages();
        fn cainary_messages() -> QString;
        fn cainary_controls_style() -> QString;
        fn cainary_platform_name() -> QString;
        fn cainary_qt_version() -> QString;
        fn cainary_format_time(timestamp: &QString) -> QString;
        fn cainary_copy_text(text: &QString);
        fn cainary_grab_window(name: &QString, path: &QString) -> bool;
        fn cainary_set_dark_palette(dark: bool);
        fn cainary_available_area(x: i32, y: i32) -> QRect;
    }

    // icons.cpp
    unsafe extern "C++" {
        fn cainary_set_app_identity();
        fn cainary_install_icon_provider(engine: Pin<&mut QQmlApplicationEngine>);
        fn cainary_svg_pixmap(svg: &QByteArray, size: i32) -> QByteArray;
        fn cainary_text_color() -> QString;
        fn cainary_keep_running_without_windows();
    }
}
