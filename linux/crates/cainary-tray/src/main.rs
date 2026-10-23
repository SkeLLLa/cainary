use std::process::ExitCode;

fn main() -> ExitCode {
    cxx_qt::init_crate!(cainary_tray);
    cxx_qt::init_crate!(cxx_qt);
    cxx_qt::init_crate!(cxx_qt_lib);
    cxx_qt::init_qml_module!("ua.SkeLLLa.cAInary");

    cainary_tray::run()
}
