// A bridge of its own: build.rs only hands it to cxx-qt-build when the `layer-shell` feature is on,
// as cxx-build does not evaluate cargo features on individual items.
#[allow(clippy::module_inception)]
#[cxx::bridge(namespace = "cainary")]
pub mod layer_shell {
    unsafe extern "C++" {
        include!("cainary-tray/cpp/cainary.h");

        fn cainary_layer_shell_attach();
        fn cainary_layer_shell_place(x: i32, y: i32);
    }
}
