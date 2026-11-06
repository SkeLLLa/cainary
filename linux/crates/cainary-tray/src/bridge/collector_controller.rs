use std::pin::Pin;

use cxx_qt::{CxxQtType, Threading};
use cxx_qt_lib::QString;

use cainary_tray_model::collector::TrustAction;

use crate::controller::{self, AppCommand, AppMessage};
use crate::ui;

#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    unsafe extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qml_singleton]
        #[qproperty(QString, view_json, cxx_name = "viewJson")]
        type CollectorController = super::CollectorControllerRust;

        #[qinvokable]
        #[cxx_name = "copyText"]
        fn copy_text(self: Pin<&mut CollectorController>, text: &QString);

        #[qinvokable]
        fn retry(self: Pin<&mut CollectorController>);

        #[qinvokable]
        #[cxx_name = "previewClaudeTrust"]
        fn preview_claude_trust(self: Pin<&mut CollectorController>);

        #[qinvokable]
        #[cxx_name = "applyClaudeTrust"]
        fn apply_claude_trust(self: Pin<&mut CollectorController>);

        #[qinvokable]
        #[cxx_name = "cancelClaudeTrustPreview"]
        fn cancel_claude_trust_preview(self: Pin<&mut CollectorController>);

        #[qinvokable]
        #[cxx_name = "undoClaudeTrust"]
        fn undo_claude_trust(self: Pin<&mut CollectorController>);

        #[qinvokable]
        #[cxx_name = "prepareCodexBundle"]
        fn prepare_codex_bundle(self: Pin<&mut CollectorController>);

        #[qinvokable]
        #[cxx_name = "undoCodexBundle"]
        fn undo_codex_bundle(self: Pin<&mut CollectorController>);
    }

    impl cxx_qt::Threading for CollectorController {}
    impl cxx_qt::Initialize for CollectorController {}
}

pub struct CollectorControllerRust {
    view_json: QString,
}

impl Default for CollectorControllerRust {
    fn default() -> Self {
        Self {
            view_json: QString::from("{}"),
        }
    }
}

impl cxx_qt::Initialize for qobject::CollectorController {
    fn initialize(self: Pin<&mut Self>) {
        ui::register_collector(self.qt_thread());
    }
}

impl qobject::CollectorController {
    pub fn apply(mut self: Pin<&mut Self>, json: &str) {
        let json = QString::from(json);
        if self.view_json != json {
            self.as_mut().rust_mut().view_json = json;
            self.as_mut().view_json_changed();
        }
    }

    fn copy_text(self: Pin<&mut Self>, text: &QString) {
        controller::send(AppMessage::Command(AppCommand::CopyText(text.to_string())));
    }

    fn retry(self: Pin<&mut Self>) {
        controller::send(AppMessage::Command(AppCommand::RetryCollector));
    }

    fn preview_claude_trust(self: Pin<&mut Self>) {
        controller::send(AppMessage::Command(AppCommand::CollectorTrust(
            TrustAction::PreviewClaude,
        )));
    }

    fn apply_claude_trust(self: Pin<&mut Self>) {
        controller::send(AppMessage::Command(AppCommand::CollectorTrust(
            TrustAction::ApplyClaude,
        )));
    }

    fn cancel_claude_trust_preview(self: Pin<&mut Self>) {
        controller::send(AppMessage::Command(AppCommand::CancelClaudeTrustPreview));
    }

    fn undo_claude_trust(self: Pin<&mut Self>) {
        controller::send(AppMessage::Command(AppCommand::CollectorTrust(
            TrustAction::UndoClaude,
        )));
    }

    fn prepare_codex_bundle(self: Pin<&mut Self>) {
        controller::send(AppMessage::Command(AppCommand::CollectorTrust(
            TrustAction::PrepareCodex,
        )));
    }

    fn undo_codex_bundle(self: Pin<&mut Self>) {
        controller::send(AppMessage::Command(AppCommand::CollectorTrust(
            TrustAction::UndoCodex,
        )));
    }
}
