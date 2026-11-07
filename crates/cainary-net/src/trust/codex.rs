//! The Codex target: a combined certificate bundle and the command that uses it. Nothing in
//! Codex's own configuration is touched.

use super::bundle::{bundle, collector_ca, system_roots};
use super::files::{Replace, lock_trust, read_in, unlink_unchanged};
use super::state::{
    CodexState, Owned, Rec, Refused, check_owned, publish_bundle, read_state, reconcile, save_state,
};
use super::{Action, BUSY, CODEX_BUNDLE, Env, Line, NEWER, TAKEOVER, Target, dir_error, lock_wait};
use crate::setup::quote;
use crate::tls::ca_file::CaDir;

pub(super) fn codex_command(path: &str) -> String {
    format!("env CODEX_CA_CERTIFICATE={} codex", quote(path))
}

const UNRECORDED_BUNDLE: &str = "A Codex certificate bundle exists that cAInary has no record of creating; leaving it untouched.";
const FOREIGN_BUNDLE: &str =
    "The Codex certificate bundle was changed since cAInary wrote it; leaving it untouched.";

pub fn codex(env: &Env<'_>, undo: bool) -> Line {
    let t = Target::Codex;
    let ca_dir = match if undo {
        CaDir::open_existing(&env.ca_dir)
    } else {
        CaDir::open(&env.ca_dir).map(Some)
    } {
        Ok(Some(d)) => d,
        Ok(None) => {
            return Line::new(
                t,
                Action::NothingToUndo,
                "No Codex certificate bundle was prepared.",
            );
        }
        Err(_) => return dir_error(t, "collector certificate", &env.ca_dir),
    };
    let _lock = match lock_trust(&ca_dir, lock_wait()) {
        Ok(Some(l)) => l,
        Ok(None) => return Line::refused(t, BUSY),
        Err(_) => return Line::refused(t, "The trust lock could not be taken."),
    };
    let path = ca_dir.path().join(CODEX_BUNDLE).display().to_string();
    let mut state = read_state(&ca_dir);
    if state.newer {
        return Line::refused(t, NEWER);
    }
    // A bundle replacement an earlier run didn't finish is settled from the file's hash first.
    if reconcile(&ca_dir, &mut state) && save_state(&ca_dir, &state).is_err() {
        return Line::refused(t, "The state file could not be written.");
    }
    // The bundle is cAInary's own file only if the state file says so and its bytes are still what
    // cAInary wrote: anything else is never rewritten or deleted.
    let rec = match &state.codex {
        Some(c) => Rec::of(c.bundle_sha.as_deref()),
        None => Rec::None,
    };
    if undo {
        let c = check_owned(&ca_dir, CODEX_BUNDLE, &rec);
        match c.owned {
            Owned::Missing if state.codex.is_none() => {
                return Line::new(
                    t,
                    Action::NothingToUndo,
                    "No Codex certificate bundle was prepared.",
                );
            }
            Owned::Foreign => {
                let mut l = Line::refused(t, FOREIGN_BUNDLE);
                l.bundle_path = Some(path);
                return l;
            }
            Owned::Unrecorded => {
                let mut l = Line::refused(t, UNRECORDED_BUNDLE);
                l.bundle_path = Some(path);
                return l;
            }
            _ => {}
        }
        match unlink_unchanged(&ca_dir, CODEX_BUNDLE, &c.snap) {
            Ok(()) => {}
            Err(Replace::Changed) => {
                let mut l = Line::refused(t, FOREIGN_BUNDLE);
                l.bundle_path = Some(path);
                return l;
            }
            Err(_) => return Line::refused(t, "The Codex bundle could not be removed."),
        }
        state.codex = None;
        let _ = save_state(&ca_dir, &state);
        let mut l = Line::new(t, Action::Undone, "Removed the Codex certificate bundle.");
        l.bundle_path = Some(path);
        return l;
    }
    let ca = match collector_ca(&ca_dir) {
        Ok(c) => c,
        Err(m) => return Line::refused(t, m),
    };
    let Some(roots) = system_roots(env.harness) else {
        return Line::refused(
            t,
            "No system certificate bundle was found, so a combined bundle can't be made.",
        );
    };
    let text = bundle(&roots, &ca);
    let same = matches!(read_in(&ca_dir, CODEX_BUNDLE), Ok(Some(b)) if b == text.as_bytes());
    let sha = match publish_bundle(
        &ca_dir,
        &mut state,
        Target::Codex,
        CODEX_BUNDLE,
        &rec,
        text.as_bytes(),
    ) {
        Ok(sha) => sha,
        Err(Refused::Foreign) => {
            let mut l = Line::refused(
                t,
                if rec == Rec::None {
                    UNRECORDED_BUNDLE
                } else {
                    FOREIGN_BUNDLE
                },
            );
            l.bundle_path = Some(path);
            return l;
        }
        Err(Refused::Crashed) => return Line::refused(t, "(simulated crash)"),
        Err(Refused::Uncertain) => {
            return Line::refused(
                t,
                "The Codex bundle may have been replaced, but that could not be confirmed on disk. Run cainary-otel-debug --trust-status to check and finish.",
            );
        }
        Err(Refused::Failed) => return Line::refused(t, "The Codex bundle could not be written."),
    };
    state.codex = Some(CodexState {
        bundle_path: path.clone(),
        bundle_sha: Some(sha),
        modes: vec![TAKEOVER.to_string()],
    });
    state.clear_journal(CODEX_BUNDLE);
    if save_state(&ca_dir, &state).is_err() {
        return Line::refused(t, "The state file could not be written.");
    }
    let mut l = Line::new(
        t,
        if same {
            Action::Already
        } else {
            Action::Applied
        },
        "Codex will trust the collector certificate when started with this command. Nothing in your Codex configuration or shell profile was changed.",
    );
    l.command = Some(codex_command(&path));
    l.bundle_path = Some(path);
    l
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::bundle::*;
    use crate::trust::tests::*;
    use crate::trust::*;
    use std::fs;

    #[test]
    fn codex_gets_a_combined_bundle_and_a_command_and_nothing_else_changes() {
        let fx = Fx::new("codex", "");
        // No system bundle yet.
        let r = codex(&fx.env(), false);
        assert_eq!(r.action, Action::Refused);
        assert!(r.message.contains("No system certificate bundle"));
        fx.roots();
        let a = codex(&fx.env(), false);
        assert_eq!(a.action, Action::Applied, "{a:?}");
        let path = fx.ca_dir.join(CODEX_BUNDLE).display().to_string();
        assert_eq!(a.bundle_path.as_deref(), Some(path.as_str()));
        // The CA directory has a space in its name, so the path is quoted for fish and bash.
        assert_eq!(
            a.command,
            Some(format!("env CODEX_CA_CERTIFICATE='{path}' codex"))
        );
        let b = fs::read_to_string(&path).unwrap();
        assert_eq!(
            pem_certs(&b),
            [ROOT_A, ROOT_B, ROOT_C, CA1],
            "system roots plus exactly one collector cert"
        );
        assert_eq!(mode(Path::new(&path)), 0o644);
        assert_eq!(codex(&fx.env(), false).action, Action::Already);
        let s: Value = serde_json::from_str(&status_json(&fx.env(), "T")).unwrap();
        assert_eq!(s["codex"]["state"], "ready");
        assert_eq!(s["codex"]["bundlePath"], path);
        assert_eq!(
            s["codex"]["command"],
            format!("env CODEX_CA_CERTIFICATE='{path}' codex")
        );
        // No Codex config or shell profile exists to have been touched; the home is still empty.
        assert!(
            fs::read_dir(fx.base.join("fx/home"))
                .unwrap()
                .next()
                .is_none()
        );
        let u = codex(&fx.env(), true);
        assert_eq!(u.action, Action::Undone);
        assert!(!Path::new(&path).exists());
        assert_eq!(codex(&fx.env(), true).action, Action::NothingToUndo);
        // Without the collector certificate there is nothing to bundle.
        fs::remove_file(fx.ca_dir.join(CA_FILE)).unwrap();
        assert_eq!(codex(&fx.env(), false).action, Action::Refused);
    }
}
