//! The `hostsFile` object of the collector view: what the takeover step needs to know about
//! `/etc/hosts` and the hosts helper, and what to say about the last edit. Pure: the reader
//! (`hostsfile`), the helper assessment (`hostsedit`) and the runner outcome come in as values,
//! so every wording and every enabling rule is tested without a process or a file.

use serde::Serialize;

use crate::hostsedit::{HostsError, HostsHelperState, MAX_EDIT_HOSTS};
use crate::hostsfile::{BlockState, Conflict, HostsFile, Unsupported};
use crate::runner::{HostsEditOutcome, HostsNotRun, HostsUncertain};

/// Which edit is running, if any.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Edit {
    #[default]
    Idle,
    /// A `set` is waiting for the authentication and the helper.
    Adding,
    /// A `clear` is.
    Removing,
}

impl Edit {
    fn word(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Adding => "adding",
            Self::Removing => "removing",
        }
    }
}

/// What the last edit came to, in the words the step shows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditResult {
    /// `applied`, `unchanged`, `not-run`, `refused` or `uncertain`.
    pub outcome: &'static str,
    /// `set` or `clear`: the step shows an add result in step 3 and a removal under the undo.
    pub op: &'static str,
    pub changed: bool,
    /// False only for `changed-unsynced`.
    pub synced: bool,
    /// The helper's token for a refusal, else empty.
    pub token: String,
    /// `neutral`, `warning` or `error`.
    pub tone: &'static str,
    /// Empty when there is nothing to add to what the step already shows.
    pub message: String,
}

const BACKUP_NOTE: &str = "No cAInary lines in /etc/hosts. The previous version is saved as /etc/hosts.cainary-backup (readable by root).";

fn refusal_text(token: HostsError) -> String {
    match token {
        HostsError::DamagedBlock => {
            "/etc/hosts has a damaged cAInary block. Fix it with sudoedit /etc/hosts.".into()
        }
        HostsError::Changed => "/etc/hosts changed while cAInary was editing it. Try again.".into(),
        HostsError::Busy => "Another cAInary edit is in progress.".into(),
        HostsError::Label => "Couldn't keep the file's permissions or security label.".into(),
        HostsError::ReadOnly => "/etc/hosts is read-only on this system.".into(),
        other => format!("Couldn't change /etc/hosts ({}).", other.token()),
    }
}

/// The result of one finished edit. `op` is `HostsOp::word()`.
pub fn result_for(op: &'static str, outcome: &HostsEditOutcome) -> EditResult {
    let adding = op == "set";
    let mut result = EditResult {
        outcome: "applied",
        op,
        changed: false,
        synced: true,
        token: String::new(),
        tone: "neutral",
        message: String::new(),
    };
    match outcome {
        HostsEditOutcome::Applied { changed, synced } => {
            result.changed = *changed;
            result.synced = *synced;
            if !changed {
                result.outcome = "unchanged";
                if !adding {
                    result.message = "No cAInary lines in /etc/hosts.".into();
                }
            } else if !synced {
                result.tone = "warning";
                result.message = if adding {
                    "The lines were added, but the system couldn't confirm they were saved to disk. They work now; check again after a restart."
                } else {
                    "The lines were removed, but the system couldn't confirm that was saved to disk. The change works now; check again after a restart."
                }
                .into();
            } else if !adding {
                result.message = BACKUP_NOTE.into();
            }
        }
        HostsEditOutcome::NotRun(why) => {
            result.outcome = "not-run";
            let yourself = if adding {
                "Add the lines yourself."
            } else {
                "Remove the lines yourself."
            };
            match why {
                HostsNotRun::Dismissed => {
                    result.message = "Nothing changed. The authentication was cancelled.".into();
                }
                HostsNotRun::NotAuthorized => {
                    result.message =
                        format!("Not authorized to change /etc/hosts. Nothing changed. {yourself}");
                }
                HostsNotRun::Spawn(_) | HostsNotRun::NotTrusted(_) => {
                    result.tone = "error";
                    result.message = format!(
                        "Couldn't ask for permission ({}). Nothing changed. {yourself}",
                        why.reason()
                    );
                }
            }
        }
        HostsEditOutcome::Refused(token) => {
            result.outcome = "refused";
            result.tone = "error";
            result.token = token.token().into();
            result.message = format!("{} Nothing changed.", refusal_text(*token));
        }
        HostsEditOutcome::Uncertain(why) => {
            result.outcome = "uncertain";
            result.tone = "warning";
            result.message = format!(
                "cAInary couldn't tell whether /etc/hosts changed ({}). It checked again; the step shows the current state.",
                why.reason()
            );
            if matches!(why, HostsUncertain::TimedOut) {
                // The helper may still finish after that look.
                result.message.push_str(" Check again in a moment.");
            }
        }
    }
    result
}

/// What is known about the helper, without the trusted handle: fixtures can name every state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Helper {
    /// Not looked at yet.
    #[default]
    Checking,
    Ready,
    /// A trusted helper of another build, with what is off about it.
    Mismatch(String),
    NoHelper(String),
    Sandboxed,
}

impl From<&HostsHelperState> for Helper {
    fn from(state: &HostsHelperState) -> Self {
        match state {
            HostsHelperState::Ready { .. } => Self::Ready,
            HostsHelperState::Mismatch { warn, .. } => Self::Mismatch(warn.clone()),
            HostsHelperState::NoHelper(why) => Self::NoHelper(why.clone()),
            HostsHelperState::Sandboxed => Self::Sandboxed,
        }
    }
}

/// What the view is built from.
#[derive(Clone, Debug)]
pub struct Inputs<'a> {
    /// The names the collector serves (valid ones).
    pub hosts: &'a [String],
    /// `None` until the file was read once.
    pub file: Option<&'a HostsFile>,
    pub helper: &'a Helper,
    pub edit: Edit,
    pub result: Option<&'a EditResult>,
}

/// The `hostsFile` object of the collector view JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostsFileView {
    /// `checking`, `ready`, `mismatch`, `no-helper` or `sandboxed`.
    pub helper: &'static str,
    /// Why there is no helper, or what is off about it; empty when there is nothing to say.
    pub helper_note: String,
    /// `unknown` (not read yet), `absent`, `current`, `stale` or `damaged`.
    pub block: &'static str,
    pub conflicts: Vec<Conflict>,
    pub reserved: Vec<String>,
    pub unsupported: Option<Unsupported>,
    /// Why the file couldn't be read, else empty.
    pub error: String,
    /// More names than one edit may carry.
    pub too_many: bool,
    /// "Add to /etc/hosts…" (or "Update…") may be pressed.
    pub can_edit: bool,
    /// "Remove from /etc/hosts…" may be pressed.
    pub can_remove: bool,
    pub busy: bool,
    /// `idle`, `adding` or `removing`.
    pub edit: &'static str,
    pub result: Option<EditResult>,
}

impl Default for HostsFileView {
    fn default() -> Self {
        view(&Inputs {
            hosts: &[],
            file: None,
            helper: &Helper::Checking,
            edit: Edit::Idle,
            result: None,
        })
    }
}

fn block_word(block: BlockState) -> &'static str {
    match block {
        BlockState::Absent => "absent",
        BlockState::Current => "current",
        BlockState::Stale => "stale",
        BlockState::Damaged => "damaged",
    }
}

pub fn view(inputs: &Inputs) -> HostsFileView {
    let (helper, helper_note, usable) = match inputs.helper {
        Helper::Checking => ("checking", String::new(), false),
        Helper::Ready => ("ready", String::new(), true),
        Helper::Mismatch(warn) => ("mismatch", warn.clone(), true),
        Helper::NoHelper(why) => ("no-helper", why.clone(), false),
        Helper::Sandboxed => ("sandboxed", String::new(), false),
    };
    let analysis = inputs.file.and_then(|file| file.analysis.as_ref());
    let unsupported = inputs.file.and_then(|file| file.unsupported.clone());
    let error = inputs
        .file
        .and_then(|file| file.error.clone())
        .unwrap_or_default();
    let block = analysis.map_or("unknown", |analysis| block_word(analysis.block));
    let too_many = inputs.hosts.len() > MAX_EDIT_HOSTS;
    let reserved = analysis.map_or_else(Vec::new, |analysis| analysis.reserved.clone());
    let idle = inputs.edit == Edit::Idle;
    // Everything that would make the helper refuse is known here, so the prompt is never shown
    // for an edit that can only fail: a file that couldn't be read or analyzed, an unsupported
    // file, a damaged block, too many names, a reserved name.
    let editable = usable
        && idle
        && analysis.is_some()
        && unsupported.is_none()
        && error.is_empty()
        && block != "damaged";
    HostsFileView {
        helper,
        helper_note,
        block,
        conflicts: analysis.map_or_else(Vec::new, |analysis| analysis.conflicts.clone()),
        can_edit: editable && !inputs.hosts.is_empty() && !too_many && reserved.is_empty(),
        can_remove: editable && matches!(block, "current" | "stale"),
        reserved,
        unsupported,
        error,
        too_many,
        busy: !idle,
        edit: inputs.edit.word(),
        result: inputs.result.cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostsfile::Analysis;

    fn names(count: usize) -> Vec<String> {
        (0..count).map(|i| format!("h{i}.example.com")).collect()
    }

    fn file(block: BlockState) -> HostsFile {
        HostsFile {
            unsupported: None,
            error: None,
            analysis: Some(Analysis {
                block,
                conflicts: Vec::new(),
                reserved: Vec::new(),
            }),
        }
    }

    fn inputs<'a>(
        hosts: &'a [String],
        file: &'a HostsFile,
        helper: &'a Helper,
        edit: Edit,
    ) -> Inputs<'a> {
        Inputs {
            hosts,
            file: Some(file),
            helper,
            edit,
            result: None,
        }
    }

    #[test]
    fn nothing_is_offered_before_anything_was_looked_at() {
        let view = HostsFileView::default();
        assert_eq!(view.helper, "checking");
        assert_eq!(view.block, "unknown");
        assert!(!view.can_edit && !view.can_remove && !view.busy);
    }

    #[test]
    fn a_missing_helper_disables_both_buttons() {
        let file = file(BlockState::Current);
        for helper in [
            Helper::Checking,
            Helper::NoHelper("x".into()),
            Helper::Sandboxed,
        ] {
            let view = view(&inputs(&names(1), &file, &helper, Edit::Idle));
            assert!(!view.can_edit && !view.can_remove, "{helper:?}");
            assert_eq!(view.block, "current");
        }
    }

    #[test]
    fn a_usable_helper_enables_add_and_remove_by_block() {
        for helper in [Helper::Ready, Helper::Mismatch("old".into())] {
            let absent = view(&inputs(
                &names(1),
                &file(BlockState::Absent),
                &helper,
                Edit::Idle,
            ));
            assert!(absent.can_edit && !absent.can_remove);
            let stale = view(&inputs(
                &names(8),
                &file(BlockState::Stale),
                &helper,
                Edit::Idle,
            ));
            assert!(stale.can_edit && stale.can_remove);
        }
    }

    #[test]
    fn a_block_can_be_removed_with_no_names() {
        let off = view(&inputs(
            &[],
            &file(BlockState::Stale),
            &Helper::Ready,
            Edit::Idle,
        ));
        assert!(off.can_remove && !off.can_edit);
    }

    #[test]
    fn what_the_helper_would_refuse_is_not_offered() {
        let helper = Helper::Ready;
        let nine = view(&inputs(
            &names(9),
            &file(BlockState::Absent),
            &helper,
            Edit::Idle,
        ));
        assert!(nine.too_many && !nine.can_edit);
        let none = view(&inputs(&[], &file(BlockState::Absent), &helper, Edit::Idle));
        assert!(!none.can_edit);
        let damaged = view(&inputs(
            &names(1),
            &file(BlockState::Damaged),
            &helper,
            Edit::Idle,
        ));
        assert!(!damaged.can_edit && !damaged.can_remove);
        let mut reserved = file(BlockState::Absent);
        reserved.analysis.as_mut().unwrap().reserved = names(1);
        let reserved = view(&inputs(&names(1), &reserved, &helper, Edit::Idle));
        assert!(!reserved.can_edit);
        let mut linked = file(BlockState::Current);
        linked.unsupported = Some(Unsupported::Symlink {
            target: "/etc/static/hosts".into(),
        });
        let linked = view(&inputs(&names(1), &linked, &helper, Edit::Idle));
        assert!(!linked.can_edit && !linked.can_remove);
        let unread = HostsFile {
            unsupported: None,
            error: Some("denied".into()),
            analysis: None,
        };
        let unread = view(&inputs(&names(1), &unread, &helper, Edit::Idle));
        assert!(!unread.can_edit && !unread.can_remove);
        assert_eq!(unread.error, "denied");
    }

    #[test]
    fn nothing_is_offered_while_an_edit_runs() {
        let file = file(BlockState::Current);
        let adding = view(&inputs(&names(1), &file, &Helper::Ready, Edit::Adding));
        assert!(adding.busy && !adding.can_edit && !adding.can_remove);
        assert_eq!(adding.edit, "adding");
        assert_eq!(
            view(&inputs(&names(1), &file, &Helper::Ready, Edit::Removing)).edit,
            "removing"
        );
    }

    #[test]
    fn refusal_texts_end_in_nothing_changed() {
        for (token, text) in [
            (
                HostsError::DamagedBlock,
                "/etc/hosts has a damaged cAInary block. Fix it with sudoedit /etc/hosts. Nothing changed.",
            ),
            (
                HostsError::Changed,
                "/etc/hosts changed while cAInary was editing it. Try again. Nothing changed.",
            ),
            (
                HostsError::Busy,
                "Another cAInary edit is in progress. Nothing changed.",
            ),
            (
                HostsError::Label,
                "Couldn't keep the file's permissions or security label. Nothing changed.",
            ),
            (
                HostsError::ReadOnly,
                "/etc/hosts is read-only on this system. Nothing changed.",
            ),
            (
                HostsError::Symlink,
                "Couldn't change /etc/hosts (symlink). Nothing changed.",
            ),
        ] {
            let result = result_for("set", &HostsEditOutcome::Refused(token));
            assert_eq!(result.message, text);
            assert_eq!(result.outcome, "refused");
            assert_eq!(result.tone, "error");
            assert_eq!(result.token, token.token());
        }
    }

    #[test]
    fn nothing_changed_is_said_for_not_run_and_refused_only() {
        let cancelled = result_for("set", &HostsEditOutcome::NotRun(HostsNotRun::Dismissed));
        assert_eq!(
            cancelled.message,
            "Nothing changed. The authentication was cancelled."
        );
        assert_eq!(cancelled.tone, "neutral");
        let denied = result_for("set", &HostsEditOutcome::NotRun(HostsNotRun::NotAuthorized));
        assert_eq!(
            denied.message,
            "Not authorized to change /etc/hosts. Nothing changed. Add the lines yourself."
        );
        let removal = result_for(
            "clear",
            &HostsEditOutcome::NotRun(HostsNotRun::NotAuthorized),
        );
        assert!(removal.message.ends_with("Remove the lines yourself."));
        for outcome in [
            HostsEditOutcome::Applied {
                changed: true,
                synced: false,
            },
            HostsEditOutcome::Applied {
                changed: true,
                synced: true,
            },
            HostsEditOutcome::Uncertain(HostsUncertain::TimedOut),
            HostsEditOutcome::Uncertain(HostsUncertain::NoReply),
        ] {
            assert!(
                !result_for("set", &outcome)
                    .message
                    .contains("Nothing changed"),
                "{outcome:?}"
            );
            assert!(
                !result_for("clear", &outcome)
                    .message
                    .contains("Nothing changed"),
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn uncertain_names_the_reason_and_says_it_looked_again() {
        let result = result_for(
            "set",
            &HostsEditOutcome::Uncertain(HostsUncertain::TimedOut),
        );
        assert_eq!(result.outcome, "uncertain");
        assert_eq!(
            result.message,
            "cAInary couldn't tell whether /etc/hosts changed (timed out waiting for the helper). It checked again; the step shows the current state. Check again in a moment."
        );
    }

    #[test]
    fn applied_outcomes() {
        let added = result_for(
            "set",
            &HostsEditOutcome::Applied {
                changed: true,
                synced: true,
            },
        );
        assert_eq!((added.outcome, added.message.as_str()), ("applied", ""));
        let unsynced = result_for(
            "set",
            &HostsEditOutcome::Applied {
                changed: true,
                synced: false,
            },
        );
        assert!(!unsynced.synced);
        assert_eq!(
            unsynced.message,
            "The lines were added, but the system couldn't confirm they were saved to disk. They work now; check again after a restart."
        );
        let removed = result_for(
            "clear",
            &HostsEditOutcome::Applied {
                changed: true,
                synced: true,
            },
        );
        assert_eq!(removed.message, BACKUP_NOTE);
        let again = result_for(
            "clear",
            &HostsEditOutcome::Applied {
                changed: false,
                synced: true,
            },
        );
        assert_eq!(again.outcome, "unchanged");
        assert_eq!(again.message, "No cAInary lines in /etc/hosts.");
    }

    #[test]
    fn view_serializes_camel_case() {
        let json = serde_json::to_value(HostsFileView::default()).unwrap();
        for key in [
            "helper",
            "helperNote",
            "block",
            "conflicts",
            "reserved",
            "unsupported",
            "error",
            "tooMany",
            "canEdit",
            "canRemove",
            "busy",
            "edit",
            "result",
        ] {
            assert!(json.get(key).is_some(), "{key}");
        }
    }
}
