//! The Claude Code target: one key (`env.NODE_EXTRA_CA_CERTS`) in the user's settings, edited
//! with a backup and a recorded transaction, and undone from that record.

use super::bundle::{
    COLLECTOR_MISSING, bundle, cert_fingerprint, collector_ca, read_certs, sha_of,
};
use super::files::{
    Done, MAX_FILE, Replace, Snapshot, TrustLock, Why, backup, discard, lock_trust, plain_name,
    publish, read_in, read_snapshot, stage, unlink_checked, unlink_in, unlink_unchanged,
};
use super::state::{
    ClaudeState, Pending, PendingKind, Rec, Refused, State, check_owned, delete_owned,
    publish_bundle, read_state, reconcile, save_state,
};
use super::{
    Action, BUSY, CLAUDE_BUNDLE, Env, KEY, Line, Mode, NEWER, ORG_NOTE, RESTART, TAKEOVER, Target,
    dir_error, hook, lock_wait, now_string, stamp, with_shell,
};
use crate::jsonedit::{self, EditError};
use crate::tls::ca_file::{CA_FILE, CaDir};
use cainary_core::harness::ctx::ScanCtx;
use cainary_core::harness::{Harness, ToolHome};
use cainary_core::model::Tool;
use cainary_core::scanners::claude_code::{self, CcFrom};
use std::path::{Path, PathBuf};

fn why_text(w: &Why) -> &'static str {
    match w {
        Why::Symlink => "The settings file is a symlink; refusing to edit it.",
        Why::Owner => "The settings file is not owned by you; refusing to edit it.",
        Why::NotRegular => {
            "The settings file is not a regular file with a single link; refusing to edit it."
        }
        Why::TooBig => "The settings file is over 1 MiB; refusing to edit it.",
        Why::Io => "The settings file could not be read.",
    }
}

fn edit_text(e: EditError) -> &'static str {
    match e {
        EditError::Syntax => {
            "The settings file is not strict JSON (no comments or trailing commas); refusing to edit it."
        }
        EditError::NotObject => "The settings file is not a JSON object; refusing to edit it.",
        EditError::Duplicate => {
            "The settings file has a key twice in one object; refusing to edit it, so that neither copy is lost."
        }
        EditError::TooDeep | EditError::TooBig => {
            "The settings file is too large or too deeply nested; refusing to edit it."
        }
        EditError::EnvNotObject => {
            "env in the settings file is not an object; refusing to edit it."
        }
        EditError::NotString => {
            "env.NODE_EXTRA_CA_CERTS in the settings file is not a string; refusing to edit it."
        }
    }
}

const RESTORED: &str =
    "Restored your previous Claude Code setting. Restart Claude Code for it to take effect.";
const UNCERTAIN: &str = "The settings file may have been changed, but that could not be confirmed on disk. Run cainary-otel-debug --trust-status to check and finish.";
const CHANGED: &str =
    "Your Claude Code settings changed while editing; close Claude Code and try again.";
const FOREIGN_BUNDLE: &str = "The Claude Code certificate bundle was changed since cAInary wrote it; leaving it untouched, and your settings too.";
const UNRECORDED_BUNDLE: &str = "A Claude Code certificate bundle exists that cAInary has no record of creating; leaving it untouched, and your settings too.";
const WHERE_CHANGED: &str = "Your Claude Code settings location changed since cAInary edited it (CLAUDE_CONFIG_DIR?); leaving it alone.";

pub(super) struct Settings {
    pub(super) dir: CaDir,
    pub(super) path: PathBuf,
    /// The file as read, when it existed, with its identity.
    pub(super) snapshot: Option<Snapshot>,
    /// Its bytes as text: validated UTF-8, never a lossy rendering.
    pub(super) text: String,
}

impl Settings {
    pub(super) fn text(&self) -> String {
        self.text.clone()
    }
    pub(super) fn path_str(&self) -> String {
        self.path.display().to_string()
    }
}

pub(super) fn open_settings(
    env: &Env<'_>,
    create_missing: bool,
) -> Result<Option<Settings>, Box<Line>> {
    let t = Target::ClaudeCode;
    let dir_path = env
        .harness
        .tool_home(ToolHome::ClaudeConfig)
        .path()
        .to_path_buf();
    let dir = match CaDir::open_shared(&dir_path, create_missing) {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(None),
        Err(_) => return Err(Box::new(dir_error(t, "Claude Code settings", &dir_path))),
    };
    let path = dir.path().join("settings.json");
    let snapshot = read_snapshot(&dir, "settings.json").map_err(|w| {
        let mut l = Line::refused(t, why_text(&w));
        l.settings_path = Some(path.display().to_string());
        Box::new(l)
    })?;
    let text = match &snapshot {
        None => String::new(),
        Some(sn) => String::from_utf8(sn.bytes.clone()).map_err(|_| {
            let mut l = Line::refused(
                t,
                "The settings file is not valid UTF-8; refusing to edit it.",
            );
            l.settings_path = Some(path.display().to_string());
            Box::new(l)
        })?,
    };
    Ok(Some(Settings {
        dir,
        path,
        snapshot,
        text,
    }))
}

/// The parsed settings text, or the refusal for it.
fn parse_settings<'a>(s: &Settings, text: &'a str) -> Result<Option<jsonedit::Doc<'a>>, Box<Line>> {
    if s.snapshot.is_none() {
        return Ok(None);
    }
    jsonedit::parse(text).map(Some).map_err(|e| {
        let mut l = Line::refused(Target::ClaudeCode, edit_text(e));
        fill_paths(&mut l, s);
        Box::new(l)
    })
}

/// Managed settings (or any admin tier) that set the key win over ours: refuse. The shell value
/// is only mentioned.
pub(super) fn managed_sets_key(h: &Harness) -> bool {
    let mut ctx = ScanCtx::new(h, Tool::ClaudeCode);
    let cfg = claude_code::resolve(&mut ctx);
    claude_code::env(&cfg, KEY).is_some_and(|v| matches!(v.from, CcFrom::Tier(_)))
}

/// What the state file says about the Claude Code bundle at `bundle_path`.
fn bundle_rec(state: &State, bundle_path: &str) -> Rec {
    match &state.claude {
        Some(c) if c.written == bundle_path => Rec::of(c.bundle_sha.as_deref()),
        _ => Rec::None,
    }
}

fn prefixed(note: Option<String>, mut line: Line) -> Line {
    if let Some(n) = note {
        line.message = format!("{n} {}", line.message);
    }
    line
}

pub fn claude_code(env: &Env<'_>, mode: Mode) -> Line {
    let t = Target::ClaudeCode;
    match mode {
        // Previews never write: no lock, no recovery, only a note about a pending transaction.
        Mode::Apply { dry_run: true } => {
            let ca = CaDir::open_existing(&env.ca_dir).ok().flatten();
            let note = ca.as_ref().and_then(|c| inspect_note(env, c));
            prefixed(note, claude_apply(env, true, ca.as_ref(), None))
        }
        Mode::Undo { dry_run: true } => match CaDir::open_existing(&env.ca_dir) {
            Ok(Some(ca)) => {
                let note = inspect_note(env, &ca);
                prefixed(note, claude_undo(env, true, &ca, None))
            }
            Ok(None) => nothing_changed(t),
            Err(_) => dir_error(t, "collector certificate", &env.ca_dir),
        },
        Mode::Apply { dry_run: false } | Mode::Undo { dry_run: false } => {
            let undo = matches!(mode, Mode::Undo { .. });
            let ca = if undo {
                match CaDir::open_existing(&env.ca_dir) {
                    Ok(Some(c)) => c,
                    Ok(None) => return nothing_changed(t),
                    Err(_) => return dir_error(t, "collector certificate", &env.ca_dir),
                }
            } else {
                match open_ca_dir(env, t) {
                    Ok(c) => c,
                    Err(l) => return *l,
                }
            };
            let lock = match lock_trust(&ca, lock_wait()) {
                Ok(Some(l)) => l,
                Ok(None) => return Line::refused(t, BUSY),
                Err(_) => return Line::refused(t, "The trust lock could not be taken."),
            };
            if read_state(&ca).newer {
                return Line::refused(t, NEWER);
            }
            let note = recover(env, &ca, &lock);
            let line = if undo {
                claude_undo(env, false, &ca, Some(&lock))
            } else {
                claude_apply(env, false, Some(&ca), Some(&lock))
            };
            prefixed(note, line)
        }
    }
}

fn nothing_changed(t: Target) -> Line {
    Line::new(
        t,
        Action::NothingToUndo,
        "cAInary has not changed your Claude Code settings.",
    )
}

fn fill_paths(l: &mut Line, s: &Settings) {
    l.settings_path = Some(s.path_str());
    l.key = Some(KEY);
}

/// The directory the collector CA lives in, opened strictly and created if needed.
fn open_ca_dir(env: &Env<'_>, t: Target) -> Result<CaDir, Box<Line>> {
    CaDir::open(&env.ca_dir)
        .map_err(|_| Box::new(dir_error(t, "collector certificate", &env.ca_dir)))
}

/// Re-reads the settings immediately before a change and requires them to be what the change was
/// computed from: same bytes and same file (device, inode, size, mtime). Nothing is written if
/// they differ. (No POSIX call compares and renames atomically; this narrows the window to
/// microseconds, and the message tells the user to close Claude Code.)
fn unchanged_since(s: &Settings, point: &str) -> bool {
    hook::before_cas(point);
    match (read_snapshot(&s.dir, "settings.json"), &s.snapshot) {
        (Ok(None), None) => true,
        (Ok(Some(now)), Some(then)) => now.bytes == then.bytes && now.ident == then.ident,
        _ => false,
    }
}

fn claude_apply(
    env: &Env<'_>,
    dry_run: bool,
    ca: Option<&CaDir>,
    lock: Option<&TrustLock>,
) -> Line {
    let t = Target::ClaudeCode;
    let h = env.harness;
    if managed_sets_key(h) {
        return Line::refused(
            t,
            "Your organization's managed settings set NODE_EXTRA_CA_CERTS; they override this.",
        );
    }
    let settings = match open_settings(env, !dry_run) {
        Ok(Some(s)) => s,
        // A dry run doesn't create the directory: it describes creating the file.
        Ok(None) => return preview_new_claude(env),
        Err(l) => return *l,
    };
    let text = settings.text();
    let doc = match parse_settings(&settings, &text) {
        Ok(d) => d,
        Err(l) => return *l,
    };
    let existing = match &doc {
        Some(d) => match d.env_value(KEY) {
            Ok(v) => v,
            Err(e) => {
                let mut l = Line::refused(t, edit_text(e));
                fill_paths(&mut l, &settings);
                return l;
            }
        },
        None => None,
    };
    // A preview with no collector directory yet reads nothing from it.
    let ca_base = ca.map_or_else(|| env.ca_dir.clone(), |d| d.path().to_path_buf());
    let ca_path = ca_base.join(CA_FILE).display().to_string();
    let bundle_path = ca_base.join(CLAUDE_BUNDLE).display().to_string();
    let state = ca.map(read_state).unwrap_or_default();
    let mut line = Line::new(t, Action::Already, "");
    fill_paths(&mut line, &settings);
    line.to = existing.clone();
    let recorded_here = state
        .claude
        .as_ref()
        .is_some_and(|c| c.written == bundle_path && c.settings_path == settings.path_str());
    if existing.as_deref() == Some(ca_path.as_str())
        || (existing.as_deref() == Some(bundle_path.as_str()) && recorded_here)
    {
        line.message = with_shell(h, "Claude Code already trusts the collector certificate.");
        line.from = existing.clone();
        if existing.as_deref() == Some(bundle_path.as_str()) {
            line.bundle_path = Some(bundle_path);
        }
        return line;
    }

    // What to write, and the bundle it may need.
    let (written, bundle_text, orig_fps): (String, Option<String>, Vec<String>) = match &existing {
        None => (ca_path.clone(), None, Vec::new()),
        Some(p) => {
            let collector = match ca.map(collector_ca) {
                Some(Ok(c)) => c,
                Some(Err(m)) => {
                    let mut l = Line::refused(t, m);
                    fill_paths(&mut l, &settings);
                    return l;
                }
                None => {
                    let mut l = Line::refused(t, COLLECTOR_MISSING);
                    fill_paths(&mut l, &settings);
                    return l;
                }
            };
            let Some(certs) = read_certs(Path::new(p)) else {
                let mut l = Line::refused(
                    t,
                    "The file your NODE_EXTRA_CA_CERTS points at could not be read as a certificate bundle, so a combined bundle can't be made.",
                );
                fill_paths(&mut l, &settings);
                l.from = Some(p.clone());
                return l;
            };
            let fps = certs.iter().map(|c| cert_fingerprint(c)).collect();
            (bundle_path.clone(), Some(bundle(&certs, &collector)), fps)
        }
    };
    let new_text = match &doc {
        Some(d) => d.set_env_value(KEY, &written),
        // A new file: just the one key, with a trailing newline.
        None => jsonedit::parse("{}")
            .expect("valid")
            .set_env_value(KEY, &written)
            .map(|t| format!("{t}\n")),
    };
    let new_text = match new_text {
        Ok(t) => t,
        Err(e) => {
            let mut l = Line::refused(t, edit_text(e));
            fill_paths(&mut l, &settings);
            return l;
        }
    };
    // What is about to be written must be something this tool would read back: within the cap.
    let too_big = |m: &str| {
        let mut l = Line::refused(t, m);
        fill_paths(&mut l, &settings);
        l
    };
    if new_text.len() > MAX_FILE {
        return too_big("The edited settings file would be over 1 MiB; refusing to edit it.");
    }
    if bundle_text.as_ref().is_some_and(|b| b.len() > MAX_FILE) {
        return too_big("The combined bundle would be over 1 MiB; refusing to make it.");
    }
    // A bundle is only replaced if it is cAInary's own and unchanged, or already holds these
    // exact bytes; a file cAInary has no record of is never overwritten.
    if let (Some(text), Some(d)) = (&bundle_text, ca) {
        let rec = bundle_rec(&state, &bundle_path);
        if !check_owned(d, CLAUDE_BUNDLE, &rec).allows_write(text.as_bytes()) {
            let mut l = Line::refused(
                t,
                if rec == Rec::None {
                    UNRECORDED_BUNDLE
                } else {
                    FOREIGN_BUNDLE
                },
            );
            fill_paths(&mut l, &settings);
            l.bundle_path = Some(bundle_path);
            return l;
        }
    }
    let stamp_now = stamp(&now_string(h));
    let planned_backup = settings
        .snapshot
        .as_ref()
        .map(|_| format!("settings.json.cainary-{stamp_now}.bak"));
    line.from = existing.clone();
    line.to = Some(written.clone());
    line.bundle_path = bundle_text.as_ref().map(|_| bundle_path.clone());
    line.backup_path = planned_backup
        .as_ref()
        .map(|n| settings.dir.path().join(n).display().to_string());
    if dry_run {
        line.action = Action::Preview;
        line.message = with_shell(
            h,
            &if bundle_text.is_some() {
                format!(
                    "Would point env.NODE_EXTRA_CA_CERTS at a combined bundle (your current file plus the collector certificate) in your Claude Code settings, after a backup. {RESTART} {ORG_NOTE}"
                )
            } else {
                format!(
                    "Would set env.NODE_EXTRA_CA_CERTS in your Claude Code settings, after a backup. {RESTART} {ORG_NOTE}"
                )
            },
        );
        return line;
    }

    let fail = |m: &str| {
        let mut l = Line::refused(t, m);
        fill_paths(&mut l, &settings);
        l
    };
    let ca_dir = ca.expect("a real apply has the collector directory");
    let _held = lock.expect("a real apply holds the trust lock");
    let cs = ClaudeState {
        settings_path: settings.path_str(),
        original: existing.clone(),
        written: written.clone(),
        created_env: !doc.as_ref().is_some_and(|d| d.has_env()),
        created_file: settings.snapshot.is_none(),
        orig_sha: settings.snapshot.as_ref().map(|s| sha_of(&s.bytes)),
        backup: None,
        new_sha: Some(sha_of(new_text.as_bytes())),
        modes: vec![TAKEOVER.to_string()],
        bundle_sha: bundle_text.as_ref().map(|b| sha_of(b.as_bytes())),
        orig_fps,
    };
    // 1. The transaction record, durable, before anything changes.
    let mut pending_state = state.clone();
    pending_state.pending = Some(Pending {
        kind: PendingKind::Apply,
        claude: cs.clone(),
        before: cs.orig_sha.clone(),
        after: cs.new_sha.clone(),
    });
    if save_state(ca_dir, &pending_state).is_err() {
        return fail("The state file could not be written; nothing was changed.");
    }
    if hook::stop("after-pending") {
        return fail("(simulated crash)");
    }
    // 2. The backup of exactly the bytes the edit was computed from.
    let backup_name = match &settings.snapshot {
        Some(s) => match backup(&settings.dir, "settings.json", &s.bytes, &stamp_now) {
            Ok(n) => Some(n),
            Err(_) => {
                let _ = save_state(ca_dir, &state);
                return fail("The settings backup could not be written; nothing was changed.");
            }
        },
        None => None,
    };
    // The bundle: journaled in the pending record, staged, re-checked, then renamed. The journal
    // stays until the apply is committed, so a failure from here on still settles from the hash.
    if let Some(text) = &bundle_text {
        let rec = bundle_rec(&state, &bundle_path);
        let refused = match publish_bundle(
            ca_dir,
            &mut pending_state,
            t,
            CLAUDE_BUNDLE,
            &rec,
            text.as_bytes(),
        ) {
            Ok(_) => None,
            Err(Refused::Foreign) => Some(if rec == Rec::None {
                UNRECORDED_BUNDLE
            } else {
                FOREIGN_BUNDLE
            }),
            Err(Refused::Failed) => {
                Some("The combined bundle could not be written; nothing was changed.")
            }
            Err(Refused::Uncertain) => return fail(UNCERTAIN),
            Err(Refused::Crashed) => return fail("(simulated crash)"),
        };
        if let Some(m) = refused {
            let _ = save_state(ca_dir, &state);
            return fail(m);
        }
    }
    let after_bundle = || {
        let mut s = state.clone();
        s.journal.clone_from(&pending_state.journal);
        s
    };
    // 3. Stage the new file first (written and fsynced), then compare, then rename at once: the
    //    time between the check and the swap is a few system calls, not a file write.
    let tmp = match stage(&settings.dir, "settings.json", new_text.as_bytes(), 0o600) {
        Ok(t) => t,
        Err(_) => {
            let _ = save_state(ca_dir, &after_bundle());
            return fail("The settings file could not be written; nothing was changed.");
        }
    };
    if !unchanged_since(&settings, "apply") {
        discard(&settings.dir, &tmp);
        if let Some(n) = &backup_name {
            let _ = unlink_in(&settings.dir, n);
        }
        let _ = save_state(ca_dir, &after_bundle());
        return fail(CHANGED);
    }
    if hook::stop("before-rename") {
        return fail("(simulated crash)");
    }
    match publish(&settings.dir, &tmp, "settings.json") {
        Ok(()) => {}
        Err(Done::No) => {
            let _ = save_state(ca_dir, &after_bundle());
            return fail("The settings file could not be written; nothing was changed.");
        }
        // The rename happened and its durability is unknown: keep the transaction, say so.
        Err(Done::Uncertain) => return fail(UNCERTAIN),
    }
    if hook::stop("after-rename") {
        return fail("(simulated crash)");
    }
    // 4. The record, replacing the transaction. If this fails the settings are NOT rolled back
    //    (that could overwrite something newer): the transaction stays, and the next --trust or
    //    --trust-status finishes it.
    let mut committed = state.clone();
    committed.claude = Some(ClaudeState {
        backup: backup_name.clone(),
        ..cs
    });
    if save_state(ca_dir, &committed).is_err() {
        return fail(
            "The change was made, but its record could not be saved. Run cainary-otel-debug --trust-status to finish it.",
        );
    }
    line.action = Action::Applied;
    line.backup_path = backup_name.map(|n| settings.dir.path().join(n).display().to_string());
    line.message = with_shell(
        h,
        "Claude Code will trust the collector certificate once it is restarted.",
    );
    line
}

/// A dry run with no `~/.claude` yet: the file would be created.
fn preview_new_claude(env: &Env<'_>) -> Line {
    let t = Target::ClaudeCode;
    let h = env.harness;
    let dir = env
        .harness
        .tool_home(ToolHome::ClaudeConfig)
        .path()
        .to_path_buf();
    let mut l = Line::new(
        t,
        Action::Preview,
        with_shell(
            h,
            &format!(
                "Would create your Claude Code settings file with only env.NODE_EXTRA_CA_CERTS (no backup is needed). {RESTART} {ORG_NOTE}"
            ),
        ),
    );
    l.settings_path = Some(dir.join("settings.json").display().to_string());
    l.key = Some(KEY);
    l.to = Some(env.ca_dir.join(CA_FILE).display().to_string());
    l
}

fn claude_undo(env: &Env<'_>, dry_run: bool, ca_dir: &CaDir, lock: Option<&TrustLock>) -> Line {
    let t = Target::ClaudeCode;
    let h = env.harness;
    let nothing = || nothing_changed(t);
    let state = read_state(ca_dir);
    let Some(cs) = state.claude.clone() else {
        return nothing();
    };
    let settings = match open_settings(env, false) {
        Ok(Some(s)) => s,
        Ok(None) => return stale_record(ca_dir, state, dry_run),
        Err(l) => return *l,
    };
    // Only the settings the record was made for.
    if cs.settings_path != settings.path_str() {
        let mut l = Line::refused(t, WHERE_CHANGED);
        fill_paths(&mut l, &settings);
        return l;
    }
    if settings.snapshot.is_none() {
        return stale_record(ca_dir, state, dry_run);
    }
    let text = settings.text();
    let doc = match parse_settings(&settings, &text) {
        Ok(Some(d)) => d,
        Ok(None) => return stale_record(ca_dir, state, dry_run),
        Err(l) => return *l,
    };
    let current = doc.env_value(KEY).ok().flatten();
    if current.as_deref() != Some(cs.written.as_str()) {
        let mut l = Line::refused(
            t,
            "The setting changed since cAInary wrote it; leaving it alone.",
        );
        fill_paths(&mut l, &settings);
        l.from = current;
        return l;
    }
    let bundle_here = ca_dir.path().join(CLAUDE_BUNDLE).display().to_string();
    // The bundle (if ours) must still be what cAInary wrote; this snapshot is re-checked before it
    // is deleted.
    let bundle_snap = if cs.written == bundle_here {
        let c = check_owned(ca_dir, CLAUDE_BUNDLE, &Rec::of(cs.bundle_sha.as_deref()));
        if !c.owned.may_replace() {
            let mut l = Line::refused(t, FOREIGN_BUNDLE);
            fill_paths(&mut l, &settings);
            l.bundle_path = Some(bundle_here);
            return l;
        }
        Some(c.snap)
    } else {
        None
    };
    // What the file becomes: the exact original bytes if nothing else touched it, else just
    // this key put back (or removed).
    let snap_bytes = settings
        .snapshot
        .as_ref()
        .map(|s| s.bytes.clone())
        .unwrap_or_default();
    let pristine = cs.new_sha.as_deref() == Some(sha_of(&snap_bytes).as_str());
    let from_backup = if pristine {
        exact_original(&settings, &cs)
    } else {
        None
    };
    let new_text: Option<String> = match from_backup {
        Some(orig) => (!cs.created_file).then_some(orig),
        None => {
            let edited = match &cs.original {
                Some(o) => doc.set_env_value(KEY, o),
                None => doc.unset_env_value(KEY, cs.created_env),
            };
            match edited {
                Ok(e) => {
                    let empty = jsonedit::parse(&e).is_ok_and(|d| d.is_empty_object());
                    if cs.created_file && empty {
                        None
                    } else {
                        Some(e)
                    }
                }
                Err(e) => {
                    let mut l = Line::refused(t, edit_text(e));
                    fill_paths(&mut l, &settings);
                    return l;
                }
            }
        }
    };
    let mut l = Line::new(t, Action::Undone, "");
    fill_paths(&mut l, &settings);
    l.from = Some(cs.written.clone());
    l.to = cs.original.clone();
    l.backup_path = Some(
        settings
            .dir
            .path()
            .join(format!(
                "settings.json.cainary-{}.bak",
                stamp(&now_string(h))
            ))
            .display()
            .to_string(),
    );
    if cs.written == bundle_here {
        l.bundle_path = Some(bundle_here.clone());
    }
    if dry_run {
        l.action = Action::Preview;
        l.message = format!(
            "Would {} in your Claude Code settings, after a backup. {RESTART}",
            match (&cs.original, new_text.is_none()) {
                (_, true) => "remove the settings file cAInary created".to_string(),
                (Some(_), _) => "restore your previous NODE_EXTRA_CA_CERTS value".to_string(),
                (None, _) => "remove env.NODE_EXTRA_CA_CERTS".to_string(),
            }
        );
        return l;
    }
    let fail = |m: &str| {
        let mut x = Line::refused(t, m);
        fill_paths(&mut x, &settings);
        x
    };
    if new_text.as_ref().is_some_and(|n| n.len() > MAX_FILE) {
        return fail("The restored settings file would be over 1 MiB; refusing to edit it.");
    }
    let _held = lock.expect("a real undo holds the trust lock");
    let after = new_text.as_ref().map(|n| sha_of(n.as_bytes()));
    let mut pending_state = state.clone();
    pending_state.pending = Some(Pending {
        kind: PendingKind::Undo,
        claude: cs.clone(),
        before: Some(sha_of(&snap_bytes)),
        after,
    });
    if save_state(ca_dir, &pending_state).is_err() {
        return fail("The state file could not be written; nothing was changed.");
    }
    if hook::stop("after-pending") {
        return fail("(simulated crash)");
    }
    let backup_name = match backup(
        &settings.dir,
        "settings.json",
        &snap_bytes,
        &stamp(&now_string(h)),
    ) {
        Ok(n) => n,
        Err(_) => {
            let _ = save_state(ca_dir, &state);
            return fail("The settings backup could not be written; nothing was changed.");
        }
    };
    // Stage first, compare, then swap (or, for a file cAInary created, compare, then remove).
    let tmp = match &new_text {
        Some(n) => match stage(&settings.dir, "settings.json", n.as_bytes(), 0o600) {
            Ok(t) => Some(t),
            Err(_) => {
                let _ = unlink_in(&settings.dir, &backup_name);
                let _ = save_state(ca_dir, &state);
                return fail("The settings file could not be written; nothing was undone.");
            }
        },
        None => None,
    };
    if !unchanged_since(&settings, "undo") {
        if let Some(t) = &tmp {
            discard(&settings.dir, t);
        }
        let _ = unlink_in(&settings.dir, &backup_name);
        let _ = save_state(ca_dir, &state);
        return fail(CHANGED);
    }
    let swapped = match &tmp {
        Some(t) => publish(&settings.dir, t, "settings.json"),
        None => unlink_checked(&settings.dir, "settings.json"),
    };
    match swapped {
        Ok(()) => {}
        Err(Done::No) => {
            let _ = save_state(ca_dir, &state);
            return fail("The settings file could not be changed; nothing was undone.");
        }
        Err(Done::Uncertain) => return fail(UNCERTAIN),
    }
    if hook::stop("after-rename") {
        return fail("(simulated crash)");
    }
    if let Err(m) = finish_undo(ca_dir, &state, bundle_snap) {
        return fail(m);
    }
    l.backup_path = Some(settings.dir.path().join(backup_name).display().to_string());
    l.message = RESTORED.to_string();
    l
}

/// The backup name a record may name: `settings.json.cainary-<stamp>[-n].bak`, nothing else.
pub(super) fn valid_backup_name(n: &str) -> bool {
    plain_name(n)
        && n.starts_with("settings.json.cainary-")
        && n.ends_with(".bak")
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
}

/// The original bytes from the backup, if the backup still holds exactly what was recorded. The
/// name comes from a record, so it is checked before it reaches a system call.
fn exact_original(s: &Settings, cs: &ClaudeState) -> Option<String> {
    let want = cs.orig_sha.as_deref()?;
    let name = Path::new(cs.backup.as_deref()?)
        .file_name()?
        .to_str()?
        .to_string();
    if !valid_backup_name(&name) {
        return None;
    }
    let bytes = read_in(&s.dir, &name).ok().flatten()?;
    (sha_of(&bytes) == want).then(|| String::from_utf8(bytes).ok())?
}

/// The record names settings that no longer exist. Cleared (surfacing a failure), unless this is
/// only a preview, which changes nothing.
fn stale_record(ca: &CaDir, mut state: State, dry_run: bool) -> Line {
    let t = Target::ClaudeCode;
    let l = nothing_changed(t);
    if dry_run {
        return l;
    }
    state.claude = None;
    if save_state(ca, &state).is_err() {
        return Line::refused(
            t,
            "The old record of the Claude Code change could not be cleared.",
        );
    }
    l
}

/// The last step of an undo: the bundle goes first, then the record and the transaction in one
/// write. A failure is reported, with the transaction left for the next run to finish.
fn finish_undo(
    ca: &CaDir,
    state: &State,
    bundle_snap: Option<Option<Snapshot>>,
) -> Result<(), &'static str> {
    const LEFT: &str = "The settings were restored, but the record of the change could not be cleared. Run cainary-otel-debug --trust-status to finish it.";
    if let Some(snap) = bundle_snap {
        // Unlinked only if it is still the file that was checked; if it changed meanwhile it stays.
        match unlink_unchanged(ca, CLAUDE_BUNDLE, &snap) {
            Ok(()) | Err(Replace::Changed) => {}
            Err(_) => return Err(LEFT),
        }
    }
    let mut done = state.clone();
    done.claude = None;
    done.pending = None;
    save_state(ca, &done).map_err(|_| LEFT)
}

const PENDING_NOTE: &str = "An interrupted Claude Code trust change is pending; run cainary-otel-debug --trust-status to finish or clear it.";

/// For previews and a status that couldn't take the lock: say a transaction is pending, change
/// nothing.
pub(super) fn inspect_note(_env: &Env<'_>, ca: &CaDir) -> Option<String> {
    read_state(ca).pending.map(|_| PENDING_NOTE.to_string())
}

/// For the status: the settings file at `path` as it is now, as (SHA-256, the value of our key);
/// `None` when there is no file or it can't be read.
pub(super) fn settings_view(path: &str) -> Option<(String, Option<String>)> {
    let dir = CaDir::open_shared(Path::new(path).parent()?, false).ok()??;
    let bytes = read_snapshot(&dir, "settings.json").ok()??.bytes;
    let value = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|t| jsonedit::parse(t).ok())
        .and_then(|d| d.env_value(KEY).ok().flatten());
    Some((sha_of(&bytes), value))
}

/// For the status: SHA-256 of a file in the settings directory (a backup), if it exists.
pub(super) fn sibling_sha(settings_path: &str, name: &str) -> Option<String> {
    let dir = CaDir::open_shared(Path::new(settings_path).parent()?, false).ok()??;
    read_in(&dir, name).ok().flatten().map(|b| sha_of(&b))
}

/// What the settings file holds now, by hash, for the file a transaction was about: `None` if the
/// directory can't be inspected, `Some(None)` if there is no file.
fn settings_sha(p: &Pending) -> Option<Option<String>> {
    let dir_path = Path::new(&p.claude.settings_path).parent()?.to_path_buf();
    match CaDir::open_shared(&dir_path, false) {
        Ok(Some(d)) => match read_snapshot(&d, "settings.json") {
            Ok(s) => Some(s.map(|s| sha_of(&s.bytes))),
            Err(_) => None,
        },
        Ok(None) => Some(None),
        Err(_) => None,
    }
}

/// A transaction found in the state file: finished, or cleared, according to what the settings
/// file turns out to hold. Returns a sentence for the user when something was found. Needs the
/// lock, so it can't clear a transaction another process is in the middle of.
pub(super) fn recover(env: &Env<'_>, ca: &CaDir, _lock: &TrustLock) -> Option<String> {
    let _ = env;
    let state = read_state(ca);
    if state.newer {
        return (state.pending.is_some() || !state.journal.is_empty()).then(|| NEWER.to_string());
    }
    if state.pending.is_none() && state.journal.is_empty() {
        return None;
    }
    let mut next = state.clone();
    let mut note: Option<&str> = None;
    if let Some(p) = state.pending.clone() {
        let Some(now) = settings_sha(&p) else {
            return Some("An interrupted Claude Code trust change was found, but the settings can't be inspected right now; run --trust-status again later.".into());
        };
        next.pending = None;
        note = Some(if now == p.after {
            match p.kind {
                PendingKind::Apply => {
                    next.claude = Some(p.claude.clone());
                    "Finished an interrupted Claude Code trust change."
                }
                PendingKind::Undo => {
                    next.claude = None;
                    if p.claude.written == ca.path().join(CLAUDE_BUNDLE).display().to_string()
                        && delete_owned(ca, CLAUDE_BUNDLE, &Rec::of(p.claude.bundle_sha.as_deref()))
                            .is_err()
                    {
                        return Some("An interrupted undo was found, but its bundle could not be removed; it will be tried again.".into());
                    }
                    "Finished an interrupted undo of the Claude Code trust change."
                }
            }
        } else if now == p.before {
            "An interrupted Claude Code trust change had not touched your settings; it was cleared."
        } else {
            "An interrupted Claude Code trust change was found, and your settings have changed since; they were left alone and the record was cleared."
        });
    }
    // Bundle replacements that were journaled, settled from each file's hash.
    if reconcile(ca, &mut next) {
        note = note.or(Some("Settled an interrupted certificate bundle update."));
    }
    if save_state(ca, &next).is_err() {
        return Some(
            "An interrupted Claude Code trust change was found but could not be cleared.".into(),
        );
    }
    note.map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::bundle::*;
    use crate::trust::files::*;
    use crate::trust::tests::*;
    use crate::trust::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn a_missing_settings_file_is_previewed_then_created_with_only_the_key() {
        let fx = Fx::new("create", "");
        let p = preview(&fx);
        assert_eq!(p.action, Action::Preview);
        assert!(p.message.contains("Would create") && p.message.contains("restart it afterwards"));
        assert!(
            p.message
                .contains("your organization's collector receives nothing")
        );
        assert!(
            !fx.settings().exists() && !fx.claude_dir().exists(),
            "a dry run writes nothing"
        );
        let a = apply(&fx);
        assert_eq!((a.action, a.code()), (Action::Applied, 0), "{a:?}");
        assert_eq!(a.key, Some(KEY));
        assert_eq!(a.to.as_deref(), Some(fx.ca_path().as_str()));
        assert_eq!(a.from, None);
        assert_eq!(a.backup_path, None, "no backup when there was no file");
        assert_eq!(
            fx.read_settings(),
            format!(
                "{{\n  \"env\": {{\n    \"{KEY}\": \"{}\"\n  }}\n}}\n",
                fx.ca_path()
            )
        );
        assert_eq!(mode(&fx.settings()), 0o600);
        assert_eq!(mode(&fx.ca_dir.join(STATE_FILE)), 0o600);
        assert!(fx.baks().is_empty());
        // Again: nothing to do.
        let again = apply(&fx);
        assert_eq!(again.action, Action::Already);
        assert!(fx.baks().is_empty());
    }

    #[test]
    fn existing_settings_keep_their_order_and_get_a_byte_identical_backup() {
        let fx = Fx::new("order", "");
        let original =
            "{\n    \"zeta\": 1,\n    \"model\": \"opus\",\n    \"alpha\": {\"x\": [1, 2]}\n}\n";
        fx.write_settings(original);
        let p = preview(&fx);
        let planned = p.backup_path.clone().expect("the backup is announced");
        assert!(
            planned.contains("settings.json.cainary-20260101T000000Z.bak"),
            "{planned}"
        );
        assert_eq!(fx.read_settings(), original, "the preview changed nothing");
        let a = apply(&fx);
        assert_eq!(a.action, Action::Applied, "{a:?}");
        assert_eq!(a.backup_path.as_deref(), Some(planned.as_str()));
        assert_eq!(fs::read_to_string(&planned).unwrap(), original);
        assert_eq!(mode(Path::new(&planned)), 0o600);
        let after = fx.read_settings();
        let keys: Vec<String> = serde_json::from_str::<Map<String, Value>>(&after)
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert_eq!(keys, ["zeta", "model", "alpha", "env"], "{after}");
        // Their layout (4 spaces here) is kept, not replaced by ours.
        assert!(
            after.ends_with("}\n") && after.contains("\n    \"zeta\": 1,"),
            "{after}"
        );
        assert_eq!(
            after.replace(
                &format!(
                    ",\n    \"env\": {{\n        \"{KEY}\": \"{}\"\n    }}",
                    fx.ca_path()
                ),
                ""
            ),
            original,
            "everything but the added member is byte-identical"
        );
        assert_eq!(env_key(&fx), Some(fx.ca_path()));
        // Undo removes the key it added (and the env object it created), keeping the rest.
        let u = undo(&fx);
        assert_eq!(u.action, Action::Undone, "{u:?}");
        assert_eq!(
            fx.read_settings(),
            original,
            "apply then undo restores the exact bytes"
        );
        // The undo made a backup of the file as it stood, without clobbering the first one.
        assert_eq!(fx.baks().len(), 2, "{:?}", fx.baks());
        assert_eq!(undo(&fx).action, Action::NothingToUndo);
    }

    #[test]
    fn undo_keeps_an_env_object_it_did_not_create() {
        let fx = Fx::new("keepenv", "");
        fx.write_settings("{\"env\":{\"FOO\":\"bar\"}}\n");
        assert_eq!(apply(&fx).action, Action::Applied);
        assert_eq!(undo(&fx).action, Action::Undone);
        let back: Value = serde_json::from_str(&fx.read_settings()).unwrap();
        assert_eq!(back, json!({"env": {"FOO": "bar"}}));
    }

    #[test]
    fn undo_deletes_a_file_cainary_created_and_only_then() {
        let fx = Fx::new("undocreated", "");
        assert_eq!(apply(&fx).action, Action::Applied);
        let u = undo(&fx);
        assert_eq!(u.action, Action::Undone, "{u:?}");
        assert!(!fx.settings().exists());
        // If the user added their own keys meanwhile, the file stays.
        assert_eq!(apply(&fx).action, Action::Applied);
        let mut doc: Map<String, Value> = serde_json::from_str(&fx.read_settings()).unwrap();
        doc.insert("model".into(), json!("opus"));
        fx.write_settings(&Value::Object(doc).to_string());
        assert_eq!(undo(&fx).action, Action::Undone);
        assert_eq!(
            serde_json::from_str::<Value>(&fx.read_settings()).unwrap(),
            json!({"model": "opus"})
        );
    }

    #[test]
    fn another_value_gets_a_combined_bundle_and_undo_restores_it() {
        let fx = Fx::new("other", "");
        let mine = fx.base.join("my-bundle.pem");
        fs::write(&mine, format!("{ROOT_A}{ROOT_B}")).unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            mine.display()
        ));
        let a = apply(&fx);
        assert_eq!(a.action, Action::Applied, "{a:?}");
        let bundle_path = fx.ca_dir.join(CLAUDE_BUNDLE).display().to_string();
        assert_eq!(a.bundle_path.as_deref(), Some(bundle_path.as_str()));
        assert_eq!(a.from.as_deref(), Some(mine.display().to_string().as_str()));
        assert_eq!(a.to.as_deref(), Some(bundle_path.as_str()));
        assert_eq!(env_key(&fx), Some(bundle_path.clone()));
        let b = fs::read_to_string(&bundle_path).unwrap();
        assert_eq!(
            pem_certs(&b),
            [ROOT_A, ROOT_B, CA1],
            "the user's certs, then exactly one collector cert"
        );
        assert_eq!(mode(Path::new(&bundle_path)), 0o644);
        assert_eq!(
            fs::read_to_string(&mine).unwrap(),
            format!("{ROOT_A}{ROOT_B}"),
            "their file is untouched"
        );
        // Re-running is a no-op; undo restores their path and removes our bundle.
        assert_eq!(apply(&fx).action, Action::Already);
        let u = undo(&fx);
        assert_eq!(u.action, Action::Undone, "{u:?}");
        assert_eq!(env_key(&fx), Some(mine.display().to_string()));
        assert!(!Path::new(&bundle_path).exists());
    }

    #[test]
    fn the_collector_cert_is_not_duplicated_when_the_users_file_already_has_it() {
        let fx = Fx::new("dedupe", "");
        let mine = fx.base.join("b.pem");
        fs::write(&mine, format!("{ROOT_A}{CA1}{ROOT_A}")).unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            mine.display()
        ));
        apply(&fx);
        let b = fs::read_to_string(fx.ca_dir.join(CLAUDE_BUNDLE)).unwrap();
        assert_eq!(pem_certs(&b), [ROOT_A, CA1]);
    }

    #[test]
    fn an_unreadable_other_bundle_or_a_missing_collector_cert_refuses() {
        let fx = Fx::new("refuse-bundle", "");
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"/nonexistent/bundle.pem\"}}}}\n"
        ));
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused);
        assert!(
            a.message
                .contains("could not be read as a certificate bundle"),
            "{}",
            a.message
        );
        assert_eq!(a.code(), 1);
        assert!(fx.baks().is_empty(), "nothing was changed");
        fs::remove_file(fx.ca_dir.join(CA_FILE)).unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            fx.base.join("b.pem").display()
        ));
        fs::write(fx.base.join("b.pem"), ROOT_A).unwrap();
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused);
        assert!(
            a.message.contains("Start the takeover once"),
            "{}",
            a.message
        );
    }

    #[test]
    fn managed_settings_that_set_the_key_refuse() {
        let fx = Fx::new("managed", "");
        fx.managed(&format!("{{\"env\":{{\"{KEY}\":\"/etc/org-ca.pem\"}}}}"));
        fx.write_settings("{\"model\":\"opus\"}\n");
        for l in [apply(&fx), preview(&fx)] {
            assert_eq!(l.action, Action::Refused, "{l:?}");
            assert_eq!(
                l.message,
                "Your organization's managed settings set NODE_EXTRA_CA_CERTS; they override this."
            );
            assert_eq!(l.code(), 1);
        }
        assert_eq!(fx.read_settings(), "{\"model\":\"opus\"}\n");
        assert!(fx.baks().is_empty());
        let st: Value = serde_json::from_str(&status_json(&fx.env(), "T")).unwrap();
        assert_eq!(st["claudeCode"]["state"], "managed");
        // Managed settings that don't touch the key don't block.
        let other = Fx::new("managed-other", "");
        other.managed("{\"allowManagedHooksOnly\":true}");
        assert_eq!(apply(&other).action, Action::Applied);
    }

    #[test]
    fn a_shell_value_is_mentioned_not_refused() {
        let fx = Fx::new("shell", "\"NODE_EXTRA_CA_CERTS\":\"/home/u/shell.pem\"");
        let a = apply(&fx);
        assert_eq!(a.action, Action::Applied, "{a:?}");
        assert!(
            a.message.contains(
                "Your shell sets NODE_EXTRA_CA_CERTS, which wins over the settings value."
            )
        );
        let none = Fx::new("noshell", "");
        assert!(!apply(&none).message.contains("Your shell"));
    }

    #[test]
    fn unsafe_settings_files_are_refused_untouched() {
        // A symlink, even to a file of ours.
        let fx = Fx::new("symlink", "");
        fs::create_dir_all(fx.claude_dir()).unwrap();
        let target = fx.base.join("dotfiles-settings.json");
        fs::write(&target, "{}\n").unwrap();
        symlink(&target, fx.settings()).unwrap();
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused);
        assert!(a.message.contains("symlink"), "{}", a.message);
        assert_eq!(fs::read_to_string(&target).unwrap(), "{}\n");
        // Not valid JSON, and valid JSON that isn't an object.
        for (tag, body) in [
            ("badjson", "{\"env\": "),
            ("array", "[1,2]"),
            ("badenv", "{\"env\": 3}"),
        ] {
            let fx = Fx::new(tag, "");
            fx.write_settings(body);
            let a = apply(&fx);
            assert_eq!(a.action, Action::Refused, "{tag}: {a:?}");
            assert_eq!(fx.read_settings(), body);
            assert!(fx.baks().is_empty());
        }
        // A file of someone else.
        let fx = Fx::new("owner", "");
        fx.write_settings("{}\n");
        FAKE_EUID.with(|c| c.set(Some(unsafe { libc::geteuid() } + 1)));
        let a = apply(&fx);
        FAKE_EUID.with(|c| c.set(None));
        assert_eq!(a.action, Action::Refused);
        assert!(a.message.contains("not owned by you"), "{}", a.message);
        assert_eq!(fx.read_settings(), "{}\n");
        // A symlinked ~/.claude.
        let fx = Fx::new("dirlink", "");
        let real = fx.base.join("real-claude");
        fs::create_dir_all(&real).unwrap();
        symlink(&real, fx.claude_dir()).unwrap();
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused);
        assert!(a.message.contains("not safe to edit"), "{}", a.message);
        assert!(!real.join("settings.json").exists());
    }

    #[test]
    fn undo_refuses_when_the_value_changed_and_says_nothing_to_undo_without_a_record() {
        let fx = Fx::new("changed", "");
        assert_eq!(undo(&fx).action, Action::NothingToUndo);
        assert_eq!(apply(&fx).action, Action::Applied);
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"/somewhere/else.pem\"}}}}\n"
        ));
        let u = undo(&fx);
        assert_eq!(u.action, Action::Refused, "{u:?}");
        assert!(u.message.contains("changed since"));
        assert_eq!(
            env_key(&fx).as_deref(),
            Some("/somewhere/else.pem"),
            "left alone"
        );
        // The undo preview of a clean state describes the change without making it.
        let fx = Fx::new("undopreview", "");
        apply(&fx);
        let before = fx.read_settings();
        let p = claude_code(&fx.env(), Mode::Undo { dry_run: true });
        assert_eq!(p.action, Action::Preview);
        assert_eq!(fx.read_settings(), before);
    }

    #[test]
    fn a_change_made_while_editing_aborts_the_apply_without_writing() {
        let fx = Fx::new("cas-apply", "");
        let original = "{\n  \"model\": \"opus\"\n}\n";
        fx.write_settings(original);
        let settings = fx.settings();
        // Claude Code (or the user) saves the file between our read and our swap.
        on_cas(move |point| {
            if point == "apply" {
                fs::write(
                    &settings,
                    "{\n  \"model\": \"sonnet\",\n  \"theme\": \"dark\"\n}\n",
                )
                .unwrap();
            }
        });
        let a = apply(&fx);
        clear_hooks();
        assert_eq!(a.action, Action::Refused, "{a:?}");
        assert_eq!(
            a.message,
            "Your Claude Code settings changed while editing; close Claude Code and try again."
        );
        assert_eq!(a.code(), 1);
        assert_eq!(
            fx.read_settings(),
            "{\n  \"model\": \"sonnet\",\n  \"theme\": \"dark\"\n}\n",
            "their newer save survives"
        );
        assert!(fx.baks().is_empty(), "the stale backup is removed");
        assert!(
            state_bytes(&fx).is_none(),
            "no half-finished record is left"
        );
        // A retry now works from the new contents.
        assert_eq!(apply(&fx).action, Action::Applied);
        assert!(fx.read_settings().contains("\"theme\": \"dark\""));
    }

    #[test]
    fn a_rewrite_with_the_same_bytes_is_still_a_different_file_and_aborts() {
        let fx = Fx::new("cas-ident", "");
        let original = "{\n  \"model\": \"opus\"\n}\n";
        fx.write_settings(original);
        let settings = fx.settings();
        on_cas(move |point| {
            if point == "apply" {
                // Same bytes, new inode (an editor's save-by-rename).
                let tmp = settings.with_extension("tmp");
                fs::write(&tmp, original).unwrap();
                fs::rename(&tmp, &settings).unwrap();
            }
        });
        let a = apply(&fx);
        clear_hooks();
        assert_eq!(a.action, Action::Refused, "{a:?}");
        assert_eq!(fx.read_settings(), original);
    }

    #[test]
    fn a_file_that_appears_while_a_missing_one_is_being_created_is_not_overwritten() {
        let fx = Fx::new("cas-create", "");
        let settings = fx.settings();
        let dir = fx.claude_dir();
        on_cas(move |point| {
            if point == "apply" {
                fs::create_dir_all(&dir).unwrap();
                fs::write(&settings, "{\"theme\":\"dark\"}\n").unwrap();
            }
        });
        let a = apply(&fx);
        clear_hooks();
        assert_eq!(a.action, Action::Refused, "{a:?}");
        assert_eq!(fx.read_settings(), "{\"theme\":\"dark\"}\n");
    }

    #[test]
    fn undo_never_deletes_or_overwrites_what_changed_since_it_looked() {
        let fx = Fx::new("cas-undo", "");
        assert_eq!(apply(&fx).action, Action::Applied);
        let ours = fx.read_settings();
        let settings = fx.settings();
        let ca = fx.ca_path();
        // Between undo's read of "only our key" and its delete, the user adds a key.
        on_cas(move |point| {
            if point == "undo" {
                fs::write(
                    &settings,
                    format!("{{\"env\":{{\"{KEY}\":\"{ca}\"}},\"model\":\"opus\"}}\n"),
                )
                .unwrap();
            }
        });
        let u = undo(&fx);
        clear_hooks();
        assert_eq!(u.action, Action::Refused, "{u:?}");
        assert_eq!(
            u.message,
            "Your Claude Code settings changed while editing; close Claude Code and try again."
        );
        assert!(
            fx.settings().exists(),
            "a file with new content is not deleted"
        );
        assert!(
            fx.read_settings().contains("\"model\": \"opus\"")
                || fx.read_settings().contains("\"model\":\"opus\"")
        );
        assert_ne!(fx.read_settings(), ours);
        // The record is intact (no transaction left), so undo works once the file is quiet.
        assert!(
            read_state(&CaDir::open_existing(&fx.ca_dir).unwrap().unwrap())
                .pending
                .is_none()
        );
        assert_eq!(undo(&fx).action, Action::Undone);
        assert!(fx.read_settings().contains("opus") && !fx.read_settings().contains(KEY));
    }

    #[test]
    fn numbers_decimals_escapes_and_layout_survive_byte_for_byte() {
        let original = "{\n\t\"big\": 123456789012345678901234567890,\n\t\"dec\": 0.1000000000000000055511151231257827,\n\t\"exp\": 1E400,\n\t\"uni\": \"\\u00e9\\ud83d\\ude00 \\/ \\n\",\n\t\"nested\": {\"a\": [1,   2 ,3], \"b\": null},\n\t\"flag\":    true\n}\n";
        let fx = Fx::new("fidelity", "");
        fx.write_settings(original);
        assert_eq!(apply(&fx).action, Action::Applied);
        let after = fx.read_settings();
        for kept in [
            "123456789012345678901234567890",
            "0.1000000000000000055511151231257827",
            "1E400",
            "\\u00e9\\ud83d\\ude00 \\/ \\n",
            "[1,   2 ,3]",
            "\"flag\":    true",
        ] {
            assert!(after.contains(kept), "{kept} in {after}");
        }
        assert!(
            after.starts_with(original.trim_end_matches("\n}\n")),
            "{after}"
        );
        assert_eq!(undo(&fx).action, Action::Undone);
        assert_eq!(fx.read_settings(), original, "apply then undo is exact");
    }

    #[test]
    fn undo_after_the_user_edited_elsewhere_is_targeted_and_keeps_their_edit() {
        let fx = Fx::new("targeted", "");
        let original = "{\n  \"model\": \"opus\"\n}\n";
        fx.write_settings(original);
        assert_eq!(apply(&fx).action, Action::Applied);
        let edited = fx.read_settings().replace("\"opus\"", "\"sonnet\"");
        fx.write_settings(&edited);
        let u = undo(&fx);
        assert_eq!(u.action, Action::Undone, "{u:?}");
        assert_eq!(fx.read_settings(), "{\n  \"model\": \"sonnet\"\n}\n");
    }

    #[test]
    fn duplicate_keys_comments_and_trailing_commas_are_refused_untouched() {
        for (tag, body) in [
            ("dup", "{\"model\":\"a\",\"model\":\"b\"}"),
            ("dupnested", "{\"hooks\":{\"x\":1,\"x\":2}}"),
            ("dupenv", "{\"env\":{\"A\":\"1\",\"A\":\"2\"}}"),
            ("comment", "{\n  // keep\n  \"model\": \"a\"\n}"),
            ("trailing", "{\"model\":\"a\",}"),
        ] {
            let fx = Fx::new(tag, "");
            fx.write_settings(body);
            let a = apply(&fx);
            assert_eq!(a.action, Action::Refused, "{tag}: {a:?}");
            assert_eq!(fx.read_settings(), body);
            assert!(fx.baks().is_empty() && state_bytes(&fx).is_none(), "{tag}");
        }
        let fx = Fx::new("dupmsg", "");
        fx.write_settings("{\"a\":1,\"a\":2}");
        assert!(apply(&fx).message.contains("twice in one object"));
    }

    #[test]
    fn group_or_other_writable_directories_are_refused_with_the_fix() {
        let fx = Fx::new("gw-claude", "");
        fs::create_dir_all(fx.claude_dir()).unwrap();
        for m in [0o775, 0o757, 0o777] {
            fs::set_permissions(fx.claude_dir(), fs::Permissions::from_mode(m)).unwrap();
            let a = apply(&fx);
            assert_eq!(a.action, Action::Refused, "{m:o}: {a:?}");
            assert!(a.message.contains("chmod go-w"), "{}", a.message);
            assert!(
                a.message.contains(&fx.claude_dir().display().to_string()),
                "{}",
                a.message
            );
            assert!(!fx.settings().exists());
        }
        fs::set_permissions(fx.claude_dir(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(apply(&fx).action, Action::Applied);
        // The state directory is held to the same rule.
        let fx = Fx::new("gw-state", "");
        fs::set_permissions(&fx.ca_dir, fs::Permissions::from_mode(0o775)).unwrap();
        let a = apply(&fx);
        assert_eq!(a.action, Action::Refused, "{a:?}");
        assert!(a.message.contains("chmod go-w"), "{}", a.message);
        assert_eq!(codex(&fx.env(), false).action, Action::Refused);
    }

    #[test]
    fn a_crash_after_the_record_but_before_the_change_leaves_nothing_behind() {
        let fx = Fx::new("crash-early", "");
        let original = "{\"model\":\"opus\"}\n";
        fx.write_settings(original);
        stop_at("after-pending");
        let _ = apply(&fx);
        clear_hooks();
        assert!(
            state_bytes(&fx).is_some(),
            "the transaction was recorded durably"
        );
        assert_eq!(fx.read_settings(), original);
        // The next call notices, clears it, and carries on.
        let s = status(&fx);
        assert_eq!(s["claudeCode"]["state"], "absent");
        assert!(
            s["note"]
                .as_str()
                .unwrap()
                .contains("had not touched your settings"),
            "{s}"
        );
        assert!(state_bytes(&fx).is_none());
        assert_eq!(apply(&fx).action, Action::Applied);
    }

    #[test]
    fn a_crash_after_the_swap_is_finished_by_the_next_call() {
        for next in ["status", "apply", "undo"] {
            let fx = Fx::new(&format!("crash-late-{next}"), "");
            fx.write_settings("{\"model\":\"opus\"}\n");
            stop_at("after-rename");
            let _ = apply(&fx);
            clear_hooks();
            assert!(
                fx.read_settings().contains(KEY),
                "the settings were changed"
            );
            match next {
                "status" => {
                    let s = status(&fx);
                    assert_eq!(s["claudeCode"]["state"], "applied", "{s}");
                    assert!(
                        s["note"]
                            .as_str()
                            .unwrap()
                            .contains("Finished an interrupted"),
                        "{s}"
                    );
                    assert_eq!(undo(&fx).action, Action::Undone);
                }
                "apply" => {
                    let a = apply(&fx);
                    assert_eq!(a.action, Action::Already, "{a:?}");
                    assert!(
                        a.message.contains("Finished an interrupted"),
                        "{}",
                        a.message
                    );
                    assert_eq!(undo(&fx).action, Action::Undone);
                }
                _ => {
                    let u = undo(&fx);
                    assert_eq!(u.action, Action::Undone, "{u:?}");
                    assert!(
                        u.message.contains("Finished an interrupted"),
                        "{}",
                        u.message
                    );
                }
            }
            assert_eq!(
                fx.read_settings(),
                "{\"model\":\"opus\"}\n",
                "{next}: exact original"
            );
            assert!(state_bytes(&fx).is_none(), "{next}");
        }
    }

    #[test]
    fn an_undo_that_crashes_after_the_swap_is_completed_and_cannot_resurrect() {
        let fx = Fx::new("crash-undo", "");
        let mine = fx.base.join("mine.pem");
        fs::write(&mine, ROOT_A).unwrap();
        fx.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            mine.display()
        ));
        assert_eq!(apply(&fx).action, Action::Applied);
        assert!(fx.ca_dir.join(CLAUDE_BUNDLE).exists());
        stop_at("after-rename");
        let _ = undo(&fx);
        clear_hooks();
        assert_eq!(
            env_key(&fx),
            Some(mine.display().to_string()),
            "the settings were restored"
        );
        let s = status(&fx);
        assert!(
            s["note"].as_str().unwrap().contains("interrupted undo"),
            "{s}"
        );
        assert!(
            !fx.ca_dir.join(CLAUDE_BUNDLE).exists(),
            "the bundle went with it"
        );
        assert!(state_bytes(&fx).is_none());
        // The user later chooses our CA path themselves; a stale record can't undo that.
        fx.write_settings(&format!("{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n", fx.ca_path()));
        assert_eq!(undo(&fx).action, Action::NothingToUndo);
        assert_eq!(env_key(&fx), Some(fx.ca_path()));
    }

    #[test]
    fn a_failed_record_write_is_reported_and_never_rolls_the_settings_back() {
        let fx = Fx::new("savefail", "");
        fx.write_settings("{\"model\":\"opus\"}\n");
        // The first save is the transaction record; fail the second (the commit).
        hook::FAIL_SAVES.with(|c| c.set(0));
        on_cas(|_| hook::FAIL_SAVES.with(|c| c.set(1)));
        let a = apply(&fx);
        clear_hooks();
        assert_eq!(a.action, Action::Refused, "{a:?}");
        assert!(
            a.message.contains("could not be saved") && a.message.contains("--trust-status"),
            "{}",
            a.message
        );
        assert!(
            fx.read_settings().contains(KEY),
            "the settings are left as written, not rolled back"
        );
        let s = status(&fx);
        assert_eq!(s["claudeCode"]["state"], "applied", "{s}");
        assert_eq!(undo(&fx).action, Action::Undone);
        // Undo's final record write failing is surfaced too, and the next call completes it.
        let fx = Fx::new("savefail-undo", "");
        assert_eq!(apply(&fx).action, Action::Applied);
        let ca = fx.ca_dir.clone();
        on_cas(move |point| {
            if point == "undo" {
                let _ = &ca;
                hook::FAIL_SAVES.with(|c| c.set(1));
            }
        });
        let u = undo(&fx);
        clear_hooks();
        assert_eq!(u.action, Action::Refused, "{u:?}");
        assert!(
            u.message
                .contains("record of the change could not be cleared"),
            "{}",
            u.message
        );
        assert!(!fx.settings().exists());
        let s = status(&fx);
        assert!(
            s["note"].as_str().unwrap().contains("interrupted undo"),
            "{s}"
        );
        fx.write_settings(&format!("{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n", fx.ca_path()));
        assert_eq!(
            undo(&fx).action,
            Action::NothingToUndo,
            "a stale record can't undo their later choice"
        );
    }

    #[test]
    fn undo_and_status_only_count_the_settings_the_record_was_made_for() {
        let a = Fx::new("loc-a", "");
        let mine = a.base.join("mine.pem");
        fs::write(&mine, ROOT_A).unwrap();
        a.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{}\"}}}}\n",
            mine.display()
        ));
        assert_eq!(apply(&a).action, Action::Applied);
        let bundle = a.ca_dir.join(CLAUDE_BUNDLE).display().to_string();
        // Another configuration (CLAUDE_CONFIG_DIR) that happens to hold the same value, sharing
        // the state directory.
        let b = Fx::new("loc-b", "");
        b.write_settings(&format!(
            "{{\"env\":{{\"{KEY}\":\"{bundle}\"}},\"theme\":\"dark\"}}\n"
        ));
        let env_b = Env {
            harness: &b.harness,
            ca_dir: a.ca_dir.clone(),
        };
        let st: Value = serde_json::from_str(&status_json(&env_b, "T")).unwrap();
        assert_eq!(st["claudeCode"]["state"], "other-value", "{st}");
        let u = claude_code(&env_b, Mode::Undo { dry_run: false });
        assert_eq!(u.action, Action::Refused, "{u:?}");
        assert!(u.message.contains("location changed"), "{}", u.message);
        assert!(
            b.read_settings().contains(&bundle) && b.read_settings().contains("dark"),
            "untouched"
        );
        // Nor is "already" claimed for it.
        let ap = claude_code(&env_b, Mode::Apply { dry_run: true });
        assert_ne!(ap.action, Action::Already, "{ap:?}");
        // The original configuration still undoes.
        assert_eq!(undo(&a).action, Action::Undone);
    }

    #[test]
    fn an_undo_preview_changes_nothing_even_with_a_stale_record() {
        let fx = Fx::new("undo-preview-ro", "");
        assert_eq!(apply(&fx).action, Action::Applied);
        let moved = fx.base.join("fx/home/.claude-away");
        fs::rename(fx.claude_dir(), &moved).unwrap();
        let before = state_bytes(&fx);
        let p = claude_code(&fx.env(), Mode::Undo { dry_run: true });
        assert_eq!(p.action, Action::NothingToUndo, "{p:?}");
        assert_eq!(state_bytes(&fx), before, "the record is still there");
        // A real undo of a record whose settings are gone clears it, and says so.
        let u = undo(&fx);
        assert_eq!(u.action, Action::NothingToUndo);
        assert!(state_bytes(&fx).is_none());
        fs::rename(&moved, fx.claude_dir()).unwrap();
    }

    #[test]
    fn the_preview_says_to_close_claude_code_first() {
        let fx = Fx::new("close-first", "");
        fx.write_settings("{}\n");
        let p = preview(&fx);
        assert!(
            p.message
                .contains("Close Claude Code before applying this, and restart it afterwards."),
            "{}",
            p.message
        );
        assert!(
            preview(&Fx::new("close-first-new", ""))
                .message
                .contains("Close Claude Code before")
        );
        apply(&fx);
        assert!(
            claude_code(&fx.env(), Mode::Undo { dry_run: true })
                .message
                .contains("Close Claude Code before")
        );
    }

    #[test]
    fn the_new_file_is_written_before_the_compare_and_the_rename_follows_at_once() {
        let fx = Fx::new("stage-first", "");
        fx.write_settings("{\"model\":\"opus\"}\n");
        let dir = fx.claude_dir();
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let s2 = seen.clone();
        on_cas(move |point| {
            if point == "apply" {
                let tmps: Vec<String> = fs::read_dir(&dir)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .filter(|n| n.contains(".cainary-tmp."))
                    .collect();
                // The staged file is complete on disk already, before anything is compared.
                for t in &tmps {
                    let text = fs::read_to_string(dir.join(t)).unwrap();
                    assert!(text.contains(KEY), "staged content is the final content");
                }
                *s2.borrow_mut() = tmps;
            }
        });
        let a = apply(&fx);
        clear_hooks();
        assert_eq!(a.action, Action::Applied, "{a:?}");
        assert_eq!(
            seen.borrow().len(),
            1,
            "exactly one staged file at the compare"
        );
        // A compare that fails leaves no staged file behind.
        let fx = Fx::new("stage-abort", "");
        fx.write_settings("{}\n");
        let p = fx.settings();
        on_cas(move |point| {
            if point == "apply" {
                fs::write(&p, "{\"a\":1}\n").unwrap();
            }
        });
        assert_eq!(apply(&fx).action, Action::Refused);
        clear_hooks();
        let leftovers: Vec<String> = fs::read_dir(fx.claude_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("tmp") || n.ends_with(".bak"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn a_failure_after_the_rename_keeps_the_transaction_and_says_so() {
        // Apply: the directory sync after the rename fails.
        let fx = Fx::new("uncertain-apply", "");
        fx.write_settings("{\"model\":\"opus\"}\n");
        on_cas(|point| {
            if point == "apply" {
                hook::FAIL_SYNCS.with(|c| c.set(1));
            }
        });
        let a = apply(&fx);
        clear_hooks();
        assert_eq!(a.action, Action::Refused, "{a:?}");
        assert!(
            a.message.contains("may have been changed") && a.message.contains("--trust-status"),
            "{}",
            a.message
        );
        assert!(!a.message.contains("nothing was changed"));
        assert!(
            fx.read_settings().contains(KEY),
            "what happened on disk is not undone"
        );
        assert!(
            String::from_utf8_lossy(&state_bytes(&fx).unwrap()).contains("pending"),
            "the transaction stays"
        );
        let s = status(&fx);
        assert_eq!(s["claudeCode"]["state"], "applied", "{s}");
        // Undo: same, on the unlink/rename of the undo.
        on_cas(|point| {
            if point == "undo" {
                hook::FAIL_SYNCS.with(|c| c.set(1));
            }
        });
        let u = undo(&fx);
        clear_hooks();
        assert_eq!(u.action, Action::Refused, "{u:?}");
        assert!(u.message.contains("may have been changed"));
        assert!(!fx.read_settings().contains(KEY));
        let s = status(&fx);
        assert!(
            s["note"].as_str().unwrap().contains("interrupted undo"),
            "{s}"
        );
        assert_eq!(undo(&fx).action, Action::NothingToUndo);
        // And deleting a file cAInary created.
        let fx = Fx::new("uncertain-delete", "");
        assert_eq!(apply(&fx).action, Action::Applied);
        on_cas(|point| {
            if point == "undo" {
                hook::FAIL_SYNCS.with(|c| c.set(1));
            }
        });
        let u = undo(&fx);
        clear_hooks();
        assert_eq!(u.action, Action::Refused);
        assert!(!fx.settings().exists());
        assert!(
            status(&fx)["note"]
                .as_str()
                .unwrap()
                .contains("interrupted undo")
        );
    }

    #[test]
    fn settings_that_are_not_utf8_are_refused_not_converted() {
        let fx = Fx::new("utf8", "");
        fs::create_dir_all(fx.claude_dir()).unwrap();
        let body = b"{\"x\":\"\xff\xfe\"}\n".to_vec();
        fs::write(fx.settings(), &body).unwrap();
        for l in [apply(&fx), preview(&fx)] {
            assert_eq!(l.action, Action::Refused, "{l:?}");
            assert_eq!(
                l.message,
                "The settings file is not valid UTF-8; refusing to edit it."
            );
        }
        assert_eq!(fs::read(fx.settings()).unwrap(), body, "bytes untouched");
        assert!(fx.baks().is_empty() && state_bytes(&fx).is_none());
        assert_eq!(status(&fx)["claudeCode"]["state"], "absent");
    }

    #[test]
    fn names_from_a_record_are_checked_and_nul_never_panics() {
        for ok in [
            "settings.json.cainary-20260101T000000Z.bak",
            "settings.json.cainary-20260101T000000Z-1.bak",
        ] {
            assert!(valid_backup_name(ok), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            "../settings.json.cainary-1.bak",
            "a/b.bak",
            "settings.json",
            "settings.json.cainary-1.bak\0",
            "settings.json.cainary-1.txt",
            "settings.json.cainary-a b.bak",
            "/etc/passwd",
        ] {
            assert!(!valid_backup_name(bad), "{bad:?}");
        }
        assert!(!plain_name(&"a".repeat(256)));
        let fx = Fx::new("names", "");
        let ca = CaDir::open_existing(&fx.ca_dir).unwrap().unwrap();
        assert!(matches!(read_snapshot(&ca, "a\0b"), Err(Why::Io)));
        assert!(unlink_in(&ca, "a\0b").is_err());
        assert!(write_atomic(&ca, "a\0b", b"x", 0o600).is_err());
        assert!(cname("a\0b").is_err());
        // A record that names a path outside the directory is not followed: the undo falls back to
        // editing just the key, and prints nothing from the record.
        let fx = Fx::new("badrecord", "");
        fx.write_settings("{\n  \"model\": \"opus\"\n}\n");
        assert_eq!(apply(&fx).action, Action::Applied);
        let sp = fx.ca_dir.join(STATE_FILE);
        let text = fs::read_to_string(&sp).unwrap();
        let tampered = text.replace("settings.json.cainary-", "../../../tmp/evil-");
        assert_ne!(text, tampered, "the record names the backup");
        fs::write(&sp, tampered).unwrap();
        let u = undo(&fx);
        assert_eq!(u.action, Action::Undone, "{u:?}");
        assert_eq!(fx.read_settings(), "{\n  \"model\": \"opus\"\n}\n");
        assert!(!u.message.contains("evil"));
    }

    #[test]
    fn a_result_over_the_read_cap_is_refused_before_anything_is_recorded() {
        let fx = Fx::new("toobig", "");
        // Under the cap by a little: valid, but the added member would push it over.
        let pad = "x".repeat(MAX_FILE - 100);
        let body = format!("{{\"pad\":\"{pad}\"}}");
        assert!(body.len() < MAX_FILE);
        fx.write_settings(&body);
        for l in [apply(&fx), preview(&fx)] {
            assert_eq!(l.action, Action::Refused, "{}", l.message);
            assert!(l.message.contains("over 1 MiB"), "{}", l.message);
        }
        assert_eq!(fx.read_settings(), body);
        assert!(fx.baks().is_empty() && state_bytes(&fx).is_none());
        // A file over the cap itself is refused as before.
        fx.write_settings(&format!("{{\"pad\":\"{}\"}}", "x".repeat(MAX_FILE)));
        assert!(apply(&fx).message.contains("over 1 MiB"));
    }

    #[test]
    fn the_undone_message_does_not_talk_about_applying() {
        let fx = Fx::new("undone-text", "");
        assert_eq!(apply(&fx).action, Action::Applied);
        let u = undo(&fx);
        assert_eq!(
            u.message,
            "Restored your previous Claude Code setting. Restart Claude Code for it to take effect."
        );
        assert!(!u.message.contains("before applying"));
    }
}
