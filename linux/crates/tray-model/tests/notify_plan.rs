//! notify_plan::plan (as NotifierTests.swift's planner cases).

mod common;

use std::collections::HashSet;

use cainary_tray_model::notify_plan::plan;
use cainary_tray_model::report::Report;
use common::{change, with_changes};
use serde_json::json;

fn report(changes: Vec<serde_json::Value>) -> Report {
    Report::decode(&with_changes("claude-code-linux.json", changes, None)).unwrap()
}

fn all(r: &Report) -> HashSet<String> {
    r.changes.iter().flatten().map(|c| c.id.clone()).collect()
}

#[test]
fn one_notification_per_entry_folding_its_changes() {
    let r = report(vec![
        change("c1", "claude", "Bedrock routing was turned on"),
        change("c2", "claude", "Telemetry export was turned on"),
        change("c3", "claude", "A third thing"),
    ]);
    let planned = plan(r.changes.as_deref().unwrap(), &r, &all(&r));
    assert_eq!(planned.len(), 1);
    let p = &planned[0];
    assert_eq!(p.entry, "claude");
    assert_eq!(p.summary, "Claude · MEDIUM");
    assert_eq!(p.body, "Bedrock routing was turned on (+2 more)");
    assert_eq!(p.change_ids, ["c1", "c2", "c3"]);
}

#[test]
fn only_due_ids_are_planned() {
    let r = report(vec![
        change("c1", "claude", "one"),
        change("c2", "claude", "two"),
    ]);
    let due: HashSet<String> = ["c2".to_string()].into();
    let planned = plan(r.changes.as_deref().unwrap(), &r, &due);
    assert_eq!(planned[0].body, "two");
    assert_eq!(planned[0].change_ids, ["c2"]);
}

#[test]
fn skips_report_scope_unknown_slugs_silent_changes_and_missing_entries() {
    let mut report_scope = change("r", "claude", "report");
    report_scope["scope"] = json!("report");
    let mut unknown_scope = change("u1", "claude", "u1");
    unknown_scope["scope"] = json!("galaxy");
    let mut unknown_kind = change("u2", "claude", "u2");
    unknown_kind["kind"] = json!("teleported");
    let mut silent = change("s", "claude", "s");
    silent["notify"] = json!(false);
    let missing = change("m", "nobody", "m");
    let r = report(vec![
        report_scope,
        unknown_scope,
        unknown_kind,
        silent,
        missing,
    ]);
    assert!(plan(r.changes.as_deref().unwrap(), &r, &all(&r)).is_empty());
    // And none of them counts as notifying.
    assert_eq!(r.notifying_change_ids(), ["r", "m"]);
}
