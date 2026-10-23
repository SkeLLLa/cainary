//! Turns due changes into notifications (macos.md §2.4): one per entry, folding that entry's
//! due changes. Posting is the caller's business (`org.freedesktop.Notifications`).

use std::collections::{HashMap, HashSet};

use crate::level::Level;
use crate::report::{Change, Report};

/// One notification to post.
#[derive(Clone, Debug, PartialEq)]
pub struct Planned {
    /// The entry it is about; activating the notification opens Details there.
    pub entry: String,
    pub summary: String,
    pub body: String,
    pub level: Level,
    /// The change ids it covers, in core order.
    pub change_ids: Vec<String>,
}

/// Plans notifications for the changes in `ids`. Changes with an unknown scope or kind, the
/// `report` scope, and entries missing from the report are skipped.
pub fn plan(changes: &[Change], report: &Report, ids: &HashSet<String>) -> Vec<Planned> {
    let mut order: Vec<&str> = Vec::new();
    let mut grouped: HashMap<&str, Vec<&Change>> = HashMap::new();
    for change in changes {
        if !change.notifies() || change.scope == "report" || !ids.contains(&change.id) {
            continue;
        }
        let Some(entry) = change.entry.as_deref() else {
            continue;
        };
        if report.entry(entry).is_none() {
            continue;
        }
        let list = grouped.entry(entry).or_default();
        if list.is_empty() {
            order.push(entry);
        }
        list.push(change);
    }
    order
        .into_iter()
        .filter_map(|id| {
            let entry = report.entry(id)?;
            let list = &grouped[id];
            let first = list.first()?;
            let more = match list.len() {
                1 => String::new(),
                n => format!(" (+{} more)", n - 1),
            };
            Some(Planned {
                entry: id.to_owned(),
                summary: format!("{} · {}", entry.name, entry.status.label),
                body: format!("{}{more}", first.text),
                level: entry.status.level.clone(),
                change_ids: list.iter().map(|c| c.id.clone()).collect(),
            })
        })
        .collect()
}
