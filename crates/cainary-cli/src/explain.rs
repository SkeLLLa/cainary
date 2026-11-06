//! `cainary explain <id|key>`: the finding block plus everything its payload preview holds.
//! Pure rendering: the report comes in, text goes out.

use crate::text::{Paint, finding_block, noun};
use cainary_core::model::{AttrOut, Finding, Payload, RecordOut, Report, Sent};
use cainary_core::rules::otel_catalog::Export;
use cainary_core::rules::otel_catalog::Group;

/// The finding with this `id` or `key`.
pub fn find<'a>(report: &'a Report, target: &str) -> Option<&'a Finding> {
    report
        .apps
        .iter()
        .chain(&report.others)
        .flat_map(|e| &e.findings)
        .find(|f| f.id == target || f.key == target)
}

pub fn render(f: &Finding, color: bool, width: usize) -> String {
    let p = Paint(color);
    let mut out = String::new();
    finding_block(&mut out, f, false, &p, false);
    let Some(pl) = &f.payload else {
        out.push_str("\nThis finding has no payload preview.\n");
        return out;
    };
    payload(&mut out, pl, &p, width);
    out
}

fn sent_word(s: Sent) -> &'static str {
    match s {
        Sent::Yes => "sent",
        Sent::Redacted => "redacted",
        Sent::Generic => "generic",
        Sent::No => "not sent",
        Sent::Local => "local",
    }
}

fn export_name(e: Export) -> &'static str {
    match e {
        Export::Logs => "log",
        Export::Metrics => "metrics",
        Export::Traces => "trace",
        Export::Beta => "detailed trace",
    }
}

fn payload(out: &mut String, pl: &Payload, p: &Paint, width: usize) {
    out.push_str(&format!(
        "\n{}\n",
        p.bold(&format!(
            "What the {} export carries (catalog {}; {})",
            export_name(pl.export),
            pl.catalog,
            pl.docs
        ))
    ));
    if pl.maybe {
        out.push_str("  Not fully documented by the vendor: this may differ from what is sent.\n");
    }
    if !pl.gates.is_empty() {
        out.push_str(&format!("\n{}\n", p.bold("Flags")));
        for g in &pl.gates {
            out.push_str(&format!("  {}\n", g.text));
        }
    }
    attrs(out, "Identity (on every record)", &pl.identity, p);
    attrs(out, "Resource", &pl.resource, p);

    let n = noun(pl.export);
    let title = format!(
        "{} ({}; * seen on the wire in {}; (may) = not in the vendor docs)",
        capitalize(n),
        pl.records.len(),
        pl.catalog
    );
    out.push_str(&format!("\n{}\n", p.bold(&title)));
    for r in &pl.records {
        record(out, r, p, width);
    }

    out.push_str(&format!("\n{}\n", p.bold("Sample record")));
    for l in &pl.sample {
        out.push_str(&format!("  {l}\n"));
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map_or(String::new(), |f| f.to_uppercase().chain(c).collect())
}

fn attrs(out: &mut String, title: &str, list: &[AttrOut], p: &Paint) {
    if list.is_empty() {
        return;
    }
    out.push_str(&format!("\n{}\n", p.bold(title)));
    let w = list
        .iter()
        .map(|a| a.key.chars().count())
        .max()
        .unwrap_or(0);
    for a in list {
        let mut line = format!("  {:w$}  {}", a.key, a.what);
        if let (Some(flag), Some(sent)) = (&a.flag, a.sent) {
            line.push_str(&format!(" ({}: {})", flag, sent_word(sent)));
        }
        if a.maybe {
            line.push_str(" (may)");
        }
        out.push_str(&format!("{line}\n"));
    }
}

fn record(out: &mut String, r: &RecordOut, p: &Paint, width: usize) {
    let mut head = format!("  {}", r.name);
    if r.observed {
        head.push_str(" *");
    }
    if r.maybe {
        head.push_str(" (may)");
    }
    if let Some(u) = &r.unit {
        head.push_str(&format!(" [{u}]"));
    }
    if let (Some(flag), Some(sent)) = (&r.flag, r.sent) {
        head.push_str(&format!(" ({}: {})", flag, sent_word(sent)));
    }
    out.push_str(&format!("{head}\n"));
    out.push_str(&format!("    {}\n", p.dim(&r.what)));
    let plain: Vec<String> = r
        .attrs
        .iter()
        .filter(|a| a.group != Group::Content)
        .map(|a| {
            if a.maybe {
                format!("{} (may)", a.key)
            } else {
                a.key.clone()
            }
        })
        .collect();
    wrapped(out, "keys: ", &plain, width);
    let content: Vec<String> = r
        .attrs
        .iter()
        .filter(|a| a.group == Group::Content)
        .map(|a| match a.sent {
            Some(s) => format!("{} ({})", a.key, sent_word(s)),
            None => a.key.clone(),
        })
        .collect();
    wrapped(out, "content: ", &content, width);
}

/// `label` then the items joined by `, `, wrapped under the label at `width`.
fn wrapped(out: &mut String, label: &str, items: &[String], width: usize) {
    if items.is_empty() {
        return;
    }
    let indent = "    ";
    let mut line = format!("{indent}{label}");
    let hang = " ".repeat(indent.len() + label.len());
    let mut first = true;
    for (i, item) in items.iter().enumerate() {
        let piece = if i + 1 < items.len() {
            format!("{item}, ")
        } else {
            item.clone()
        };
        if !first && line.chars().count() + piece.trim_end().chars().count() > width {
            out.push_str(line.trim_end());
            out.push('\n');
            line = hang.clone();
        }
        line.push_str(&piece);
        first = false;
    }
    out.push_str(&line);
    out.push('\n');
}
