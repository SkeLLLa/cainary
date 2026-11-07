use std::time::{Duration, UNIX_EPOCH};

use cainary_tray_model::logbook::{Filter, Level, Logbook, Source, byte_cap, clamp_max_entries};

fn small(book: &mut Logbook, n: usize) {
    for i in 0..n {
        book.push(Level::Info, Source::Tray, &format!("m{i}"), None);
    }
}

#[test]
fn caps_by_count() {
    let mut book = Logbook::new();
    small(&mut book, 2_005);
    assert_eq!(book.len(), 2_000);
    assert_eq!(book.entries().next().unwrap().message, "m5");
}

#[test]
fn caps_by_bytes() {
    let mut book = Logbook::new();
    let detail = "x".repeat(16 * 1024);
    for _ in 0..200 {
        book.push(Level::Info, Source::Scan, "big", Some(&detail));
    }
    let bytes: usize = book
        .entries()
        .map(|e| e.message.len() + e.detail.as_ref().map_or(0, String::len))
        .sum();
    assert!(bytes <= 2 * 1024 * 1024);
    assert!(book.len() < 200);
    assert_eq!(book.len() as u64 + book.dropped(), 200);
}

#[test]
fn dropped_counted_and_reported() {
    let mut book = Logbook::with_limits(100);
    small(&mut book, 102);
    assert_eq!(book.dropped(), 2);
    let all: Vec<_> = book.entries().collect();
    assert!(
        book.copy_text(&all, None, None)
            .starts_with("2 older entries dropped\n")
    );
    assert_eq!(book.view_json(&Filter::default(), 10)["dropped"], 2);
}

#[test]
fn filter_by_level_and_source() {
    let mut book = Logbook::new();
    book.push(Level::Info, Source::Tray, "a", None);
    book.push(Level::Warn, Source::Scan, "b", None);
    book.push(Level::Error, Source::Trust, "c", None);
    book.push(Level::Error, Source::Scan, "d", None);
    let msgs = |v: Vec<&cainary_tray_model::logbook::Entry>| -> Vec<String> {
        v.into_iter().map(|e| e.message.clone()).collect()
    };
    assert_eq!(msgs(book.filtered(Level::Warn, &[])), ["b", "c", "d"]);
    assert_eq!(
        msgs(book.filtered(Level::Info, &[Source::Scan])),
        ["b", "d"]
    );
    assert_eq!(
        msgs(book.filtered(Level::Error, &[Source::Scan, Source::Tray])),
        ["d"]
    );
}

#[test]
fn errors_since() {
    let mut book = Logbook::new();
    book.push(Level::Error, Source::Tray, "e1", None);
    let mark = book.push(Level::Warn, Source::Tray, "w", None);
    book.push(Level::Error, Source::Tray, "e2", None);
    assert_eq!(book.errors_since(0), 2);
    assert_eq!(book.errors_since(mark), 1);
    assert_eq!(book.errors_since(mark + 1), 0);
}

#[test]
fn clear_keeps_seq_monotonic() {
    let mut book = Logbook::new();
    small(&mut book, 3);
    book.clear();
    assert!(book.is_empty());
    let seq = book.push(Level::Info, Source::Tray, "after", None);
    assert_eq!(seq, 4);
}

#[test]
fn copy_text_format_and_home_tilde() {
    let mut book = Logbook::new();
    let ts = UNIX_EPOCH + Duration::from_secs(3_600 * 13 + 60 * 5 + 9);
    book.push_at(
        ts,
        Level::Error,
        Source::Collector,
        "cannot write /home/ann/otel.log",
        Some("path: /home/ann/otel.log\n/home/annabel/x"),
    );
    let all: Vec<_> = book.entries().collect();
    let text = book.copy_text(&all, Some("cAInary 1.0\n"), Some("/home/ann"));
    assert_eq!(
        text,
        "cAInary 1.0\n\n13:05:09 ERROR collector cannot write ~/otel.log\n    path: ~/otel.log\n    /home/annabel/x\n"
    );
}

#[test]
fn sanitize_controls_and_bidi() {
    let mut book = Logbook::new();
    book.push(
        Level::Info,
        Source::Tray,
        "a\nb\u{1b}[31m\u{202e}evil\u{2066}\u{200b}",
        Some("l1\nl2\u{7}\u{202a}"),
    );
    let e = book.entries().next().unwrap();
    assert_eq!(
        e.message,
        "a\\u{000A}b\\u{001B}[31m\\u{202E}evil\\u{2066}\\u{200B}"
    );
    assert_eq!(e.detail.as_deref(), Some("l1\nl2\\u{0007}\\u{202A}"));
}

#[test]
fn message_truncated_to_300() {
    let mut book = Logbook::new();
    book.push(Level::Info, Source::Tray, &"é".repeat(500), None);
    let m = &book.entries().next().unwrap().message;
    assert_eq!(m.chars().count(), 300);
    assert!(m.ends_with('…'));
    book.push(Level::Info, Source::Tray, &"y".repeat(300), None);
    assert_eq!(book.entries().last().unwrap().message.len(), 300);
}

#[test]
fn detail_truncated_to_16k() {
    let mut book = Logbook::new();
    book.push(Level::Info, Source::Tray, "m", Some(&"é".repeat(20_000)));
    let d = book.entries().next().unwrap().detail.clone().unwrap();
    assert!(d.len() <= 16 * 1024);
    assert!(d.ends_with("[truncated]"));
}

#[test]
fn view_json_shape() {
    let mut book = Logbook::new();
    let ts = UNIX_EPOCH + Duration::from_secs(1_794_000_000);
    book.push_at(ts, Level::Warn, Source::Privilege, "port 80", Some("d"));
    book.push_at(ts, Level::Info, Source::Tray, "x", None);
    let v = book.view_json(
        &Filter {
            min_level: Level::Warn,
            sources: vec![],
        },
        5,
    );
    assert_eq!(v["total"], 2);
    assert_eq!(v["matched"], 1);
    assert_eq!(v["dropped"], 0);
    let e = &v["entries"][0];
    assert_eq!(e["seq"], 1);
    assert_eq!(e["ts"], "2026-11-06T21:20:00Z");
    assert_eq!(e["level"], "warn");
    assert_eq!(e["source"], "privilege");
    assert_eq!(e["message"], "port 80");
    assert_eq!(e["detail"], "d");
    let last = book.view_json(&Filter::default(), 1);
    assert_eq!(last["entries"][0]["message"], "x");
    assert!(last["entries"][0]["detail"].is_null());
}

#[test]
fn set_max_entries_evicts_and_counts() {
    let mut book = Logbook::new();
    small(&mut book, 300);
    book.set_max_entries(100);
    assert_eq!(book.len(), 100);
    assert_eq!(book.dropped(), 200);
    assert_eq!(book.entries().next().unwrap().message, "m200");
    book.set_max_entries(5_000);
    assert_eq!(book.len(), 100);
    assert_eq!(book.max_entries(), 5_000);
}

#[test]
fn max_entries_clamped() {
    assert_eq!(clamp_max_entries(0), 100);
    assert_eq!(clamp_max_entries(2_000), 2_000);
    assert_eq!(clamp_max_entries(u32::MAX), 50_000);
    assert_eq!(Logbook::with_limits(1).max_entries(), 100);
    let mut book = Logbook::new();
    book.set_max_entries(usize::MAX);
    assert_eq!(book.max_entries(), 50_000);
}

#[test]
fn byte_cap_scales_and_is_bounded() {
    assert_eq!(byte_cap(100), 2 * 1024 * 1024);
    assert_eq!(byte_cap(2_000), 2 * 1024 * 1024);
    assert_eq!(byte_cap(10_000), 10_000 * 1024);
    assert_eq!(byte_cap(50_000), 32 * 1024 * 1024);
    assert_eq!(byte_cap(usize::MAX), 32 * 1024 * 1024);
    let mut book = Logbook::with_limits(50_000);
    let detail = "x".repeat(16 * 1024);
    for _ in 0..4_000 {
        book.push(Level::Info, Source::Scan, "big", Some(&detail));
    }
    let bytes: usize = book
        .entries()
        .map(|e| e.message.len() + e.detail.as_ref().map_or(0, String::len))
        .sum();
    assert!(bytes <= 32 * 1024 * 1024);
    assert!(book.len() < 4_000);
}
