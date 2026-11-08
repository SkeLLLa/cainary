//! In-memory activity log for the tray's Logs view: a bounded ring buffer of sanitized,
//! single-line entries. Pure model, no I/O.

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::strings::safe_line;

/// Default number of kept entries.
pub const DEFAULT_MAX_ENTRIES: usize = 2_000;
/// Lowest configurable entry cap.
pub const MIN_MAX_ENTRIES: usize = 100;
/// Highest configurable entry cap.
pub const MAX_MAX_ENTRIES: usize = 50_000;
/// Byte budget per allowed entry; the total is clamped to `MIN_BYTES..=MAX_BYTES`.
const BYTES_PER_ENTRY: usize = 1024;
pub const MIN_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_MESSAGE_CHARS: usize = 300;
pub const MAX_DETAIL_BYTES: usize = 16 * 1024;
const DETAIL_MARKER: &str = "\n… [truncated]";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Tray,
    Scan,
    Collector,
    Trust,
    Privilege,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Tray => "tray",
            Source::Scan => "scan",
            Source::Collector => "collector",
            Source::Trust => "trust",
            Source::Privilege => "privilege",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    /// UTC wall-clock time.
    pub ts: SystemTime,
    pub level: Level,
    pub source: Source,
    /// One line, at most 300 characters.
    pub message: String,
    /// Optional multi-line context, at most 16 KiB.
    pub detail: Option<String>,
}

impl Entry {
    fn bytes(&self) -> usize {
        self.message.len() + self.detail.as_ref().map_or(0, String::len)
    }
}

/// Filter for [`Logbook::view_json`]; empty `sources` means every source.
#[derive(Clone, Debug)]
pub struct Filter {
    pub min_level: Level,
    pub sources: Vec<Source>,
}

impl Default for Filter {
    fn default() -> Self {
        Filter {
            min_level: Level::Info,
            sources: Vec::new(),
        }
    }
}

/// Clamps a user-configured line count to `100..=50_000`, for a `[logs] max_lines` setting
/// (default 2,000) before building or resizing a [`Logbook`]. The tray doesn't use it yet.
pub fn clamp_max_entries(n: u32) -> usize {
    (n as usize).clamp(MIN_MAX_ENTRIES, MAX_MAX_ENTRIES)
}

/// Total bytes (message plus detail) kept for a given entry cap, so memory stays bounded
/// whatever the line setting: `max_entries` KiB, between 2 MiB and 32 MiB.
pub fn byte_cap(max_entries: usize) -> usize {
    max_entries
        .saturating_mul(BYTES_PER_ENTRY)
        .clamp(MIN_BYTES, MAX_BYTES)
}

#[derive(Debug)]
pub struct Logbook {
    entries: VecDeque<Entry>,
    bytes: usize,
    next_seq: u64,
    dropped: u64,
    max_entries: usize,
}

impl Default for Logbook {
    fn default() -> Self {
        Self::new()
    }
}

impl Logbook {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_ENTRIES)
    }

    /// A logbook keeping at most `max_entries` entries (clamped to 100..=50,000).
    pub fn with_limits(max_entries: usize) -> Self {
        Logbook {
            entries: VecDeque::new(),
            bytes: 0,
            next_seq: 1,
            dropped: 0,
            max_entries: max_entries.clamp(MIN_MAX_ENTRIES, MAX_MAX_ENTRIES),
        }
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Changes the entry cap (clamped to 100..=50,000), evicting oldest entries at once if it
    /// was lowered; evicted entries count as dropped.
    pub fn set_max_entries(&mut self, n: usize) {
        self.max_entries = n.clamp(MIN_MAX_ENTRIES, MAX_MAX_ENTRIES);
        self.evict();
    }

    fn evict(&mut self) {
        let max_bytes = byte_cap(self.max_entries);
        while self.entries.len() > self.max_entries
            || (self.bytes > max_bytes && self.entries.len() > 1)
        {
            if let Some(old) = self.entries.pop_front() {
                self.bytes -= old.bytes();
                self.dropped += 1;
            }
        }
    }

    /// Records an entry stamped now and returns its sequence number.
    ///
    /// Redaction is the caller's job: never pass batches, alerts, matches, values, stdin
    /// config, red-flag names or environment values. Only operational facts (what happened,
    /// which path or port, an exit status) belong here.
    pub fn push(
        &mut self,
        level: Level,
        source: Source,
        message: &str,
        detail: Option<&str>,
    ) -> u64 {
        self.push_at(SystemTime::now(), level, source, message, detail)
    }

    /// Like [`push`](Self::push) with an explicit timestamp.
    pub fn push_at(
        &mut self,
        ts: SystemTime,
        level: Level,
        source: Source,
        message: &str,
        detail: Option<&str>,
    ) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        let entry = Entry {
            seq,
            ts,
            level,
            source,
            message: clean_message(message),
            detail: detail.map(clean_detail),
        };
        self.bytes += entry.bytes();
        self.entries.push_back(entry);
        self.evict();
        seq
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Entries at `min_level` or above from any of `sources` (empty means all sources).
    pub fn filtered(&self, min_level: Level, sources: &[Source]) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| e.level >= min_level && (sources.is_empty() || sources.contains(&e.source)))
            .collect()
    }

    /// Number of error entries with `seq` greater than the given one (sidebar badge).
    pub fn errors_since(&self, seq: u64) -> usize {
        self.entries
            .iter()
            .filter(|e| e.seq > seq && e.level == Level::Error)
            .count()
    }

    /// Empties the log. Sequence numbers keep increasing; the dropped count resets.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
        self.dropped = 0;
    }

    /// Plain text for the clipboard: optional diagnostics block, a dropped-entries header, then
    /// `HH:MM:SS LEVEL source message` lines with detail indented below. The home directory is
    /// replaced with `~`.
    pub fn copy_text(
        &self,
        entries: &[&Entry],
        diagnostics: Option<&str>,
        home: Option<&str>,
    ) -> String {
        let mut out = String::new();
        if let Some(block) = diagnostics {
            out.push_str(block.trim_end());
            out.push_str("\n\n");
        }
        if self.dropped > 0 {
            out.push_str(&format!("{} older entries dropped\n", self.dropped));
        }
        for e in entries {
            out.push_str(&format!(
                "{} {:<5} {} {}\n",
                clock(e.ts),
                e.level.as_str().to_uppercase(),
                e.source.as_str(),
                e.message
            ));
            if let Some(detail) = &e.detail {
                for line in detail.lines() {
                    out.push_str("    ");
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        match home {
            Some(home) => tilde(&out, home),
            None => out,
        }
    }

    /// JSON for the bridge: the newest `limit` entries that pass `filter`, oldest first.
    pub fn view_json(&self, filter: &Filter, limit: usize) -> Value {
        let matched = self.filtered(filter.min_level, &filter.sources);
        let skip = matched.len().saturating_sub(limit);
        let shown: Vec<Value> = matched[skip..]
            .iter()
            .map(|e| {
                json!({
                    "seq": e.seq,
                    "ts": rfc3339(e.ts),
                    "level": e.level.as_str(),
                    "source": e.source.as_str(),
                    "message": e.message,
                    "detail": e.detail,
                })
            })
            .collect();
        json!({
            "total": self.entries.len(),
            "matched": matched.len(),
            "dropped": self.dropped,
            "entries": shown,
        })
    }
}

fn clean_message(message: &str) -> String {
    let safe = safe_line(message);
    if safe.chars().count() <= MAX_MESSAGE_CHARS {
        return safe;
    }
    let mut cut: String = safe.chars().take(MAX_MESSAGE_CHARS - 1).collect();
    cut.push('…');
    cut
}

fn clean_detail(detail: &str) -> String {
    let safe = detail.lines().map(safe_line).collect::<Vec<_>>().join("\n");
    if safe.len() <= MAX_DETAIL_BYTES {
        return safe;
    }
    let mut end = MAX_DETAIL_BYTES - DETAIL_MARKER.len();
    while !safe.is_char_boundary(end) {
        end -= 1;
    }
    let mut cut = safe[..end].to_owned();
    cut.push_str(DETAIL_MARKER);
    cut
}

fn secs(ts: SystemTime) -> i64 {
    match ts.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

fn clock(ts: SystemTime) -> String {
    let day = secs(ts).rem_euclid(86_400);
    format!("{:02}:{:02}:{:02}", day / 3600, day % 3600 / 60, day % 60)
}

fn rfc3339(ts: SystemTime) -> String {
    let s = secs(ts);
    let (y, m, d) = civil_from_days(s.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}T{}Z", clock(ts))
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Replaces `home` with `~` where it is a whole path prefix (not followed by a name character).
fn tilde(text: &str, home: &str) -> String {
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(home) {
        let after = &rest[at + home.len()..];
        let boundary = after
            .chars()
            .next()
            .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.')));
        out.push_str(&rest[..at]);
        out.push_str(if boundary { "~" } else { home });
        rest = after;
    }
    out.push_str(rest);
    out
}
