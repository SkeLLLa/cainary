//! Red-flag patterns: the model, compilation and matching. Reusable by goal 3 (design §8.5).
//!
//! Text patterns are escaped into regexes with ASCII-only case folding (non-ASCII letters match
//! exactly): the timing test (design §13) found Aho-Corasick no faster than a `RegexSet` here.
//! Everything runs through one `RegexSet` per mode, then `Regex::find` for the span. Both are
//! linear-time, so hostile input can't ReDoS, and compilation has hard size limits.

pub mod file;
pub mod presets;

use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use std::fmt;

pub const MAX_PATTERN_BYTES: usize = 1024;
pub const MAX_PATTERNS: usize = 64;
/// All compiled regexes together, the set included (design §14.6).
pub const REGEX_BUDGET: usize = 16 << 20;
/// Text matched per request, and per single value; past either the batch is `scanIncomplete`.
pub const MAX_REQUEST_BYTES: usize = 4 << 20;
pub const MAX_LEAF_BYTES: usize = 256 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Regex,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Text => "text",
            Kind::Regex => "regex",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub name: String,
    pub kind: Kind,
    pub pattern: String,
    pub case_sensitive: bool,
    pub preset: bool,
}

/// A first match of one pattern: byte offsets into the scanned text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub pattern: usize,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    Empty(String),
    TooLong(String),
    BadName(String),
    Duplicate(String),
    Invalid(String, String),
    TooBig(String),
    TooMany,
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternError::Empty(n) => write!(f, "red flag '{n}': the pattern is empty"),
            PatternError::TooLong(n) => {
                write!(
                    f,
                    "red flag '{n}': the pattern is over {MAX_PATTERN_BYTES} bytes"
                )
            }
            PatternError::BadName(n) => write!(
                f,
                "red flag name '{n}' is invalid: use a-z, 0-9, '-' and '_' (up to 64 characters, starting with a letter or digit)"
            ),
            PatternError::Duplicate(n) => write!(f, "red flag '{n}' is defined more than once"),
            PatternError::Invalid(n, why) => write!(f, "red flag '{n}': invalid regex: {why}"),
            PatternError::TooBig(n) => {
                write!(
                    f,
                    "red flag '{n}': regex is too big to compile (limit 1 MiB)"
                )
            }
            PatternError::TooMany => write!(f, "more than {MAX_PATTERNS} red flags"),
        }
    }
}

impl std::error::Error for PatternError {}

/// `^[a-z0-9][a-z0-9_-]{0,63}$`
pub fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Patterns that share a mode (text or regex, case-sensitive or not), so one `RegexSet` with
/// the right flags covers them and no pattern is rewritten (wrapping would break `(?x)`).
#[derive(Default)]
struct Class {
    set: Option<RegexSet>,
    /// Pattern index of each member, and its individually compiled form (for the span).
    members: Vec<(usize, Regex)>,
}

pub struct Matcher {
    patterns: Vec<Pattern>,
    /// Indexed `text * 2 + case_sensitive`.
    classes: [Class; 4],
}

fn class_of(p: &Pattern) -> usize {
    usize::from(p.kind == Kind::Text) * 2 + usize::from(p.case_sensitive)
}

/// What a pattern compiles from: text is escaped, regexes are verbatim.
fn source(p: &Pattern) -> std::borrow::Cow<'_, str> {
    match p.kind {
        Kind::Text => regex::escape(&p.pattern).into(),
        Kind::Regex => (&p.pattern).into(),
    }
}

/// `ascii`: text patterns fold case for ASCII only.
fn builder(p: &str, case_insensitive: bool, ascii: bool) -> RegexBuilder {
    let mut b = RegexBuilder::new(p);
    b.case_insensitive(case_insensitive)
        .unicode(!ascii)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .nest_limit(64);
    b
}

fn compile_error(name: &str, e: regex::Error) -> PatternError {
    match e {
        regex::Error::CompiledTooBig(_) => PatternError::TooBig(name.to_string()),
        // regex's own message quotes the pattern, which may have come from --config-stdin.
        regex::Error::Syntax(_) => PatternError::Invalid(name.to_string(), "syntax error".into()),
        _ => PatternError::Invalid(name.to_string(), "unsupported expression".into()),
    }
}

/// Compiles with the 1 MiB per-regex limit and estimates its size: the smallest of 16 KiB,
/// 64 KiB, 256 KiB and 1 MiB that it fits in, which is what it is charged against the budget.
fn compile_costed(
    name: &str,
    p: &str,
    ci: bool,
    ascii: bool,
) -> Result<(Regex, usize), PatternError> {
    for limit in [16 << 10, 64 << 10, 256 << 10] {
        if let Ok(re) = builder(p, ci, ascii).size_limit(limit).build() {
            return Ok((re, limit));
        }
    }
    builder(p, ci, ascii)
        .build()
        .map(|re| (re, 1 << 20))
        .map_err(|e| compile_error(name, e))
}

impl Matcher {
    pub fn new(patterns: Vec<Pattern>) -> Result<Matcher, PatternError> {
        if patterns.len() > MAX_PATTERNS {
            return Err(PatternError::TooMany);
        }
        let mut seen = std::collections::HashSet::new();
        for p in &patterns {
            if !valid_name(&p.name) {
                return Err(PatternError::BadName(p.name.clone()));
            }
            if !seen.insert(p.name.as_str()) {
                return Err(PatternError::Duplicate(p.name.clone()));
            }
            if p.pattern.is_empty() {
                return Err(PatternError::Empty(p.name.clone()));
            }
            if p.pattern.len() > MAX_PATTERN_BYTES {
                return Err(PatternError::TooLong(p.name.clone()));
            }
        }

        let mut members: [Vec<(usize, Regex)>; 4] = Default::default();
        let mut srcs: [Vec<String>; 4] = Default::default();
        let mut spent = 0usize;
        for (i, p) in patterns.iter().enumerate() {
            let ascii = p.kind == Kind::Text;
            let src = source(p).into_owned();
            let (re, cost) = compile_costed(&p.name, &src, !p.case_sensitive, ascii)?;
            spent += cost;
            if spent > REGEX_BUDGET {
                return Err(PatternError::TooBig("(all regexes together)".into()));
            }
            members[class_of(p)].push((i, re));
            srcs[class_of(p)].push(src);
        }
        // Each pattern compiled alone above, so a failure here is only the shared size.
        let limit = ((REGEX_BUDGET - spent) / 4).max(256 << 10);
        let mut classes: [Class; 4] = Default::default();
        for (k, (m, src)) in members.into_iter().zip(srcs).enumerate() {
            if src.is_empty() {
                continue;
            }
            let set = RegexSetBuilder::new(&src)
                .case_insensitive(k % 2 == 0)
                .unicode(k < 2)
                .size_limit(limit)
                .dfa_size_limit(8 << 20)
                .nest_limit(64)
                .build()
                .map_err(|_| PatternError::TooBig("(all regexes together)".into()))?;
            classes[k] = Class {
                set: Some(set),
                members: m,
            };
        }
        Ok(Matcher { patterns, classes })
    }

    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    /// Appends the first hit of each pattern found in `hay`. Unbudgeted: for tests and callers
    /// that bound `hay` themselves.
    pub fn scan(&self, hay: &str, out: &mut Vec<Hit>) {
        for c in &self.classes {
            let Some(set) = &c.set else { continue };
            for k in set.matches(hay).iter() {
                let (pattern, re) = &c.members[k];
                if let Some(m) = re.find(hay) {
                    out.push(Hit {
                        pattern: *pattern,
                        start: m.start(),
                        end: m.end(),
                    });
                }
            }
        }
    }

    pub fn scanner(&self) -> Scanner<'_> {
        Scanner {
            matcher: self,
            bytes_left: MAX_REQUEST_BYTES,
            incomplete: false,
        }
    }
}

/// Which patterns the command line selects, before config files and stdin config are merged.
pub struct Selection<'a> {
    pub no_default: bool,
    pub cli_presets: &'a [String],
    pub cli_patterns: &'a [Pattern],
    /// `--match-case` names that must be defined by a config.
    pub match_case: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveError {
    pub code: u8,
    pub message: String,
}

/// Presets (defaults unless `--no-default-red-flags`, then each config's `[presets]`, then
/// `--preset`), then the CLI patterns, then the configs' patterns.
pub fn resolve(sel: &Selection, configs: &[file::FileConfig]) -> Result<Matcher, ResolveError> {
    let fail = |message: String| ResolveError { code: 2, message };
    let mut on: Vec<&'static str> = Vec::new();
    let mut set = |name: &str, enable: bool| {
        if let Some(p) = presets::find(name) {
            on.retain(|n| *n != p.name);
            if enable {
                on.push(p.name);
            }
        }
    };
    if !sel.no_default {
        for p in presets::PRESETS.iter().filter(|p| p.default_on) {
            set(p.name, true);
        }
    }
    for c in configs {
        for (name, enable) in &c.presets {
            set(name, *enable);
        }
    }
    for name in sel.cli_presets {
        set(name, true);
    }
    // Table order, not selection order, so output doesn't depend on how it was asked for.
    let mut patterns: Vec<Pattern> = presets::PRESETS
        .iter()
        .filter(|p| on.contains(&p.name))
        .map(presets::Preset::pattern)
        .collect();
    patterns.extend(sel.cli_patterns.iter().cloned());
    for c in configs {
        for p in &c.patterns {
            if presets::find(&p.name).is_some() {
                return Err(fail(format!(
                    "red flag '{}' has the name of a preset; pick another",
                    p.name
                )));
            }
            patterns.push(p.clone());
        }
    }
    for name in sel.match_case {
        match patterns.iter_mut().find(|p| &p.name == name && !p.preset) {
            Some(p) => p.case_sensitive = true,
            None => {
                return Err(fail(format!(
                    "--match-case names '{name}', which no red flag defines"
                )));
            }
        }
    }
    Matcher::new(patterns).map_err(|e| fail(e.to_string()))
}

/// One request's matching budget (design §14.6). Nothing is silently truncated: whenever a
/// limit cuts a scan short, `incomplete` is set.
pub struct Scanner<'m> {
    matcher: &'m Matcher,
    bytes_left: usize,
    pub incomplete: bool,
}

impl Scanner<'_> {
    pub fn is_empty(&self) -> bool {
        self.matcher.patterns.is_empty()
    }

    pub fn patterns(&self) -> &[Pattern] {
        &self.matcher.patterns
    }

    /// Scans a value, at most `MAX_LEAF_BYTES` of it and what's left of the request's bytes.
    /// Returns whether the whole value was scanned; false means a hit may have been missed.
    pub fn scan(&mut self, hay: &str, out: &mut Vec<Hit>) -> bool {
        if hay.is_empty() || self.matcher.patterns.is_empty() {
            return true;
        }
        let cap = MAX_LEAF_BYTES.min(self.bytes_left);
        let mut end = hay.len().min(cap);
        let complete = end == hay.len();
        if end < hay.len() {
            self.incomplete = true;
            while !hay.is_char_boundary(end) {
                end -= 1;
            }
        }
        if end == 0 {
            return false;
        }
        self.bytes_left -= end;
        self.matcher.scan(&hay[..end], out);
        complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, kind: Kind, pat: &str, cs: bool) -> Pattern {
        Pattern {
            name: name.into(),
            kind,
            pattern: pat.into(),
            case_sensitive: cs,
            preset: false,
        }
    }

    fn hits(m: &Matcher, hay: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        m.scan(hay, &mut out);
        let mut v: Vec<_> = out
            .iter()
            .map(|h| {
                (
                    m.patterns()[h.pattern].name.clone(),
                    hay[h.start..h.end].to_string(),
                )
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn text_is_case_insensitive_by_default_and_match_case_flips_it() {
        let m = Matcher::new(vec![
            p("ci", Kind::Text, "Acme-Internal", false),
            p("cs", Kind::Text, "Acme-Internal", true),
        ])
        .unwrap();
        assert_eq!(
            hits(&m, "x acme-internal y"),
            vec![("ci".to_string(), "acme-internal".to_string())]
        );
        assert_eq!(hits(&m, "Acme-Internal").len(), 2);
    }

    #[test]
    fn overlapping_literals_all_report() {
        let m = Matcher::new(vec![
            p("a", Kind::Text, "abc", false),
            p("b", Kind::Text, "bcd", false),
            p("c", Kind::Text, "abcd", false),
        ])
        .unwrap();
        assert_eq!(hits(&m, "xabcdx").len(), 3);
    }

    #[test]
    fn only_the_first_hit_per_pattern() {
        let m = Matcher::new(vec![
            p("t", Kind::Text, "ab", false),
            p("r", Kind::Regex, "ab", true),
        ])
        .unwrap();
        let mut out = Vec::new();
        m.scan("ab ab ab", &mut out);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|h| h.start == 0));
    }

    #[test]
    fn non_ascii_letters_match_exactly() {
        let m = Matcher::new(vec![p("t", Kind::Text, "Ärger", false)]).unwrap();
        assert!(hits(&m, "ärger").is_empty());
        assert_eq!(hits(&m, "xÄRGER Ärger").len(), 1);
    }

    #[test]
    fn regex_case_folding_follows_the_flag() {
        let m = Matcher::new(vec![
            p("ci", Kind::Regex, "db-[0-9]+", false),
            p("cs", Kind::Regex, "db-[0-9]+", true),
        ])
        .unwrap();
        assert_eq!(
            hits(&m, "DB-12"),
            vec![("ci".to_string(), "DB-12".to_string())]
        );
        assert_eq!(hits(&m, "db-12").len(), 2);
    }

    #[test]
    fn rejects_bad_patterns() {
        let e = |pats| Matcher::new(pats).err().unwrap();
        assert_eq!(
            e(vec![p("a", Kind::Text, "", false)]),
            PatternError::Empty("a".into())
        );
        assert_eq!(
            e(vec![p("a", Kind::Text, &"x".repeat(1025), false)]),
            PatternError::TooLong("a".into())
        );
        assert_eq!(
            e(vec![p("A", Kind::Text, "x", false)]),
            PatternError::BadName("A".into())
        );
        assert_eq!(
            e(vec![p("-a", Kind::Text, "x", false)]),
            PatternError::BadName("-a".into())
        );
        assert_eq!(
            e(vec![
                p("a", Kind::Text, "x", false),
                p("a", Kind::Regex, "y", false)
            ]),
            PatternError::Duplicate("a".into())
        );
        assert!(matches!(
            e(vec![p("a", Kind::Regex, "(", false)]),
            PatternError::Invalid(n, _) if n == "a"
        ));
        assert_eq!(
            e(vec![p("big", Kind::Regex, "a{1000}{1000}", false)]),
            PatternError::TooBig("big".into())
        );
        let many = (0..65)
            .map(|i| p(&format!("p{i}"), Kind::Text, "x", false))
            .collect();
        assert_eq!(e(many), PatternError::TooMany);
        assert_eq!(
            PatternError::TooBig("x".into()).to_string(),
            "red flag 'x': regex is too big to compile (limit 1 MiB)"
        );
    }

    #[test]
    fn inline_flags_like_x_work() {
        let m = Matcher::new(vec![
            p("ext", Kind::Regex, "(?x) a b  c", true),
            p("ci", Kind::Regex, "(?x) a b  c", false),
        ])
        .unwrap();
        assert_eq!(hits(&m, "xabcx").len(), 2);
        assert_eq!(hits(&m, "XABCX").len(), 1);
    }

    #[test]
    fn compile_errors_never_quote_the_pattern() {
        for pat in ["SECRET-TOKEN(", "SECRET-TOKEN[", "(?<SECRET-TOKEN"] {
            let e = Matcher::new(vec![p("a", Kind::Regex, pat, false)])
                .err()
                .unwrap()
                .to_string();
            assert!(!e.contains("SECRET"), "{e}");
            assert!(e.contains("'a'"));
        }
    }

    #[test]
    fn name_rules() {
        for ok in ["a", "0", "prod-db", "a_b", &"a".repeat(64)] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "-a", "_a", "A", "a b", "a.b", &"a".repeat(65)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    fn cfg(patterns: Vec<Pattern>, presets: Vec<(&str, bool)>) -> file::FileConfig {
        file::FileConfig {
            presets: presets
                .into_iter()
                .map(|(n, b)| (n.to_string(), b))
                .collect(),
            patterns,
        }
    }

    fn names(m: &Matcher) -> Vec<&str> {
        m.patterns().iter().map(|p| p.name.as_str()).collect()
    }

    #[test]
    fn resolve_orders_presets_file_then_cli() {
        let sel = |no_default, cli_presets: &'static [String]| Selection {
            no_default,
            cli_presets,
            cli_patterns: &[],
            match_case: &[],
        };
        let m = resolve(&sel(false, &[]), &[]).unwrap();
        assert_eq!(m.patterns().len(), 8);
        assert!(!names(&m).contains(&"ipv4"));
        // The file turns email off and ipv4 on; --preset turns email back on.
        let c = cfg(vec![], vec![("email", false), ("ipv4", true)]);
        let m = resolve(&sel(false, &[]), std::slice::from_ref(&c)).unwrap();
        assert!(!names(&m).contains(&"email") && names(&m).contains(&"ipv4"));
        let again: &'static [String] = Box::leak(Box::new(["email".to_string()]));
        let m = resolve(&sel(false, again), std::slice::from_ref(&c)).unwrap();
        assert!(names(&m).contains(&"email"));
        // --no-default-red-flags starts empty.
        let m = resolve(&sel(true, &[]), &[]).unwrap();
        assert!(m.patterns().is_empty());
        let m = resolve(&sel(true, &[]), std::slice::from_ref(&c)).unwrap();
        assert_eq!(names(&m), vec!["ipv4"]);
    }

    #[test]
    fn resolve_rejects_collisions_and_unknown_match_case() {
        let sel = Selection {
            no_default: true,
            cli_presets: &[],
            cli_patterns: &[],
            match_case: &["ghost".to_string()],
        };
        assert_eq!(resolve(&sel, &[]).err().unwrap().code, 2);
        let c = cfg(vec![p("email", Kind::Text, "x", false)], vec![]);
        let sel = Selection {
            match_case: &[],
            ..sel
        };
        assert!(
            resolve(&sel, &[c])
                .err()
                .unwrap()
                .message
                .contains("preset")
        );
        let c = cfg(vec![p("mine", Kind::Text, "x", false)], vec![]);
        let cli = [p("mine", Kind::Text, "y", false)];
        let sel = Selection {
            cli_patterns: &cli,
            ..sel
        };
        assert!(
            resolve(&sel, &[c])
                .err()
                .unwrap()
                .message
                .contains("more than once")
        );
        let c = cfg(vec![p("mine", Kind::Text, "x", false)], vec![]);
        let mc = ["mine".to_string()];
        let sel = Selection {
            cli_patterns: &[],
            match_case: &mc,
            ..sel
        };
        let m = resolve(&sel, &[c]).unwrap();
        assert!(m.patterns()[0].case_sensitive);
    }

    #[test]
    fn scanner_budgets_are_reported_not_silent() {
        let m = Matcher::new(vec![p("t", Kind::Text, "needle", false)]).unwrap();
        let mut s = m.scanner();
        let mut out = Vec::new();
        s.scan("a needle here", &mut out);
        assert_eq!(out.len(), 1);
        assert!(!s.incomplete);
        // One leaf over the per-value cap: only its head is scanned.
        let big = format!("{}needle", "a".repeat(MAX_LEAF_BYTES));
        out.clear();
        s.scan(&big, &mut out);
        assert!(out.is_empty() && s.incomplete);
        // The request budget runs out across many leaves.
        let mut s = m.scanner();
        let leaf = "b".repeat(MAX_LEAF_BYTES);
        for _ in 0..(MAX_REQUEST_BYTES / MAX_LEAF_BYTES) {
            s.scan(&leaf, &mut out);
        }
        assert!(!s.incomplete);
        s.scan("needle", &mut out);
        assert!(s.incomplete && out.is_empty());
    }

    #[test]
    fn overlapping_literals_on_repeated_text_stay_fast() {
        let lits: Vec<Pattern> = (1..=30)
            .map(|n| p(&format!("a{n}"), Kind::Text, &"a".repeat(n), false))
            .collect();
        let m = Matcher::new(lits).unwrap();
        let mut s = m.scanner();
        let mut out = Vec::new();
        let t = std::time::Instant::now();
        assert!(s.scan(&"a".repeat(MAX_LEAF_BYTES), &mut out));
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(out.len(), 30);
    }

    #[test]
    fn regex_budget_is_shared() {
        // Each of these is a few hundred KiB compiled; sixty of them are far past 16 MiB.
        let pats: Vec<Pattern> = (0..60)
            .map(|i| {
                p(
                    &format!("r{i}"),
                    Kind::Regex,
                    &format!("x{{100}}y{{100}}z{{100}}{i}[a-z]{{200}}"),
                    false,
                )
            })
            .collect();
        match Matcher::new(pats) {
            Err(PatternError::TooBig(n)) => assert!(n.contains("together") || n.starts_with('r')),
            Ok(_) => panic!("expected the shared budget to trip"),
            Err(e) => panic!("{e}"),
        }
        // The presets together are comfortably inside it.
        Matcher::new(
            presets::PRESETS
                .iter()
                .map(presets::Preset::pattern)
                .collect(),
        )
        .unwrap();
    }

    #[test]
    fn empty_matcher_scans_nothing() {
        let m = Matcher::new(vec![]).unwrap();
        let mut out = Vec::new();
        m.scan("anything", &mut out);
        assert!(out.is_empty());
    }
}
