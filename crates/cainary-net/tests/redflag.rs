//! Public-API tests of the red-flag matcher: presets together, case modes, the TOML file,
//! and hostile inputs staying fast.

use cainary_net::redflag::file;
use cainary_net::redflag::{self, Kind, Matcher, Pattern, Selection, presets};
use std::time::{Duration, Instant};

fn pat(name: &str, kind: Kind, p: &str, cs: bool) -> Pattern {
    Pattern {
        name: name.into(),
        kind,
        pattern: p.into(),
        case_sensitive: cs,
        preset: false,
    }
}

fn defaults() -> Matcher {
    let sel = Selection {
        no_default: false,
        cli_presets: &[],
        cli_patterns: &[],
        match_case: &[],
    };
    redflag::resolve(&sel, &[]).unwrap()
}

fn names_hit(m: &Matcher, hay: &str) -> Vec<String> {
    let mut out = Vec::new();
    m.scan(hay, &mut out);
    let mut v: Vec<String> = out
        .iter()
        .map(|h| m.patterns()[h.pattern].name.clone())
        .collect();
    v.sort();
    v
}

#[test]
fn the_default_presets_find_what_they_should_in_one_pass() {
    let m = defaults();
    let hay = "mail alice@example-corp.com key AKIAIOSFODNN7EXAMPLE token xoxb-1234567890-abcdef";
    assert_eq!(
        names_hit(&m, hay),
        ["aws-access-key", "email", "slack-token"]
    );
    assert!(
        names_hit(&m, "version 2.1.316 on 10.0.0.1").is_empty(),
        "ipv4 is off by default"
    );
}

#[test]
fn ipv4_is_opt_in() {
    let sel = Selection {
        no_default: true,
        cli_presets: &["ipv4".to_string()],
        cli_patterns: &[],
        match_case: &[],
    };
    let m = redflag::resolve(&sel, &[]).unwrap();
    assert_eq!(names_hit(&m, "host 10.0.0.1"), ["ipv4"]);
    assert!(names_hit(&m, "v2.1.316").is_empty());
}

#[test]
fn custom_patterns_follow_the_case_flags() {
    let m = Matcher::new(vec![
        pat("lit-ci", Kind::Text, "Acme-Internal", false),
        pat("lit-cs", Kind::Text, "Acme-Internal", true),
        pat("re-ci", Kind::Regex, r"\bdb-[0-9]+\b", false),
    ])
    .unwrap();
    assert_eq!(names_hit(&m, "see acme-internal DB-7"), ["lit-ci", "re-ci"]);
    assert_eq!(names_hit(&m, "Acme-Internal"), ["lit-ci", "lit-cs"]);
}

#[test]
fn the_toml_file_round_trips_through_resolve() {
    let cfg = file::parse(
        r#"
[presets]
email = false
ipv4 = true
[red_flags]
customer = "acme-internal"
"#,
    )
    .unwrap();
    let sel = Selection {
        no_default: false,
        cli_presets: &[],
        cli_patterns: &[],
        match_case: &[],
    };
    let m = redflag::resolve(&sel, &[cfg]).unwrap();
    let hit = names_hit(&m, "ACME-Internal 10.1.1.1 a@example-corp.com");
    assert_eq!(hit, ["customer", "ipv4"]);
}

#[test]
fn hostile_regexes_stay_linear() {
    // Catastrophic for a backtracking engine; the regex crate is linear-time.
    let m = Matcher::new(vec![
        pat("nested", Kind::Regex, r"(a+)+$", true),
        pat("alt", Kind::Regex, r"(a|aa)+$", true),
        pat("dots", Kind::Regex, r"(.*)*x", true),
    ])
    .unwrap();
    let hay = "a".repeat(200_000) + "!";
    let t = Instant::now();
    let mut out = Vec::new();
    m.scan(&hay, &mut out);
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
}

#[test]
fn invalid_and_oversized_patterns_are_refused_by_name() {
    for (p, expect) in [
        (pat("a", Kind::Regex, "(", false), "invalid regex"),
        (pat("big", Kind::Regex, "a{1000}{1000}", false), "too big"),
        (pat("e", Kind::Text, "", false), "empty"),
    ] {
        let e = Matcher::new(vec![p]).err().unwrap().to_string();
        assert!(e.contains(expect), "{e}");
    }
    let _ = presets::PRESETS.len();
}
