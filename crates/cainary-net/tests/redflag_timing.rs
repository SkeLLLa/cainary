//! Timing and false-positive surveys (design §8.5, §14.6). All `#[ignore]`: run with
//! `cargo test -p cainary-net --release -- --ignored --nocapture`.

use cainary_net::redflag::{self, Kind, Matcher, Pattern, presets};
use regex::RegexSet;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn payload_dirs() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../cainary-core/tests/otel-payloads");
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn lower(&mut self, len: usize) -> String {
        (0..len)
            .map(|_| (b'a' + (self.next() % 26) as u8) as char)
            .collect()
    }
}

const BIG_KEYS: [&str; 4] = ["tool_parameters", "tool_input", "arguments", "output"];

fn collect(
    v: &Value,
    key: Option<&str>,
    rng: &mut Lcg,
    out: &mut Vec<String>,
    constants: &mut Vec<String>,
) {
    match v {
        Value::Object(o) => {
            let k = o.get("key").and_then(Value::as_str);
            for (name, child) in o {
                let ctx = if name == "value" { k } else { key };
                if name == "stringValue" {
                    if let Some(s) = child.as_str() {
                        if s == "<string>" {
                            let len = if key.is_some_and(|k| BIG_KEYS.contains(&k)) {
                                2048
                            } else {
                                8 + (rng.next() % 193) as usize
                            };
                            out.push(rng.lower(len));
                        } else {
                            constants.push(s.to_string());
                            out.push(s.to_string());
                        }
                    }
                } else {
                    collect(child, ctx, rng, out, constants);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|c| collect(c, key, rng, out, constants)),
        _ => {}
    }
}

/// Every string value of the sanitized fixtures, 1000 times over, placeholders randomized.
fn haystack() -> (Vec<String>, Vec<String>) {
    let mut rng = Lcg(42);
    let mut values = Vec::new();
    let mut constants = Vec::new();
    for dir in payload_dirs() {
        for f in ["logs.json", "metrics.json", "traces.json"] {
            let Ok(text) = std::fs::read_to_string(dir.join(f)) else {
                continue;
            };
            let doc: Value = serde_json::from_str(&text).unwrap();
            for _ in 0..1000 {
                collect(&doc, None, &mut rng, &mut values, &mut constants);
            }
        }
    }
    constants.sort();
    constants.dedup();
    (values, constants)
}

fn literals(constants: &[String]) -> Vec<String> {
    let mut lits: Vec<String> = constants
        .iter()
        .filter(|c| c.len() >= 6 && c.is_ascii())
        .take(10)
        .cloned()
        .collect();
    let present = lits.len();
    lits.extend((0..20 - present).map(|i| format!("acme-internal-secret-{i}")));
    lits
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn bench(values: &[String], mut f: impl FnMut(&str)) -> f64 {
    median(
        (0..5)
            .map(|_| {
                let t = Instant::now();
                for v in values {
                    f(v);
                }
                t.elapsed().as_nanos() as f64 / values.len() as f64
            })
            .collect(),
    )
}

/// The text path's per-value cost (20 literals, 10 present). Design §13 records the one-off
/// comparison with Aho-Corasick (0.87x, so the dependency was dropped); this keeps the number
/// visible so a regression shows.
#[test]
#[ignore]
fn text_path_cost() {
    let (values, constants) = haystack();
    let lits = literals(&constants);
    let matcher = Matcher::new(
        lits.iter()
            .enumerate()
            .map(|(i, l)| Pattern {
                name: format!("p{i}"),
                kind: Kind::Text,
                pattern: l.clone(),
                case_sensitive: false,
                preset: false,
            })
            .collect(),
    )
    .unwrap();
    let set = RegexSet::new(lits.iter().map(|l| format!("(?i){}", regex::escape(l)))).unwrap();
    let mut hits = Vec::new();
    let ours = bench(&values, |v| {
        hits.clear();
        matcher.scan(v, &mut hits);
    });
    let mut n = 0usize;
    let plain = bench(&values, |v| n += set.matches(v).iter().count());
    println!(
        "values: {}  literals: {}  Matcher: {ours:.0} ns/value  bare RegexSet: {plain:.0} ns/value  (hits {n})",
        values.len(),
        lits.len(),
    );
    assert!(
        ours < plain * 5.0,
        "the matcher costs more than 5x a bare RegexSet"
    );
}

#[test]
#[ignore]
fn adversarial_inputs_stay_inside_the_budget() {
    // Repeated characters, overlapping literals, a mostly-matching set, a maximum-size value.
    let overlapping: Vec<Pattern> = (1..=40)
        .map(|n| Pattern {
            name: format!("a{n}"),
            kind: Kind::Text,
            pattern: "a".repeat(n),
            case_sensitive: false,
            preset: false,
        })
        .collect();
    let m = Matcher::new(overlapping).unwrap();
    let mixed = Matcher::new(
        presets::PRESETS
            .iter()
            .map(presets::Preset::pattern)
            .chain((0..20).map(|i| Pattern {
                name: format!("w{i}"),
                kind: Kind::Text,
                pattern: format!("needle{i}"),
                case_sensitive: false,
                preset: false,
            }))
            .collect(),
    )
    .unwrap();
    let max = redflag::MAX_LEAF_BYTES;
    let cases: Vec<(&str, &Matcher, String)> = vec![
        ("repeated a, overlapping literals", &m, "a".repeat(max)),
        (
            "max-size value, presets + literals",
            &mixed,
            "x@y.example.com ".repeat(max / 16),
        ),
        (
            "mostly matching set",
            &mixed,
            (0..20)
                .map(|i| format!("needle{i} AKIAIOSFODNN7EXAMPLE a@b.io "))
                .collect::<String>()
                .repeat(max / 700),
        ),
        (
            "max-size lowercase noise",
            &mixed,
            "qwertyuiop ".repeat(max / 11),
        ),
    ];
    for (name, m, hay) in cases {
        let mut worst = 0u128;
        for _ in 0..5 {
            let mut s = m.scanner();
            let mut out = Vec::new();
            let t = Instant::now();
            s.scan(&hay, &mut out);
            worst = worst.max(t.elapsed().as_micros());
        }
        println!("{name}: worst of 5 = {worst} µs for {} bytes", hay.len());
        assert!(worst < 2_000_000, "{name} took {worst} µs");
    }
}

/// Counts preset hits over the raw POC dumps in `$CAINARY_OTEL_DUMPS` (local only). Prints
/// counts, never values. Run it before promoting `ipv4` to a default.
#[test]
#[ignore]
fn fp_survey() {
    let Ok(dir) = std::env::var("CAINARY_OTEL_DUMPS") else {
        println!("CAINARY_OTEL_DUMPS is not set; nothing to survey");
        return;
    };
    fn strings(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|c| strings(c, out)),
            Value::Object(o) => o.iter().for_each(|(k, c)| {
                out.push(k.clone());
                strings(c, out);
            }),
            _ => {}
        }
    }
    let mut all = Vec::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "json")
            && let Ok(v) = serde_json::from_str::<Value>(&std::fs::read_to_string(&p).unwrap())
        {
            strings(&v, &mut all);
        }
    }
    let m = Matcher::new(
        presets::PRESETS
            .iter()
            .map(presets::Preset::pattern)
            .collect(),
    )
    .unwrap();
    let mut counts = vec![0usize; m.patterns().len()];
    for s in &all {
        let mut out = Vec::new();
        m.scan(s, &mut out);
        for h in out {
            counts[h.pattern] += 1;
        }
    }
    println!("survey over {} strings", all.len());
    for (p, c) in m.patterns().iter().zip(counts) {
        println!("  {:<16} {c} strings", p.name);
    }
}
