//! `--config-stdin`: the first stdin line is one JSON object with the red-flag
//! patterns, so a GUI never puts pattern text in argv (visible in `ps`).
//!
//! Errors name the pattern or the key, never its text, and serde's own messages (which can
//! quote values) are never used.

use crate::redflag::file::FileConfig;
use crate::redflag::{Kind, Pattern, presets};
use serde_json::Value;

pub const MAX_CONFIG_BYTES: usize = 1 << 20;

fn bad<T>(m: impl Into<String>) -> Result<T, String> {
    Err(m.into())
}

pub fn parse(line: &str) -> Result<FileConfig, String> {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return bad(format!(
                "invalid config JSON (line {}, column {})",
                e.line(),
                e.column()
            ));
        }
    };
    let Value::Object(o) = v else {
        return bad("config must be a JSON object");
    };
    let mut cfg = FileConfig::default();
    let mut version = false;
    for (k, v) in &o {
        match k.as_str() {
            "v" => {
                if v.as_u64() != Some(1) {
                    return bad("config 'v' must be 1");
                }
                version = true;
            }
            "presets" => {
                let Value::Object(p) = v else {
                    return bad("config 'presets' must be an object");
                };
                for (name, on) in p {
                    if presets::find(name).is_none() {
                        return bad(format!("unknown preset '{}'", crate::output::escape(name)));
                    }
                    let Value::Bool(on) = on else {
                        return bad(format!("preset '{name}' must be true or false"));
                    };
                    cfg.presets.push((name.clone(), *on));
                }
            }
            "redFlags" => {
                let Value::Array(items) = v else {
                    return bad("config 'redFlags' must be an array");
                };
                for (i, item) in items.iter().enumerate() {
                    cfg.patterns.push(pattern(i, item)?);
                }
            }
            other => {
                return bad(format!(
                    "unknown config key '{}'",
                    crate::output::escape(other)
                ));
            }
        }
    }
    if !version {
        return bad("config needs \"v\":1");
    }
    Ok(cfg)
}

fn pattern(i: usize, v: &Value) -> Result<Pattern, String> {
    let Value::Object(o) = v else {
        return bad(format!("redFlags[{i}] must be an object"));
    };
    let mut name: Option<&str> = None;
    let mut kind = Kind::Text;
    let mut text: Option<&str> = None;
    let mut case_sensitive = false;
    for (k, v) in o {
        match (k.as_str(), v) {
            ("name", Value::String(s)) => name = Some(s),
            ("pattern", Value::String(s)) => text = Some(s),
            ("kind", Value::String(s)) => {
                kind = match s.as_str() {
                    "text" => Kind::Text,
                    "regex" => Kind::Regex,
                    _ => return bad(format!("redFlags[{i}].kind must be \"text\" or \"regex\"")),
                }
            }
            ("caseSensitive", Value::Bool(b)) => case_sensitive = *b,
            ("name" | "pattern" | "kind" | "caseSensitive", _) => {
                return bad(format!("redFlags[{i}].{k} has the wrong type"));
            }
            (other, _) => {
                return bad(format!(
                    "unknown key '{}' in redFlags[{i}]",
                    crate::output::escape(other)
                ));
            }
        }
    }
    let (Some(name), Some(text)) = (name, text) else {
        return bad(format!("redFlags[{i}] needs a name and a pattern"));
    };
    if !crate::redflag::valid_name(name) {
        return bad(format!("redFlags[{i}]: the name is invalid"));
    }
    Ok(Pattern {
        name: name.to_string(),
        kind,
        pattern: text.to_string(),
        case_sensitive,
        preset: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_documented_shape() {
        let c = parse(
            r#"{"v":1,"presets":{"ipv4":true,"email":false},
                "redFlags":[{"name":"customer","kind":"text","pattern":"acme","caseSensitive":false},
                            {"name":"db","kind":"regex","pattern":"db-[0-9]+","caseSensitive":true}]}"#,
        )
        .unwrap();
        assert_eq!(c.presets.len(), 2);
        assert_eq!(c.patterns.len(), 2);
        assert_eq!(c.patterns[1].kind, Kind::Regex);
        assert!(c.patterns[1].case_sensitive);
    }

    #[test]
    fn errors_never_echo_pattern_text_or_values() {
        let secret = "SECRET-PATTERN-TEXT";
        for bad_cfg in [
            format!(r#"{{"v":1,"redFlags":[{{"name":"a","pattern":"{secret}","extra":1}}]}}"#),
            format!(
                r#"{{"v":1,"redFlags":[{{"name":"a","pattern":"{secret}","kind":"{secret}"}}]}}"#
            ),
            format!(r#"{{"v":1,"redFlags":[{{"name":"Bad Name","pattern":"{secret}"}}]}}"#),
            format!(r#"{{"v":1,"redFlags":[{{"name":"a","pattern":5,"x":"{secret}"}}]}}"#),
            format!(r#"{{"v":"{secret}"}}"#),
            format!(r#"{{"v":1,"presets":{{"email":"{secret}"}}}}"#),
            format!(r#"{{"v":1,"redFlags":"{secret}"}}"#),
            format!(r#"[{secret}"#),
            format!(r#"{{"v":1}} {secret}"#),
        ] {
            let e = parse(&bad_cfg).unwrap_err();
            assert!(!e.contains(secret), "{e}");
        }
    }

    #[test]
    fn strictness() {
        for bad_cfg in [
            "{}",
            r#"{"v":2}"#,
            r#"{"v":1,"nope":1}"#,
            r#"{"v":1,"presets":{"nope":true}}"#,
            r#"{"v":1,"redFlags":[{"name":"a"}]}"#,
            r#"{"v":1,"redFlags":[3]}"#,
            "[]",
        ] {
            assert!(parse(bad_cfg).is_err(), "{bad_cfg}");
        }
        assert_eq!(parse(r#"{"v":1}"#).unwrap(), FileConfig::default());
    }
}
