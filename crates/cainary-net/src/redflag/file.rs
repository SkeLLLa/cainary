//! The `--red-flags` TOML file: read once, strict. Unknown keys are an error
//! that names the key. The only reader of the file system in this crate.

use super::{Kind, Pattern, presets};
use std::io::Read;
use std::path::Path;

pub const MAX_FILE_BYTES: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileConfig {
    /// `[presets]`: name → on/off, in name order (the TOML table is sorted).
    pub presets: Vec<(String, bool)>,
    pub patterns: Vec<Pattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileError {
    /// Unreadable or too large: exit 1.
    Read(String),
    /// Not valid TOML, or not the documented shape: exit 2.
    Invalid(String),
}

impl FileError {
    pub fn code(&self) -> u8 {
        match self {
            FileError::Read(_) => 1,
            FileError::Invalid(_) => 2,
        }
    }
    pub fn message(&self) -> &str {
        match self {
            FileError::Read(m) | FileError::Invalid(m) => m,
        }
    }
}

pub fn load(path: &Path) -> Result<FileConfig, FileError> {
    let shown = path.display();
    let read =
        |e: std::io::Error| FileError::Read(format!("can't read red flags file {shown}: {e}"));
    let f = std::fs::File::open(path).map_err(read)?;
    let mut text = String::new();
    f.take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(read)?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(FileError::Read(format!(
            "red flags file {shown} is over 1 MiB"
        )));
    }
    parse(&text).map_err(|e| match e {
        FileError::Invalid(m) => FileError::Invalid(format!("{shown}: {m}")),
        other => other,
    })
}

fn invalid<T>(msg: impl Into<String>) -> Result<T, FileError> {
    Err(FileError::Invalid(msg.into()))
}

pub fn parse(text: &str) -> Result<FileConfig, FileError> {
    let doc: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| FileError::Invalid(e.message().to_string()))?;
    let mut cfg = FileConfig::default();
    for (key, value) in &doc {
        match key.as_str() {
            "presets" => {
                let toml::Value::Table(t) = value else {
                    return invalid("[presets] must be a table");
                };
                for (name, v) in t {
                    if presets::find(name).is_none() {
                        return invalid(format!("unknown preset '{name}' in [presets]"));
                    }
                    let toml::Value::Boolean(on) = v else {
                        return invalid(format!("presets.{name} must be true or false"));
                    };
                    cfg.presets.push((name.clone(), *on));
                }
            }
            "red_flags" => {
                let toml::Value::Table(t) = value else {
                    return invalid("[red_flags] must be a table");
                };
                for (name, v) in t {
                    cfg.patterns.push(pattern(name, v)?);
                }
            }
            other => return invalid(format!("unknown key '{other}'")),
        }
    }
    Ok(cfg)
}

fn pattern(name: &str, v: &toml::Value) -> Result<Pattern, FileError> {
    let mut p = Pattern {
        name: name.to_string(),
        kind: Kind::Text,
        pattern: String::new(),
        case_sensitive: false,
        preset: false,
    };
    match v {
        toml::Value::String(s) => p.pattern = s.clone(),
        toml::Value::Table(t) => {
            let mut have_pattern = false;
            for (k, v) in t {
                match (k.as_str(), v) {
                    ("pattern", toml::Value::String(s)) => {
                        p.pattern = s.clone();
                        have_pattern = true;
                    }
                    ("kind", toml::Value::String(s)) => {
                        p.kind = match s.as_str() {
                            "text" => Kind::Text,
                            "regex" => Kind::Regex,
                            other => {
                                return invalid(format!(
                                    "red_flags.{name}.kind must be \"text\" or \"regex\", not \"{other}\""
                                ));
                            }
                        }
                    }
                    ("case_sensitive", toml::Value::Boolean(b)) => p.case_sensitive = *b,
                    ("pattern" | "kind" | "case_sensitive", _) => {
                        return invalid(format!("red_flags.{name}.{k} has the wrong type"));
                    }
                    (other, _) => {
                        return invalid(format!("unknown key '{other}' in red_flags.{name}"));
                    }
                }
            }
            if !have_pattern {
                return invalid(format!("red_flags.{name} needs a pattern"));
            }
        }
        _ => {
            return invalid(format!(
                "red_flags.{name} must be a string or a table with a pattern"
            ));
        }
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[presets]
ipv4 = true
email = false

[red_flags]
customer = "acme-internal"
prod-db  = { kind = "regex", pattern = '\bdb-[0-9]+\.prod\.example-corp\.com\b' }
api-host = { pattern = "api.example-corp.com", case_sensitive = true }
"#;

    #[test]
    fn parses_the_documented_shape() {
        let c = parse(GOOD).unwrap();
        assert_eq!(
            c.presets,
            vec![("email".into(), false), ("ipv4".into(), true)]
        );
        assert_eq!(c.patterns.len(), 3);
        let by = |n: &str| c.patterns.iter().find(|p| p.name == n).unwrap();
        assert_eq!(by("customer").kind, Kind::Text);
        assert!(!by("customer").case_sensitive);
        assert_eq!(by("prod-db").kind, Kind::Regex);
        assert!(by("api-host").case_sensitive);
        assert!(c.patterns.iter().all(|p| !p.preset));
    }

    #[test]
    fn empty_file_is_fine() {
        assert_eq!(parse("").unwrap(), FileConfig::default());
    }

    #[test]
    fn strictness_names_the_key() {
        let err = |t: &str| parse(t).unwrap_err().message().to_string();
        assert!(err("extra = 1").contains("unknown key 'extra'"));
        assert!(err("[presets]\nnope = true").contains("unknown preset 'nope'"));
        assert!(err("[presets]\nemail = 1").contains("presets.email"));
        assert!(
            err("[red_flags]\na = { pattern = \"x\", colour = 1 }")
                .contains("unknown key 'colour'")
        );
        assert!(err("[red_flags]\na = { kind = \"regex\" }").contains("needs a pattern"));
        assert!(err("[red_flags]\na = { pattern = \"x\", kind = \"glob\" }").contains("kind"));
        assert!(err("[red_flags]\na = 3").contains("red_flags.a"));
        assert!(err("[red_flags]\na = { pattern = 1 }").contains("wrong type"));
        assert!(err("not toml [").len() > 3);
        assert_eq!(parse("x = 1").unwrap_err().code(), 2);
    }

    #[test]
    fn missing_file_is_a_setup_error() {
        let e = load(Path::new("/nonexistent/cainary-red-flags.toml")).unwrap_err();
        assert_eq!(e.code(), 1);
    }
}
