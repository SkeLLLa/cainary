//! Built-in red-flag presets. All regex, case-sensitive; `ipv4` is off by default.
//! IPv6 is left out: its regexes match hex-and-colon strings such as timestamps.

use super::{Kind, Pattern};

pub struct Preset {
    pub name: &'static str,
    pub regex: &'static str,
    pub default_on: bool,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "email",
        regex: r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}",
        default_on: true,
    },
    Preset {
        name: "private-key",
        regex: r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----",
        default_on: true,
    },
    Preset {
        name: "jwt",
        regex: r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        default_on: true,
    },
    Preset {
        name: "aws-access-key",
        regex: r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        default_on: true,
    },
    Preset {
        name: "github-token",
        regex: r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})",
        default_on: true,
    },
    Preset {
        name: "anthropic-key",
        regex: r"\bsk-ant-[A-Za-z0-9_-]{20,}",
        default_on: true,
    },
    Preset {
        name: "openai-key",
        regex: r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{32,}",
        default_on: true,
    },
    Preset {
        name: "slack-token",
        regex: r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
        default_on: true,
    },
    Preset {
        name: "ipv4",
        regex: r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        default_on: false,
    },
];

pub fn find(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.name == name)
}

pub fn names() -> impl Iterator<Item = &'static str> {
    PRESETS.iter().map(|p| p.name)
}

impl Preset {
    pub fn pattern(&self) -> Pattern {
        Pattern {
            name: self.name.to_string(),
            kind: Kind::Regex,
            pattern: self.regex.to_string(),
            case_sensitive: true,
            preset: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::Matcher;
    use super::*;

    fn matcher(name: &str) -> Matcher {
        Matcher::new(vec![find(name).unwrap().pattern()]).unwrap()
    }

    fn hit(name: &str, hay: &str) -> bool {
        let mut out = Vec::new();
        matcher(name).scan(hay, &mut out);
        !out.is_empty()
    }

    fn check(name: &str, hits: &[&str], misses: &[&str]) {
        for h in hits {
            assert!(hit(name, h), "{name} should hit {h:?}");
        }
        for m in misses {
            assert!(!hit(name, m), "{name} should not hit {m:?}");
        }
    }

    #[test]
    fn email() {
        check(
            "email",
            &[
                "alice@example-corp.com",
                "git@github.com:org/repo",
                "x a.b+c@d.io y",
            ],
            &["alice@localhost", "a@b.c", "@example.com"],
        );
    }

    #[test]
    fn private_key() {
        check(
            "private-key",
            &[
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
            ],
            &["-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----"],
        );
    }

    #[test]
    fn jwt() {
        let seg = "A".repeat(12);
        check(
            "jwt",
            &[&format!("eyJ{seg}.eyJ{seg}.{seg}")],
            &[&format!("eyJ{seg}"), &format!("eyJ{seg}.eyJ{seg}")],
        );
    }

    #[test]
    fn aws_access_key() {
        check(
            "aws-access-key",
            &["AKIAIOSFODNN7EXAMPLE", "id=ASIAIOSFODNN7EXAMPLE;"],
            &[
                "AKIAIOSFODNN7EXAMPL",
                "akiaiosfodnn7example",
                "AKIAIOSFODNN7EXAMPLEX",
            ],
        );
    }

    #[test]
    fn github_token() {
        let t = |p: &str, n: usize| format!("{p}{}", "a".repeat(n));
        check(
            "github-token",
            &[&t("ghp_", 36), &t("gho_", 40), &t("github_pat_", 22)],
            &[&t("ghp_", 35), &t("ghx_", 36), &t("github_pat_", 21)],
        );
    }

    #[test]
    fn anthropic_key() {
        let t = |n: usize| format!("sk-ant-{}", "a".repeat(n));
        check(
            "anthropic-key",
            &[&t(20), "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"],
            &[&t(19)],
        );
    }

    #[test]
    fn openai_key() {
        let proj = format!("sk-proj-{}", "a".repeat(24));
        let legacy = format!("sk-{}", "a".repeat(48));
        check(
            "openai-key",
            &[&proj, &legacy, &format!("sk-svcacct-{}", "b".repeat(20))],
            &[
                "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
                &format!("sk-{}", "a".repeat(31)),
            ],
        );
    }

    #[test]
    fn slack_token() {
        check(
            "slack-token",
            &["xoxb-1234567890-abc", "xoxp-1234567890"],
            &["xoxz-1234567890-abc", "xoxb-123456789"],
        );
    }

    #[test]
    fn ipv4() {
        check(
            "ipv4",
            &["10.0.0.1", "host 192.168.1.255 up", "255.255.255.255"],
            &["2.1.316", "256.1.1.1", "1.2.3"],
        );
    }

    #[test]
    fn defaults() {
        let on: Vec<_> = PRESETS
            .iter()
            .filter(|p| p.default_on)
            .map(|p| p.name)
            .collect();
        assert_eq!(on.len(), 8);
        assert!(!on.contains(&"ipv4"));
        assert!(PRESETS.iter().all(|p| super::super::valid_name(p.name)));
        Matcher::new(PRESETS.iter().map(Preset::pattern).collect()).unwrap();
    }
}
