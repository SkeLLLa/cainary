//! Mask secret-looking values; display paths (architecture.md §5.2).
//!
//! Minimal by design: obvious secrets only, no entropy scoring, no allowlist renderer.

use crate::value::Value;

const REDACTED: &str = "<redacted>";
const SECRET_PARTS: [&str; 9] = [
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "api-key",
    "authorization",
    "cookie",
];
const KEY_PARTS: [&str; 2] = ["credential", "private"];
/// Token prefixes (`?` matches one letter, as in `xoxb-`); a hit needs `MIN_REST` more token chars.
const PREFIXES: [&str; 10] = [
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "xox?-",
    "glpat-",
    "AKIA",
    "AIza",
    "eyJ",
];
const MIN_REST: usize = 6;

fn is_header_key(k: &str) -> bool {
    k.to_ascii_lowercase().ends_with("headers") && !is_exception(k)
}

fn is_exception(k: &str) -> bool {
    [
        "apikeyhelper",
        "otelheadershelper",
        "max_tokens",
        "max-tokens",
    ]
    .iter()
    .any(|e| k.eq_ignore_ascii_case(e))
}

/// Does a (case-insensitive) key name a secret? Helper-command keys are exceptions.
pub fn is_secret_key(k: &str) -> bool {
    if is_exception(k) {
        return false;
    }
    let k = k.to_ascii_lowercase();
    SECRET_PARTS.iter().chain(&KEY_PARTS).any(|p| k.contains(p))
        || k.ends_with("headers")
        || k.ends_with("_key")
}

/// Render a config value for an evidence line: `<redacted>` for secret keys, names only for
/// header maps, URLs through [`url`], otherwise compact text.
pub fn value(key: &str, v: &Value) -> String {
    match sanitize(key, v) {
        Value::String(s) => s,
        other => other.to_string(),
    }
}

fn sanitize(key: &str, v: &Value) -> Value {
    if is_header_key(key) {
        return Value::String(header_names(v).join(", "));
    }
    if is_secret_key(key) {
        return Value::String(REDACTED.into());
    }
    match v {
        Value::String(s) if s.contains("://") => Value::String(text(&url(s))),
        Value::String(s) => Value::String(text(s)),
        Value::Array(a) => Value::Array(a.iter().map(|x| sanitize(key, x)).collect()),
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, x)| (k.clone(), sanitize(k, x))).collect())
        }
        other => other.clone(),
    }
}

/// `(scheme://, authority without userinfo, path)`.
fn url_parts(s: &str) -> (&str, &str, &str) {
    let (scheme, rest) = s.find("://").map_or(("", s), |i| s.split_at(i + 3));
    let rest = &rest[..rest.find(['?', '#']).unwrap_or(rest.len())];
    let (auth, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    (scheme, auth.rsplit('@').next().unwrap_or(auth), path)
}

/// Keep scheme, host, port and path; drop userinfo, query and fragment.
pub fn url(s: &str) -> String {
    let (scheme, auth, path) = url_parts(s);
    format!("{scheme}{auth}{path}")
}

/// The host of a URL, if it has one.
pub fn url_host(s: &str) -> Option<String> {
    let (scheme, auth, _) = url_parts(s);
    if scheme.is_empty() {
        return None;
    }
    let host = match auth.strip_prefix('[') {
        Some(r) => r.split(']').next().unwrap_or(r),
        None => match auth.rsplit_once(':') {
            Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => auth,
        },
    };
    (!host.is_empty()).then(|| host.to_string())
}

fn is_quote(c: char) -> bool {
    matches!(c, '\'' | '"')
}

fn is_scheme(w: &str) -> bool {
    ["Bearer", "Basic"]
        .iter()
        .any(|s| w.eq_ignore_ascii_case(s))
}

/// Replace the part of `word` between its quotes/trailing punctuation.
fn mask_word(word: &str) -> String {
    let core = word
        .trim_start_matches(is_quote)
        .trim_end_matches(|c| is_quote(c) || c == ';');
    let lead = &word[..word.len() - word.trim_start_matches(is_quote).len()];
    let tail = &word[lead.len() + core.len()..];
    format!("{lead}{REDACTED}{tail}")
}

/// Mask bearer tokens, secret flags, secret `NAME=value` pairs and well-known token prefixes.
pub fn command(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut mask_next = false;
    let mut quote: Option<char> = None; // an open `-H '…'` header whose words are all masked
    let mut rest = s;
    while !rest.is_empty() {
        let ws = rest.starts_with(char::is_whitespace);
        let n = rest
            .find(|c: char| c.is_whitespace() != ws)
            .unwrap_or(rest.len());
        let (w, tail) = rest.split_at(n);
        rest = tail;
        if ws {
            out.push_str(w);
            continue;
        }
        if mask_next && is_scheme(w.trim_matches(is_quote)) {
            out.push_str(w);
            continue;
        }
        let name = w.trim_start_matches(|c: char| c == '-' || is_quote(c));
        if mask_next || quote.is_some() {
            out.push_str(&mask_word(w));
            mask_next = false;
            if quote.is_some_and(|q| w.ends_with(q)) {
                quote = None;
            }
        } else if is_scheme(w) {
            out.push_str(w);
            mask_next = true;
        } else if let Some((k, _)) = name.split_once('=').filter(|(k, _)| is_secret_key(k)) {
            out.push_str(&w[..w.len() - name.len() + k.len() + 1]);
            out.push_str(&mask_word(&w[w.len() - name.len() + k.len() + 1..]));
        } else if w.starts_with('-') && is_secret_key(name) {
            out.push_str(w);
            mask_next = !tail.trim_start().starts_with("--");
        } else if let Some(k) = name.strip_suffix(':').filter(|k| is_secret_key(k)) {
            out.push_str(w);
            mask_next = true;
            quote = w.chars().next().filter(|c| is_quote(*c));
            debug_assert!(!k.is_empty());
        } else if w.contains("://") {
            let core = w.trim_matches(is_quote);
            out.push_str(&w.replace(core, &url(core)));
        } else {
            out.push_str(w);
        }
    }
    text(&out)
}

/// `$HOME` → `~`, control characters → `?`.
pub fn display_path(p: &str, home: &str) -> String {
    let home = home.trim_end_matches('/');
    let shown = match p.strip_prefix(home) {
        Some(r) if !home.is_empty() && (r.is_empty() || r.starts_with('/')) => format!("~{r}"),
        _ => p.to_string(),
    };
    shown
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn prefix_len(s: &[u8]) -> Option<usize> {
    PREFIXES.iter().find_map(|p| {
        let ok = s.len() >= p.len()
            && p.bytes().zip(s).all(|(a, b)| {
                if a == b'?' {
                    b.is_ascii_alphabetic()
                } else {
                    a == *b
                }
            });
        ok.then_some(p.len())
    })
}

/// The final net: control characters and well-known token prefixes.
pub fn text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_alnum = false;
    let mut skip = 0;
    for (i, c) in s.char_indices() {
        if i < skip {
            continue;
        }
        if !prev_alnum && let Some(p) = prefix_len(&s.as_bytes()[i..]) {
            let rest = s[i + p..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || "_-.".contains(c)))
                .unwrap_or(s.len() - i - p);
            if rest >= MIN_REST {
                out.push_str(REDACTED);
                skip = i + p + rest;
                prev_alnum = true;
                continue;
            }
        }
        prev_alnum = c.is_ascii_alphanumeric();
        out.push(if c.is_control() { '?' } else { c });
    }
    out
}

/// Header names only, from a map or from a `k=v,k2=v2` string.
pub fn header_names(v: &Value) -> Vec<String> {
    let names: Vec<String> = match v {
        Value::Object(o) => o.keys().cloned().collect(),
        Value::String(s) => s
            .split(',')
            .filter_map(|kv| kv.split_once('=').map(|(k, _)| k.trim().to_string()))
            .collect(),
        _ => Vec::new(),
    };
    names
        .into_iter()
        .filter(|n| !n.is_empty())
        .map(|n| text(&n))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRETS: [&str; 6] = [
        "sk-test-EXAMPLE",
        "ghp_EXAMPLE0123456789",
        "hunter2EXAMPLE",
        "AKIAEXAMPLE012345678",
        "eyJhbGciOi.EXAMPLE.sig",
        "alice-pw",
    ];

    fn clean(out: &str) {
        for s in SECRETS {
            assert!(!out.contains(s), "{s} leaked in {out}");
        }
    }

    #[test]
    fn secret_keys() {
        for k in [
            "token",
            "OTEL_API_TOKEN",
            "client_secret",
            "Password",
            "passwd",
            "apiKey",
            "api_key",
            "x-api-key",
            "Authorization",
            "Cookie",
            "credentials",
            "private_key",
            "OTLP_HEADERS",
            "http_headers",
            "signing_key",
            "AUTH_TOKEN",
        ] {
            assert!(is_secret_key(k), "{k}");
        }
        for k in [
            "apiKeyHelper",
            "otelHeadersHelper",
            "APIKEYHELPER",
            "max_tokens",
            "endpoint",
            "model",
            "keyboard",
        ] {
            assert!(!is_secret_key(k), "{k}");
        }
    }

    #[test]
    fn values() {
        assert_eq!(value("api_key", &json!("sk-test-EXAMPLE")), "<redacted>");
        assert_eq!(
            value("apiKeyHelper", &json!("/bin/get-key")),
            "/bin/get-key"
        );
        assert_eq!(value("max_tokens", &json!(4096)), "4096");
        assert_eq!(
            value(
                "endpoint",
                &json!("https://alice:pw@otel.example-corp.com:4318/v1?k=1#f")
            ),
            "https://otel.example-corp.com:4318/v1"
        );
        assert_eq!(value("on", &json!(true)), "true");
        assert_eq!(value("x", &json!("a\u{1b}[31m")), "a?[31m");
        let nested = value(
            "env",
            &json!({"A_TOKEN": "sk-test-EXAMPLE", "N": 1, "list": ["ghp_EXAMPLE0123456789"]}),
        );
        clean(&nested);
        assert!(nested.contains("<redacted>") && nested.contains("\"N\":1"));
    }

    #[test]
    fn header_string_fragments_without_equals_are_dropped() {
        let v = json!("Authorization=Bearer synthetic,credential-fragment");
        assert_eq!(header_names(&v), ["Authorization"]);
        assert_eq!(value("headers", &v), "Authorization");
    }

    #[test]
    fn header_maps_show_names_only() {
        let m = json!({"Authorization": "Bearer sk-test-EXAMPLE", "X-Org": "alice-pw"});
        assert_eq!(header_names(&m), ["Authorization", "X-Org"]);
        assert_eq!(
            header_names(&json!("api-key=sk-test-EXAMPLE, x-team = alice-pw,")),
            ["api-key", "x-team"]
        );
        assert!(header_names(&json!(3)).is_empty());
        for key in ["OTEL_EXPORTER_OTLP_HEADERS", "headers", "http_headers"] {
            let out = value(key, &m);
            assert_eq!(out, "Authorization, X-Org");
            clean(&out);
        }
        assert_eq!(
            value(
                "OTEL_EXPORTER_OTLP_HEADERS",
                &json!("api-key=sk-test-EXAMPLE")
            ),
            "api-key"
        );
    }

    #[test]
    fn urls() {
        assert_eq!(
            url("https://u:alice-pw@h.example-corp.com:8443/a/b?token=hunter2EXAMPLE#frag"),
            "https://h.example-corp.com:8443/a/b"
        );
        assert_eq!(
            url("http://h.example-corp.com"),
            "http://h.example-corp.com"
        );
        assert_eq!(
            url("h.example-corp.com:4317?x=1"),
            "h.example-corp.com:4317"
        );
        assert_eq!(
            url_host("https://u:p@Otel.example-corp.com:4318/v1?q=1").as_deref(),
            Some("Otel.example-corp.com")
        );
        assert_eq!(url_host("http://[::1]:8080/x").as_deref(), Some("::1"));
        assert_eq!(
            url_host("https://h.example-corp.com#f").as_deref(),
            Some("h.example-corp.com")
        );
        assert_eq!(url_host("not a url"), None);
        assert_eq!(url_host("https:///path"), None);
    }

    #[test]
    fn commands() {
        let cases = [
            "curl -H 'Authorization: Bearer sk-test-EXAMPLE' https://h.example-corp.com",
            "curl -H \"Authorization: Basic hunter2EXAMPLE\" x",
            "curl --header 'Cookie: s=alice-pw; t=hunter2EXAMPLE' x",
            "run --token hunter2EXAMPLE --verbose",
            "run --token=hunter2EXAMPLE",
            "run --api-key sk-test-EXAMPLE",
            "run --password=alice-pw",
            "API_TOKEN=hunter2EXAMPLE run",
            "env DB_PASSWORD='alice-pw' run",
            "echo Bearer eyJhbGciOi.EXAMPLE.sig",
            "echo ghp_EXAMPLE0123456789 AKIAEXAMPLE012345678",
            "run --flag=sk-test-EXAMPLE",
        ];
        for c in cases {
            let out = command(c);
            clean(&out);
            assert!(out.contains("<redacted>"), "{c} -> {out}");
        }
        assert_eq!(
            command("curl -H 'Authorization: Bearer sk-test-EXAMPLE' -X POST"),
            "curl -H 'Authorization: Bearer <redacted>' -X POST"
        );
        assert_eq!(
            command("run --token x --verbose"),
            "run --token <redacted> --verbose"
        );
        assert_eq!(command("run --token=x"), "run --token=<redacted>");
        assert_eq!(command("run --token --verbose"), "run --token --verbose");
        assert_eq!(command("A_TOKEN=x run"), "A_TOKEN=<redacted> run");
        assert_eq!(
            command("curl 'https://a:b@h.example-corp.com/p?q=1'"),
            "curl 'https://h.example-corp.com/p'"
        );
        assert_eq!(
            command("run --max-tokens 100 --model x"),
            "run --max-tokens 100 --model x"
        );
        assert_eq!(
            command("/usr/bin/acme-hook --verbose  now"),
            "/usr/bin/acme-hook --verbose  now"
        );
        assert_eq!(command(""), "");
    }

    #[test]
    fn token_prefixes() {
        for t in [
            "sk-test-EXAMPLE",
            "ghp_EXAMPLE0123456789",
            "gho_EXAMPLE0123456789",
            "ghs_EXAMPLE0123456789",
            "github_pat_EXAMPLE0123456789",
            "xoxb-EXAMPLE-0123",
            "xoxp-EXAMPLE-0123",
            "glpat-EXAMPLE0123456789",
            "AKIAEXAMPLE012345678",
            "AIzaEXAMPLE0123456789",
            "eyJhbGciOi.EXAMPLE.sig",
        ] {
            let out = text(&format!("key {t}, next"));
            assert_eq!(out, "key <redacted>, next", "{t}");
        }
        assert_eq!(text("key=sk-test-EXAMPLE"), "key=<redacted>");
        assert_eq!(
            text("task-1 risk-assessment skeleton"),
            "task-1 risk-assessment skeleton"
        );
        assert_eq!(text("sk-x"), "sk-x");
        assert_eq!(text("a\nb\u{7}"), "a?b?");
        assert_eq!(text("héllo ünï"), "héllo ünï");
    }

    #[test]
    fn display_paths() {
        assert_eq!(
            display_path("/Users/alice/.claude/settings.json", "/Users/alice"),
            "~/.claude/settings.json"
        );
        assert_eq!(display_path("/Users/alice", "/Users/alice/"), "~");
        assert_eq!(
            display_path("/Users/alice2/x", "/Users/alice"),
            "/Users/alice2/x"
        );
        assert_eq!(display_path("/etc/codex/a", ""), "/etc/codex/a");
        assert_eq!(
            display_path("/Users/alice/a\nb\u{1b}[0m", "/Users/alice"),
            "~/a?b?[0m"
        );
    }
}
