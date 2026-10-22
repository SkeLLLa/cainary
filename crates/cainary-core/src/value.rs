//! One value type for every config format (architecture.md §5.1).

use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use plist::stream::{Event, Reader};
use serde_json::{Map, Number};

pub use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    /// JSON with `//` and `/* */` comments and trailing commas.
    Jsonc,
    Toml,
    /// Base64 text that decodes to TOML (Codex `*_toml_base64`).
    TomlBase64,
    /// XML or binary plist.
    Plist,
    /// `KEY=value` lines (`/etc/environment`, pip.conf, go env); `#` comments, optional quotes.
    Env,
    /// The file as one string, for line scans of formats with no parser (NuGet.Config, YAML).
    Text,
}

/// Per-document limits: nesting depth and node count.
#[derive(Debug, Clone)]
pub struct Budget {
    /// Maximum container nesting.
    depth: usize,
    /// Values still allowed.
    nodes: usize,
}

const TOO_DEEP: &str = "not read: nesting is too deep";
const TOO_MANY: &str = "not read: too many values";

impl Budget {
    /// Depth 128, nodes 100_000.
    pub fn new() -> Budget {
        Budget {
            depth: 128,
            nodes: 100_000,
        }
    }

    fn node(&mut self) -> Result<(), String> {
        self.nodes = self.nodes.checked_sub(1).ok_or(TOO_MANY)?;
        Ok(())
    }

    fn level(&self, level: usize) -> Result<(), String> {
        if level > self.depth {
            return Err(TOO_DEEP.into());
        }
        Ok(())
    }

    /// Charge every value of an already-built tree.
    fn charge(&mut self, v: &Value, level: usize) -> Result<(), String> {
        self.node()?;
        match v {
            Value::Array(a) => {
                self.level(level)?;
                a.iter().try_for_each(|x| self.charge(x, level + 1))
            }
            Value::Object(o) => {
                self.level(level)?;
                o.values().try_for_each(|x| self.charge(x, level + 1))
            }
            _ => Ok(()),
        }
    }
}

impl Default for Budget {
    fn default() -> Budget {
        Budget::new()
    }
}

fn cut(mut s: String) -> String {
    if let Some((i, _)) = s.char_indices().nth(120) {
        s.truncate(i);
    }
    s
}

pub fn parse(bytes: &[u8], fmt: Format, b: &mut Budget) -> Result<Value, String> {
    parse_inner(bytes, fmt, b).map_err(cut)
}

fn parse_inner(bytes: &[u8], fmt: Format, b: &mut Budget) -> Result<Value, String> {
    match fmt {
        Format::Json => from_json(strip_bom(bytes), b),
        Format::Jsonc => from_json(&strip_jsonc(strip_bom(bytes)), b),
        Format::Toml => from_toml(bytes, b),
        Format::TomlBase64 => {
            let text = std::str::from_utf8(bytes).map_err(|_| "base64 is not text")?;
            let raw = base64_decode(text).ok_or("invalid base64")?;
            from_toml(&raw, b)
        }
        Format::Plist => from_plist(bytes, b),
        Format::Env => from_env(bytes, b),
        Format::Text => from_text(bytes, b),
    }
}

fn from_env(bytes: &[u8], b: &mut Budget) -> Result<Value, String> {
    let text = std::str::from_utf8(strip_bom(bytes)).map_err(|_| "environment file is not text")?;
    let mut map = serde_json::Map::new();
    for line in text.lines().map(str::trim) {
        let line = line.strip_prefix("export ").unwrap_or(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(v);
        map.insert(k.trim().to_string(), Value::String(v.to_string()));
    }
    let v = Value::Object(map);
    b.charge(&v, 1)?;
    Ok(v)
}

fn from_text(bytes: &[u8], b: &mut Budget) -> Result<Value, String> {
    let text = std::str::from_utf8(strip_bom(bytes)).map_err(|_| "file is not text")?;
    let v = Value::String(text.to_string());
    b.charge(&v, 1)?;
    Ok(v)
}

fn strip_bom(b: &[u8]) -> &[u8] {
    b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(b)
}

fn from_json(bytes: &[u8], b: &mut Budget) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON: {e}"))?;
    b.charge(&v, 1)?;
    Ok(v)
}

/// Remove `//` and `/* */` comments and trailing commas that sit outside strings.
fn strip_jsonc(src: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    let mut comma: Option<usize> = None;
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        match c {
            b'"' => {
                comma = None;
                out.push(c);
                i += 1;
                while i < src.len() {
                    out.push(src[i]);
                    match src[i] {
                        b'\\' if i + 1 < src.len() => {
                            out.push(src[i + 1]);
                            i += 1;
                        }
                        b'"' => break,
                        _ => {}
                    }
                    i += 1;
                }
            }
            b'/' if src.get(i + 1) == Some(&b'/') => {
                while i < src.len() && src[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if src.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < src.len() && !src[i..].starts_with(b"*/") {
                    i += 1;
                }
                i += 1;
                out.push(b' ');
            }
            b',' => {
                comma = Some(out.len());
                out.push(c);
            }
            b'}' | b']' => {
                if let Some(p) = comma.take() {
                    out[p] = b' ';
                }
                out.push(c);
            }
            _ => {
                if !c.is_ascii_whitespace() {
                    comma = None;
                }
                out.push(c);
            }
        }
        i += 1;
    }
    out
}

fn from_toml(bytes: &[u8], b: &mut Budget) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "TOML is not UTF-8")?;
    let t: toml::Value = toml::from_str(text).map_err(|e| format!("invalid TOML: {e}"))?;
    let v = toml_value(t, 1, b)?;
    Ok(v)
}

fn toml_value(t: toml::Value, level: usize, b: &mut Budget) -> Result<Value, String> {
    b.node()?;
    Ok(match t {
        toml::Value::String(s) => Value::String(s),
        toml::Value::Integer(i) => Value::from(i),
        toml::Value::Float(f) => {
            Number::from_f64(f).map_or_else(|| Value::String(f.to_string()), Value::Number)
        }
        toml::Value::Boolean(x) => Value::Bool(x),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(a) => {
            b.level(level)?;
            Value::Array(
                a.into_iter()
                    .map(|x| toml_value(x, level + 1, b))
                    .collect::<Result<_, _>>()?,
            )
        }
        toml::Value::Table(t) => {
            b.level(level)?;
            let mut m = Map::new();
            for (k, x) in t {
                m.insert(k, toml_value(x, level + 1, b)?);
            }
            Value::Object(m)
        }
    })
}

enum Frame {
    Arr(Vec<Value>),
    Obj(Map<String, Value>, Option<String>),
}

fn from_plist(bytes: &[u8], b: &mut Budget) -> Result<Value, String> {
    // The plist reader also accepts the old ASCII format; only XML and binary are supported.
    let head = strip_bom(bytes).trim_ascii_start();
    if !(head.starts_with(b"bplist") || head.starts_with(b"<")) {
        return Err("not an XML or binary plist".into());
    }
    // The reader does not notice a missing closing tag, so check the XML document end here.
    if head.starts_with(b"<") && !head.trim_ascii_end().ends_with(b"</plist>") {
        return Err("invalid plist: missing </plist>".into());
    }
    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<Value> = None;
    for ev in Reader::new(Cursor::new(bytes)) {
        let ev = ev.map_err(|e| format!("invalid plist: {e}"))?;
        if root.is_some() {
            return Err("invalid plist: content after the root value".into());
        }
        let v = match ev {
            Event::StartArray(_) | Event::StartDictionary(_) => {
                b.node()?;
                b.level(stack.len() + 1)?;
                stack.push(if matches!(ev, Event::StartArray(_)) {
                    Frame::Arr(Vec::new())
                } else {
                    Frame::Obj(Map::new(), None)
                });
                continue;
            }
            Event::EndCollection => match stack.pop() {
                Some(Frame::Arr(a)) => Value::Array(a),
                Some(Frame::Obj(m, None)) => Value::Object(m),
                Some(Frame::Obj(_, Some(_))) => {
                    return Err("invalid plist: dictionary key without a value".into());
                }
                None => return Err("invalid plist: unbalanced end".into()),
            },
            Event::String(s) => {
                if let Some(Frame::Obj(_, key @ None)) = stack.last_mut() {
                    *key = Some(s.into_owned());
                    continue;
                }
                b.node()?;
                Value::String(s.into_owned())
            }
            other => {
                b.node()?;
                scalar(other)
            }
        };
        match stack.last_mut() {
            Some(Frame::Arr(a)) => a.push(v),
            Some(Frame::Obj(m, key)) => {
                let k = key
                    .take()
                    .ok_or("invalid plist: dictionary key is not a string")?;
                m.insert(k, v);
            }
            None => {
                root = Some(v);
            }
        }
    }
    root.ok_or_else(|| "invalid plist: empty".into())
}

fn scalar(ev: Event<'_>) -> Value {
    match ev {
        Event::Boolean(x) => Value::Bool(x),
        Event::Data(d) => Value::String(format!("<data {} bytes>", d.len())),
        Event::Date(d) => Value::String(d.to_xml_format()),
        Event::Integer(i) => match (i.as_signed(), i.as_unsigned()) {
            (Some(s), _) => Value::from(s),
            (None, Some(u)) => Value::from(u),
            _ => Value::Null,
        },
        Event::Real(f) => Number::from_f64(f).map_or(Value::Null, Value::Number),
        Event::Uid(u) => Value::from(u.get()),
        _ => Value::Null,
    }
}

/// A string that starts with `{` or `[` and parses as JSON is decoded (charging `b`); anything
/// else is cloned.
pub fn str_or_json(v: &Value, b: &mut Budget) -> Result<Value, String> {
    if let Value::String(s) = v {
        let t = s.trim_start();
        if t.starts_with(['{', '[']) {
            match serde_json::from_str::<Value>(t) {
                Ok(inner) => {
                    b.charge(&inner, 1).map_err(cut)?;
                    return Ok(inner);
                }
                Err(e) if e.to_string().starts_with("recursion limit exceeded") => {
                    return Err("nested JSON string is too deep".into());
                }
                Err(_) => {}
            }
        }
    }
    Ok(v.clone())
}

/// Dotted-path lookup (`a.b.c`); also matches a literal dotted key such as `"a.b"`.
pub fn get<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(x) = child(v, path) {
        return Some(x);
    }
    path.match_indices('.')
        .find_map(|(i, _)| child(v, &path[..i]).and_then(|c| get(c, &path[i + 1..])))
}

fn child<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m.get(key),
        Value::Array(a) => key.parse::<usize>().ok().and_then(|i| a.get(i)),
        _ => None,
    }
}

/// `1/true/yes/on` (case-insensitive), a bool, or the number 1.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(x) => *x,
        Value::Number(n) => n.as_f64() == Some(1.0),
        Value::String(s) => {
            let s = s.trim();
            ["1", "true", "yes", "on"]
                .iter()
                .any(|w| s.eq_ignore_ascii_case(w))
        }
        _ => false,
    }
}

/// Standard alphabet, padding optional, whitespace skipped.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits, mut padded) = (0u32, 0u32, false);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        let n = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padded = true;
                continue;
            }
            _ => return None,
        };
        if padded {
            return None;
        }
        acc = (acc << 6) | u32::from(n);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // A lone leftover sextet (6 bits) can't encode a byte.
    (bits < 6).then_some(out)
}

/// UTC, whole seconds: `2026-10-21T12:00:00Z`.
pub fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Days since 1970-01-01 → civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    fn p(s: &str, f: Format) -> Result<Value, String> {
        parse(s.as_bytes(), f, &mut Budget::new())
    }

    #[test]
    fn json() {
        assert_eq!(
            p(r#"{"a":[1,true,null]}"#, Format::Json).unwrap(),
            json!({"a":[1,true,null]})
        );
        assert_eq!(
            p("\u{feff}{\"a\":1}", Format::Json).unwrap(),
            json!({"a":1})
        );
        assert!(p("{\"a\":", Format::Json).is_err());
        assert!(p("", Format::Json).is_err());
    }

    #[test]
    fn json_keeps_key_order() {
        let v = p(r#"{"z":1,"a":2,"m":3}"#, Format::Json).unwrap();
        let keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["z", "a", "m"]);
    }

    #[test]
    fn jsonc() {
        let src = "{\n // line\n \"url\": \"http://x//y\", /* block */ \"a\": [1, 2,], \"s\": \"/*not*/ , ]\",\n}\n";
        assert_eq!(
            p(src, Format::Jsonc).unwrap(),
            json!({"url":"http://x//y","a":[1,2],"s":"/*not*/ , ]"})
        );
        assert_eq!(
            p(r#"{"q":"a\"//b"} // end"#, Format::Jsonc).unwrap(),
            json!({"q":"a\"//b"})
        );
        assert_eq!(p("[1,\n// c\n]", Format::Jsonc).unwrap(), json!([1]));
        assert!(p("{\"a\": /* open", Format::Jsonc).is_err());
    }

    #[test]
    fn toml_values() {
        let v = p(
            "a = 1\nf = 1.5\nb = true\nd = 2026-01-01T00:00:00Z\n[t]\nx = [\"y\"]\n",
            Format::Toml,
        )
        .unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["f"], 1.5);
        assert_eq!(v["b"], true);
        assert_eq!(v["d"], "2026-01-01T00:00:00Z");
        assert_eq!(v["t"]["x"], json!(["y"]));
        assert!(p("a = ", Format::Toml).is_err());
    }

    #[test]
    fn toml_base64() {
        let v = p("YSA9IDEK\n", Format::TomlBase64).unwrap(); // "a = 1\n"
        assert_eq!(v, json!({"a":1}));
        assert!(p("!!!", Format::TomlBase64).is_err());
        assert!(p("YSA9", Format::TomlBase64).is_err()); // "a =" is not TOML
    }

    #[test]
    fn env_lines() {
        let src = "# proxy\nhttp_proxy=http://proxy.example-corp.com:3128\nexport HTTPS_PROXY=\"https://p.example-corp.com\"\nPATH='/usr/bin'\nnoise\n";
        let v = p(src, Format::Env).unwrap();
        assert_eq!(
            v,
            json!({"http_proxy":"http://proxy.example-corp.com:3128","HTTPS_PROXY":"https://p.example-corp.com","PATH":"/usr/bin"})
        );
    }

    #[test]
    fn toml_error_is_cut() {
        let long = format!("a = \"{}\" junk", "x".repeat(400));
        let e = p(&long, Format::Toml).unwrap_err();
        assert!(e.chars().count() <= 120, "{}", e.len());
    }

    #[test]
    fn plist_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Name</key><string>AcmeCollector</string>
<key>On</key><true/><key>N</key><integer>-3</integer><key>R</key><real>1.5</real>
<key>When</key><date>2026-01-02T03:04:05Z</date>
<key>Blob</key><data>AAEC</data>
<key>List</key><array><string>a</string><dict><key>k</key><string>v</string></dict></array>
</dict></plist>"#;
        let v = p(xml, Format::Plist).unwrap();
        assert_eq!(v["Name"], "AcmeCollector");
        assert_eq!(v["On"], true);
        assert_eq!(v["N"], -3);
        assert_eq!(v["R"], 1.5);
        assert_eq!(v["When"], "2026-01-02T03:04:05Z");
        assert_eq!(v["Blob"], "<data 3 bytes>");
        assert_eq!(v["List"][1]["k"], "v");
        assert!(p("<plist><dict><key>a</key>", Format::Plist).is_err());
        for bad in [
            "<plist><dict><key>a</key></dict></plist>",
            "<plist><dict></dict>",
            "<plist><dict></dict><broken></plist>",
        ] {
            assert!(p(bad, Format::Plist).is_err(), "{bad}");
        }
        assert!(p("not a plist", Format::Plist).is_err());
    }

    #[test]
    fn plist_binary() {
        let mut d = plist::Dictionary::new();
        d.insert("k".into(), plist::Value::String("v".into()));
        d.insert("n".into(), plist::Value::Integer(7.into()));
        d.insert(
            "a".into(),
            plist::Value::Array(vec![plist::Value::Boolean(true)]),
        );
        let mut buf = Vec::new();
        plist::to_writer_binary(&mut buf, &plist::Value::Dictionary(d)).unwrap();
        assert!(buf.starts_with(b"bplist00"));
        let v = parse(&buf, Format::Plist, &mut Budget::new()).unwrap();
        assert_eq!(v, json!({"k":"v","n":7,"a":[true]}));
        assert!(parse(&buf[..buf.len() - 5], Format::Plist, &mut Budget::new()).is_err());
    }

    /// Objects: 0 = parent array of 1000 refs to 1; 1 = array of 200 refs to 2; 2 = int 0.
    fn amplified_bplist() -> Vec<u8> {
        let array = |n: u16, target: u16| {
            let mut o = vec![0xAF, 0x11];
            o.extend(n.to_be_bytes());
            for _ in 0..n {
                o.extend(target.to_be_bytes());
            }
            o
        };
        let mut out = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for obj in [array(1000, 1), array(200, 2), vec![0x10, 0x00]] {
            offsets.push(out.len() as u16);
            out.extend(obj);
        }
        let table = out.len() as u64;
        offsets.iter().for_each(|o| out.extend(o.to_be_bytes()));
        out.extend([0; 6]);
        out.extend([2, 2]); // offset size, object-ref size
        out.extend(3u64.to_be_bytes());
        out.extend(0u64.to_be_bytes());
        out.extend(table.to_be_bytes());
        out
    }

    #[test]
    fn plist_shared_container_is_capped() {
        let e = parse(&amplified_bplist(), Format::Plist, &mut Budget::new()).unwrap_err();
        assert!(e.contains("too many values"), "{e}");
    }

    #[test]
    fn plist_depth() {
        let xml = format!(
            "<plist>{}<string>x</string>{}</plist>",
            "<array>".repeat(200),
            "</array>".repeat(200)
        );
        assert!(p(&xml, Format::Plist).is_err());
    }

    #[test]
    fn json_depth_200_is_rejected() {
        let s = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        assert!(p(&s, Format::Json).is_err());
        assert!(p(&s, Format::Jsonc).is_err());
    }

    #[test]
    fn depth_budget_applies_below_serde_limit() {
        let mut b = Budget::new();
        b.depth = 10;
        let s = format!("{}1{}", "[".repeat(20), "]".repeat(20));
        assert!(
            parse(s.as_bytes(), Format::Json, &mut b)
                .unwrap_err()
                .contains("too deep")
        );
        let t = toml_nested(20);
        assert!(
            parse(t.as_bytes(), Format::Toml, &mut b)
                .unwrap_err()
                .contains("too deep")
        );
    }

    fn toml_nested(n: usize) -> String {
        format!("a = {}1{}", "[".repeat(n), "]".repeat(n))
    }

    #[test]
    fn node_budget_is_shared_across_calls() {
        let mut b = Budget::new();
        b.nodes = 5;
        let s = Value::String("[1,2,3]".into()); // 4 nodes
        assert_eq!(str_or_json(&s, &mut b).unwrap(), json!([1, 2, 3]));
        let e = str_or_json(&s, &mut b).unwrap_err();
        assert!(e.contains("too many values"), "{e}");
    }

    #[test]
    fn str_or_json_cases() {
        let mut b = Budget::new();
        assert_eq!(
            str_or_json(&json!(" {\"a\":1}"), &mut b).unwrap(),
            json!({"a":1})
        );
        assert_eq!(
            str_or_json(&json!("plain"), &mut b).unwrap(),
            json!("plain")
        );
        assert_eq!(
            str_or_json(&json!("[oops"), &mut b).unwrap(),
            json!("[oops")
        );
        assert_eq!(str_or_json(&json!(3), &mut b).unwrap(), json!(3));
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        assert!(str_or_json(&json!(deep), &mut b).is_err());
    }

    #[test]
    fn get_paths() {
        let v = json!({"a":{"b":{"c":1}},"x.y":2,"m.n":{"o":3},"l":[{"k":4}],"a.b":5});
        assert_eq!(get(&v, "a.b.c"), Some(&json!(1)));
        assert_eq!(get(&v, "x.y"), Some(&json!(2)));
        assert_eq!(get(&v, "m.n.o"), Some(&json!(3)));
        assert_eq!(get(&v, "a.b"), Some(&json!(5))); // literal wins
        assert_eq!(get(&v, "l.0.k"), Some(&json!(4)));
        assert_eq!(get(&v, "a.z"), None);
        assert_eq!(get(&json!(1), "a"), None);
        assert_eq!(get(&v, ""), None);
    }

    #[test]
    fn truthy_values() {
        for t in [
            json!(true),
            json!(1),
            json!("1"),
            json!("TRUE"),
            json!(" Yes "),
            json!("on"),
        ] {
            assert!(truthy(&t), "{t}");
        }
        for f in [
            json!(false),
            json!(0),
            json!(2),
            json!("0"),
            json!("off"),
            json!(""),
            json!(null),
            json!([]),
        ] {
            assert!(!truthy(&f), "{f}");
        }
    }

    #[test]
    fn base64() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVs\nbG8 =").unwrap(), b"hello");
        assert_eq!(base64_decode("+/8=").unwrap(), [0xFB, 0xFF]);
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("a").is_none());
        assert!(base64_decode("aG-s").is_none());
        assert!(base64_decode("aG=s").is_none());
    }

    #[test]
    fn rfc3339_formats() {
        let at = |s| UNIX_EPOCH + Duration::from_secs(s);
        assert_eq!(rfc3339(at(0)), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(at(1_782_043_200)), "2026-06-21T12:00:00Z");
        assert_eq!(rfc3339(at(1_803_902_399)), "2027-03-01T11:59:59Z");
        assert_eq!(rfc3339(at(951_782_400)), "2000-02-29T00:00:00Z");
    }
}
