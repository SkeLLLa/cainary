//! A lossless, targeted editor for one member of a JSON settings file.
//!
//! `trust` must change `env.NODE_EXTRA_CA_CERTS` and nothing else, so it can't round-trip the
//! document through a value tree (integers past 64 bits, precise decimals and duplicate members
//! don't survive that). This scans the text strictly (RFC 8259, depth ≤ 64, size ≤ 1 MiB, no
//! comments, no duplicate member names at any level), remembers where each member of the top-level
//! object and of its `env` object sit, and splices only the bytes of the member it edits. Every
//! other byte of the file stays identical. Pure: no I/O.

use std::collections::HashSet;

pub const MAX_BYTES: usize = 1 << 20;
pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditError {
    /// Not strict JSON.
    Syntax,
    /// A member name appears twice in one object (somewhere in the document).
    Duplicate,
    TooDeep,
    TooBig,
    /// The document's root isn't an object.
    NotObject,
    /// `env` is there but isn't an object.
    EnvNotObject,
    /// The target member is there but isn't a string.
    NotString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Object,
    Array,
    String,
    Other,
}

#[derive(Debug, Clone)]
struct Member {
    key: String,
    /// Where the member's text starts (its key's opening quote) and where its value ends.
    start: usize,
    value_start: usize,
    end: usize,
    kind: Kind,
    /// For an object value: its members, and where its `{` and `}` are.
    object: Option<Obj>,
}

#[derive(Debug, Clone)]
struct Obj {
    open: usize,
    close: usize,
    members: Vec<Member>,
}

pub struct Doc<'a> {
    text: &'a str,
    root: Obj,
}

struct Scanner<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
}

impl Scanner<'_> {
    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), EditError> {
        if self.s.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err(EditError::Syntax)
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), EditError> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(())
        } else {
            Err(EditError::Syntax)
        }
    }

    fn hex4(&mut self) -> Result<u32, EditError> {
        let h = self.s.get(self.i..self.i + 4).ok_or(EditError::Syntax)?;
        let t = std::str::from_utf8(h).map_err(|_| EditError::Syntax)?;
        if !t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(EditError::Syntax);
        }
        self.i += 4;
        u32::from_str_radix(t, 16).map_err(|_| EditError::Syntax)
    }

    /// A string token: returns its decoded text. Control characters and bad escapes are errors;
    /// a lone surrogate is an error too (it can't be text).
    fn string(&mut self) -> Result<String, EditError> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(&b) = self.s.get(self.i) {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.i += 1;
            }
            out.push_str(&self.text[start..self.i]);
            match self.s.get(self.i) {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let c = *self.s.get(self.i).ok_or(EditError::Syntax)?;
                    self.i += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xd800..0xdc00).contains(&hi) {
                                self.literal("\\u")?;
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return Err(EditError::Syntax);
                                }
                                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            } else if (0xdc00..0xe000).contains(&hi) {
                                return Err(EditError::Syntax);
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or(EditError::Syntax)?);
                        }
                        _ => return Err(EditError::Syntax),
                    }
                }
                _ => return Err(EditError::Syntax),
            }
        }
    }

    fn number(&mut self) -> Result<(), EditError> {
        let at = |s: &Self| s.s.get(s.i).copied();
        if at(self) == Some(b'-') {
            self.i += 1;
        }
        match at(self) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while at(self).is_some_and(|b| b.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            _ => return Err(EditError::Syntax),
        }
        if at(self) == Some(b'.') {
            self.i += 1;
            if !at(self).is_some_and(|b| b.is_ascii_digit()) {
                return Err(EditError::Syntax);
            }
            while at(self).is_some_and(|b| b.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(at(self), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(at(self), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !at(self).is_some_and(|b| b.is_ascii_digit()) {
                return Err(EditError::Syntax);
            }
            while at(self).is_some_and(|b| b.is_ascii_digit()) {
                self.i += 1;
            }
        }
        Ok(())
    }

    /// One value; `depth` is the nesting of the value itself. Returns its kind, and its members
    /// when it is an object (arrays are scanned and checked but not recorded).
    fn value(&mut self, depth: usize) -> Result<(Kind, Option<Obj>), EditError> {
        if depth > MAX_DEPTH {
            return Err(EditError::TooDeep);
        }
        match self.s.get(self.i) {
            Some(b'{') => Ok((Kind::Object, Some(self.object(depth)?))),
            Some(b'[') => {
                self.i += 1;
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok((Kind::Array, None));
                }
                loop {
                    self.ws();
                    self.value(depth + 1)?;
                    self.ws();
                    match self.s.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok((Kind::Array, None));
                        }
                        _ => return Err(EditError::Syntax),
                    }
                }
            }
            Some(b'"') => {
                self.string()?;
                Ok((Kind::String, None))
            }
            Some(b't') => self.literal("true").map(|()| (Kind::Other, None)),
            Some(b'f') => self.literal("false").map(|()| (Kind::Other, None)),
            Some(b'n') => self.literal("null").map(|()| (Kind::Other, None)),
            Some(b'-' | b'0'..=b'9') => self.number().map(|()| (Kind::Other, None)),
            _ => Err(EditError::Syntax),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Obj, EditError> {
        let open = self.i;
        self.eat(b'{')?;
        let mut members = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        self.ws();
        if self.s.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Obj {
                open,
                close: self.i - 1,
                members,
            });
        }
        loop {
            self.ws();
            let start = self.i;
            let key = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            let value_start = self.i;
            let (kind, object) = self.value(depth + 1)?;
            if !seen.insert(key.clone()) {
                return Err(EditError::Duplicate);
            }
            members.push(Member {
                key,
                start,
                value_start,
                end: self.i,
                kind,
                object,
            });
            self.ws();
            match self.s.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Obj {
                        open,
                        close: self.i - 1,
                        members,
                    });
                }
                _ => return Err(EditError::Syntax),
            }
        }
    }
}

/// Validates `text` as strict JSON with an object root and indexes the members the edits need.
pub fn parse(text: &str) -> Result<Doc<'_>, EditError> {
    if text.len() > MAX_BYTES {
        return Err(EditError::TooBig);
    }
    let mut sc = Scanner {
        s: text.as_bytes(),
        text,
        i: 0,
    };
    sc.ws();
    if sc.s.get(sc.i) != Some(&b'{') {
        // Valid JSON of another kind is a refusal of its own; anything else is a syntax error.
        let mut probe = Scanner {
            s: text.as_bytes(),
            text,
            i: sc.i,
        };
        return match probe.value(0) {
            Ok(_) => {
                probe.ws();
                if probe.i == text.len() {
                    Err(EditError::NotObject)
                } else {
                    Err(EditError::Syntax)
                }
            }
            Err(e) => Err(e),
        };
    }
    let root = sc.object(0)?;
    sc.ws();
    if sc.i != text.len() {
        return Err(EditError::Syntax);
    }
    Ok(Doc { text, root })
}

/// The whitespace at the start of the line that `at` is on, if `at` is the first thing on it.
fn line_indent(text: &str, at: usize) -> Option<&str> {
    let line_start = text[..at].rfind('\n').map_or(0, |n| n + 1);
    let before = &text[line_start..at];
    before
        .bytes()
        .all(|b| b == b' ' || b == b'\t')
        .then_some(before)
}

fn quoted(s: &str) -> String {
    serde_json::to_string(s).expect("a string serializes")
}

/// How an object lays out: whether it is multi-line, the indent of its members, and the unit.
struct Style {
    multiline: bool,
    member_indent: String,
    close_indent: String,
}

impl Doc<'_> {
    fn style(&self, o: &Obj, parent_indent: &str) -> Style {
        let multiline = self.text[o.open..o.close].contains('\n');
        let close_indent = line_indent(self.text, o.close)
            .unwrap_or(parent_indent)
            .to_string();
        let member_indent = o
            .members
            .first()
            .and_then(|m| line_indent(self.text, m.start))
            .map(str::to_string)
            .unwrap_or_else(|| format!("{close_indent}  "));
        Style {
            multiline,
            member_indent,
            close_indent,
        }
    }

    fn root_indent(&self) -> &str {
        line_indent(self.text, self.root.open).unwrap_or("")
    }

    fn env_member(&self) -> Result<Option<&Member>, EditError> {
        match self.root.members.iter().find(|m| m.key == "env") {
            None => Ok(None),
            Some(m) if m.kind == Kind::Object => Ok(Some(m)),
            Some(_) => Err(EditError::EnvNotObject),
        }
    }

    /// The decoded string value of `env.<key>`, if there is one.
    pub fn env_value(&self, key: &str) -> Result<Option<String>, EditError> {
        let Some(env) = self.env_member()? else {
            return Ok(None);
        };
        let obj = env.object.as_ref().expect("an object has members");
        match obj.members.iter().find(|m| m.key == key) {
            None => Ok(None),
            Some(m) if m.kind == Kind::String => {
                let mut sc = Scanner {
                    s: self.text.as_bytes(),
                    text: self.text,
                    i: m.value_start,
                };
                sc.string().map(Some)
            }
            Some(_) => Err(EditError::NotString),
        }
    }

    /// Whether the root has any member besides `env`, and whether `env` has any besides `key`.
    pub fn has_other_members(&self, key: &str) -> (bool, bool) {
        let root_other = self.root.members.iter().any(|m| m.key != "env");
        let env_other = self
            .env_member()
            .ok()
            .flatten()
            .and_then(|e| e.object.as_ref())
            .is_some_and(|o| o.members.iter().any(|m| m.key != key));
        (root_other, env_other)
    }

    /// `env.<key> = value`, touching only that member (or adding it, or `env`, in the file's own
    /// layout).
    pub fn set_env_value(&self, key: &str, value: &str) -> Result<String, EditError> {
        let member = format!("{}: {}", quoted(key), quoted(value));
        match self.env_member()? {
            Some(env) => {
                let obj = env.object.as_ref().expect("an object has members");
                match obj.members.iter().find(|m| m.key == key) {
                    Some(m) if m.kind == Kind::String => {
                        Ok(self.splice(m.value_start, m.end, &quoted(value)))
                    }
                    Some(_) => Err(EditError::NotString),
                    None => {
                        let st = self.style(obj, &self.member_indent_of(env));
                        Ok(self.insert_member(obj, &st, &member))
                    }
                }
            }
            None => {
                let st = self.style(&self.root, "");
                let unit = self.unit(&st);
                let inner = if st.multiline || self.root.members.is_empty() {
                    format!(
                        "{{\n{ind}{unit}{member}\n{ind}}}",
                        ind = if self.root.members.is_empty() {
                            self.root_indent().to_string() + &unit
                        } else {
                            st.member_indent.clone()
                        }
                    )
                } else {
                    format!("{{{member}}}")
                };
                let env_member = format!("\"env\": {inner}");
                Ok(self.insert_member(&self.root, &st, &env_member))
            }
        }
    }

    /// The indent of an object member (the line it starts on), or the root's own.
    fn member_indent_of(&self, m: &Member) -> String {
        line_indent(self.text, m.start).unwrap_or("").to_string()
    }

    fn unit(&self, st: &Style) -> String {
        match st.member_indent.strip_prefix(st.close_indent.as_str()) {
            Some(u) if !u.is_empty() => u.to_string(),
            _ => "  ".to_string(),
        }
    }

    fn splice(&self, from: usize, to: usize, with: &str) -> String {
        format!("{}{}{}", &self.text[..from], with, &self.text[to..])
    }

    /// Appends `member` as the last member of `o`.
    fn insert_member(&self, o: &Obj, st: &Style, member: &str) -> String {
        match o.members.last() {
            Some(last) => {
                let sep = if st.multiline {
                    format!(",\n{}", st.member_indent)
                } else {
                    ", ".to_string()
                };
                self.splice(last.end, last.end, &format!("{sep}{member}"))
            }
            None => {
                // `{}` (or `{ }`): replace the braces' contents.
                let unit = if st.multiline {
                    self.unit(st)
                } else {
                    "  ".to_string()
                };
                let ind = format!("{}{unit}", st.close_indent);
                let body = format!("\n{ind}{member}\n{}", st.close_indent);
                self.splice(o.open + 1, o.close, &body)
            }
        }
    }

    /// Removes the member at `idx` of `o`, with the comma and whitespace that belong to it.
    fn drop_member(&self, o: &Obj, idx: usize) -> String {
        let m = &o.members[idx];
        if let Some(next) = o.members.get(idx + 1) {
            self.splice(m.start, next.start, "")
        } else if idx > 0 {
            self.splice(o.members[idx - 1].end, m.end, "")
        } else {
            // The only member: leave the object empty.
            self.splice(o.open + 1, o.close, "")
        }
    }

    /// Removes `env.<key>`; with `drop_empty_env`, also `env` itself if that leaves it empty.
    pub fn unset_env_value(&self, key: &str, drop_empty_env: bool) -> Result<String, EditError> {
        let Some(env) = self.env_member()? else {
            return Ok(self.text.to_string());
        };
        let obj = env.object.as_ref().expect("an object has members");
        let Some(idx) = obj.members.iter().position(|m| m.key == key) else {
            return Ok(self.text.to_string());
        };
        if drop_empty_env && obj.members.len() == 1 {
            let at = self
                .root
                .members
                .iter()
                .position(|m| m.key == "env")
                .expect("found above");
            return Ok(self.drop_member(&self.root, at));
        }
        Ok(self.drop_member(obj, idx))
    }

    /// Whether the document already has an `env` member.
    pub fn has_env(&self) -> bool {
        self.root.members.iter().any(|m| m.key == "env")
    }

    /// Whether the document is exactly `{}` with only whitespace around.
    pub fn is_empty_object(&self) -> bool {
        self.root.members.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "NODE_EXTRA_CA_CERTS";

    fn set(text: &str, v: &str) -> String {
        parse(text).unwrap().set_env_value(KEY, v).unwrap()
    }
    fn unset(text: &str, drop: bool) -> String {
        parse(text).unwrap().unset_env_value(KEY, drop).unwrap()
    }
    fn get(text: &str) -> Option<String> {
        parse(text).unwrap().env_value(KEY).unwrap()
    }

    #[test]
    fn strict_json_only() {
        for ok in [
            "{}",
            " {\"a\": [1, 2.5e-3, -0, true, false, null, \"x\"]} \n",
            "{\"a\":{\"b\":{}}}",
        ] {
            assert!(parse(ok).is_ok(), "{ok}");
        }
        for (bad, why) in [
            ("{\"a\":1,}", EditError::Syntax),
            ("{\"a\" 1}", EditError::Syntax),
            ("{a:1}", EditError::Syntax),
            ("{'a':1}", EditError::Syntax),
            ("{\"a\":01}", EditError::Syntax),
            ("{\"a\":1.}", EditError::Syntax),
            ("{\"a\":.5}", EditError::Syntax),
            ("{\"a\":+1}", EditError::Syntax),
            ("{\"a\":NaN}", EditError::Syntax),
            ("{\"a\":\"\\x\"}", EditError::Syntax),
            ("{\"a\":\"\\ud800\"}", EditError::Syntax),
            ("{\"a\":\"\\udc00\"}", EditError::Syntax),
            ("{\"a\":\"line\nbreak\"}", EditError::Syntax),
            ("{\"a\":1} x", EditError::Syntax),
            ("{\"a\":1}{}", EditError::Syntax),
            ("// c\n{}", EditError::Syntax),
            ("{/* c */}", EditError::Syntax),
            ("{\"a\":1 // c\n}", EditError::Syntax),
            ("\u{feff}{}", EditError::Syntax),
            ("", EditError::Syntax),
            ("{", EditError::Syntax),
            ("[1,2]", EditError::NotObject),
            ("\"s\"", EditError::NotObject),
            ("3", EditError::NotObject),
        ] {
            assert_eq!(parse(bad).err(), Some(why), "{bad:?}");
        }
    }

    #[test]
    fn duplicates_are_rejected_at_every_level_even_with_escapes() {
        for bad in [
            "{\"a\":1,\"a\":2}",
            "{\"x\":{\"a\":1,\"a\":2}}",
            "{\"x\":[{\"a\":1,\"a\":2}]}",
            "{\"env\":{\"K\":\"1\",\"K\":\"2\"}}",
            "{\"env\":{},\"\\u0065nv\":{}}",
            "{\"a\":1,\"\\u0061\":2}",
        ] {
            assert_eq!(parse(bad).err(), Some(EditError::Duplicate), "{bad}");
        }
        assert!(
            parse("{\"a\":{\"x\":1},\"b\":{\"x\":2}}").is_ok(),
            "the same name in different objects is fine"
        );
    }

    #[test]
    fn depth_and_size_are_bounded() {
        let deep = |n: usize| format!("{}{}{}", "{\"a\":".repeat(n), "1", "}".repeat(n));
        assert!(parse(&deep(60)).is_ok());
        assert_eq!(parse(&deep(70)).err(), Some(EditError::TooDeep));
        let arr = format!("{{\"a\":{}1{}}}", "[".repeat(70), "]".repeat(70));
        assert_eq!(parse(&arr).err(), Some(EditError::TooDeep));
        let big = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_BYTES));
        assert_eq!(parse(&big).err(), Some(EditError::TooBig));
    }

    #[test]
    fn reads_the_value_with_escapes_decoded() {
        assert_eq!(
            get("{\"env\":{\"NODE_EXTRA_CA_CERTS\":\"/a/b.pem\"}}").as_deref(),
            Some("/a/b.pem")
        );
        assert_eq!(
            get("{\"\\u0065nv\":{\"NODE_EXTRA_CA_CERTS\":\"/a\\/\\u00e9\\ud83d\\ude00\"}}")
                .as_deref(),
            Some("/a/é😀")
        );
        assert_eq!(get("{}"), None);
        assert_eq!(get("{\"env\":{}}"), None);
        assert_eq!(
            parse("{\"env\":3}").unwrap().env_value(KEY),
            Err(EditError::EnvNotObject)
        );
        assert_eq!(
            parse("{\"env\":{\"NODE_EXTRA_CA_CERTS\":3}}")
                .unwrap()
                .env_value(KEY),
            Err(EditError::NotString)
        );
    }

    #[test]
    fn replacing_a_value_changes_only_those_bytes() {
        let t = "{\n  \"big\": 123456789012345678901234567890,\n  \"dec\": 0.1000000000000000055511151231257827,\n  \"u\": \"\\u00e9\\n\",\n  \"env\": {\n    \"A\": 1,\n    \"NODE_EXTRA_CA_CERTS\": \"/old.pem\",\n    \"B\": [1, 2 ]\n  },\n  \"z\":   true\n}\n";
        let out = set(t, "/new.pem");
        assert_eq!(out, t.replace("\"/old.pem\"", "\"/new.pem\""));
        assert_eq!(
            unset(&out, false),
            t.replace("    \"NODE_EXTRA_CA_CERTS\": \"/old.pem\",\n", "")
        );
    }

    #[test]
    fn adding_a_member_keeps_the_layout_and_every_other_byte() {
        let cases = [
            // multi-line, 2 and 4 spaces, tabs
            "{\n  \"a\": 1,\n  \"env\": {\n    \"X\": \"y\"\n  }\n}\n",
            "{\n    \"a\": 1,\n    \"env\": {\n        \"X\": \"y\"\n    }\n}\n",
            "{\n\t\"a\": 1,\n\t\"env\": {\n\t\t\"X\": \"y\"\n\t}\n}\n",
            // no trailing newline, odd spacing, huge numbers
            "{\"a\":123456789012345678901234567890,\"env\":{\"X\":\"y\"}}",
            "{ \"a\" : 1.50 , \"env\" : { \"X\" : \"y\" } }",
        ];
        for t in cases {
            let out = set(t, "/ca.pem");
            let d = parse(&out).expect("still valid");
            assert_eq!(
                d.env_value(KEY).unwrap().as_deref(),
                Some("/ca.pem"),
                "{out}"
            );
            // Removing it again gives back the original bytes exactly.
            assert_eq!(unset(&out, false), t, "{t:?}\n{out}");
        }
    }

    #[test]
    fn adding_env_to_a_document_without_one_and_removing_it_again_is_exact() {
        for t in [
            "{\n  \"model\": \"opus\",\n  \"hooks\": {}\n}\n",
            "{\n    \"model\": \"opus\"\n}\n",
            "{\"model\":\"opus\"}",
            "{ \"model\": \"opus\" }\n",
            "{\n\t\"model\": \"opus\"\n}\n",
            "{\r\n  \"model\": \"opus\"\r\n}\r\n",
        ] {
            let out = set(t, "/ca.pem");
            assert!(parse(&out).is_ok(), "{out}");
            assert_eq!(get(&out).as_deref(), Some("/ca.pem"), "{out}");
            assert_eq!(unset(&out, true), t, "{t:?}\n{out}");
        }
    }

    #[test]
    fn an_empty_document_gets_a_tidy_env_and_loses_it_again() {
        let out = set("{}", "/ca.pem");
        assert_eq!(
            out,
            "{\n  \"env\": {\n    \"NODE_EXTRA_CA_CERTS\": \"/ca.pem\"\n  }\n}"
        );
        assert!(parse(&out).is_ok());
        let again = set("{}\n", "/ca.pem");
        assert!(again.ends_with("}\n"));
        let un = parse(&out).unwrap().unset_env_value(KEY, true).unwrap();
        assert!(parse(&un).unwrap().is_empty_object());
        // An existing empty env object is filled in place.
        let filled = set("{\n  \"env\": {}\n}\n", "/ca.pem");
        assert_eq!(
            filled,
            "{\n  \"env\": {\n    \"NODE_EXTRA_CA_CERTS\": \"/ca.pem\"\n  }\n}\n"
        );
        assert_eq!(get(&filled).as_deref(), Some("/ca.pem"));
    }

    #[test]
    fn removing_the_first_middle_last_and_only_member() {
        let t = |body: &str| format!("{{\n  \"env\": {{\n{body}\n  }}\n}}\n");
        let first = t("    \"NODE_EXTRA_CA_CERTS\": \"/x\",\n    \"B\": 1,\n    \"C\": 2");
        assert_eq!(unset(&first, false), t("    \"B\": 1,\n    \"C\": 2"));
        let mid = t("    \"B\": 1,\n    \"NODE_EXTRA_CA_CERTS\": \"/x\",\n    \"C\": 2");
        assert_eq!(unset(&mid, false), t("    \"B\": 1,\n    \"C\": 2"));
        let last = t("    \"B\": 1,\n    \"C\": 2,\n    \"NODE_EXTRA_CA_CERTS\": \"/x\"");
        assert_eq!(unset(&last, false), t("    \"B\": 1,\n    \"C\": 2"));
        for out in [
            unset(&first, false),
            unset(&mid, false),
            unset(&last, false),
        ] {
            assert!(parse(&out).is_ok(), "{out}");
        }
        let only = "{\"env\":{\"NODE_EXTRA_CA_CERTS\":\"/x\"},\"b\":1}";
        assert_eq!(unset(only, true), "{\"b\":1}");
        assert!(parse(&unset(only, false)).is_ok());
        assert_eq!(get(&unset(only, false)), None);
        // Nothing to remove: the text comes back unchanged.
        assert_eq!(unset("{\"a\":1}", true), "{\"a\":1}");
        assert_eq!(unset("{\"env\":{\"B\":1}}", true), "{\"env\":{\"B\":1}}");
    }

    #[test]
    fn values_are_escaped_and_comments_never_appear() {
        let out = set("{}", "/we\"ird\\path\u{e9}\n");
        assert_eq!(get(&out).as_deref(), Some("/we\"ird\\path\u{e9}\n"));
        assert!(!out.contains("//") && !out.contains("/*"));
    }

    #[test]
    fn other_members_are_reported() {
        let d = parse("{\"env\":{\"NODE_EXTRA_CA_CERTS\":\"/x\"}}").unwrap();
        assert_eq!(d.has_other_members(KEY), (false, false));
        let d = parse("{\"a\":1,\"env\":{\"NODE_EXTRA_CA_CERTS\":\"/x\",\"B\":2}}").unwrap();
        assert_eq!(d.has_other_members(KEY), (true, true));
    }

    #[test]
    fn set_refuses_what_it_cannot_edit() {
        assert_eq!(
            parse("{\"env\":[]}")
                .unwrap()
                .set_env_value(KEY, "/x")
                .err(),
            Some(EditError::EnvNotObject)
        );
        assert_eq!(
            parse("{\"env\":{\"NODE_EXTRA_CA_CERTS\":5}}")
                .unwrap()
                .set_env_value(KEY, "/x")
                .err(),
            Some(EditError::NotString)
        );
    }
}
