//! Minimal JSON reader for `rpass import` (CLI_REFERENCE schema v1).
//!
//! Hand-rolled deliberately: the no-dependency-creeep principle that shaped
//! the whole tree (ADR-0005 is about network, but the same taste applies
//! here) means one ~200-line parser beats a serde_json dep for a schema this
//! small. It parses the JSON *grammar* (objects, arrays, strings, numbers,
//! bools, null) with \u escapes; interpretation lives in the importer.
//!
//! The writer side (export) emits a strict subset by construction; this
//! reader is liberal in what it accepts per the import contract
//! ("unrecognized top-level keys = ignored, forward-compat").

use crate::crypto::error::{Error, Result};
use zeroize::Zeroize;

/// Parsed JSON value. Numbers are kept as f64 — the schema's numbers are
/// item ids, unix timestamps, and TOTP parameters, all far below 2^53.
#[derive(Debug, Clone, PartialEq, Zeroize)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_num(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Obj(fields) => Some(fields),
            _ => None,
        }
    }
}

pub fn parse(input: &str) -> Result<Json> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(p.err("trailing characters after JSON value"));
    }
    Ok(v)
}

/// Hard nesting cap: `object`/`array` recurse, so unbounded depth on a
/// hostile import file means stack exhaustion, not a clean error. 128 is
/// far past any real export.
const MAX_DEPTH: u32 = 128;
const MAX_COLLECTION_LEN: usize = 10_000;

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: u32,
}

impl<'a> Parser<'a> {
    fn err(&self, what: &'static str) -> Error {
        Error::Encrypt(format!("json: {what} at byte {}", self.pos))
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> Result<Json> {
        if self.depth >= MAX_DEPTH {
            return Err(self.err("nesting too deep (max 128 levels)"));
        }
        // Depth is bumped around the recursive call only; scalars don't nest.
        match self.peek() {
            Some(b'{') => {
                self.depth += 1;
                let r = self.object();
                self.depth -= 1;
                r
            }
            Some(b'[') => {
                self.depth += 1;
                let r = self.array();
                self.depth -= 1;
                r
            }
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(self.err("unexpected character")),
        }
    }

    fn literal(&mut self, lit: &str, value: Json) -> Result<Json> {
        if self.bytes[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(value)
        } else {
            Err(self.err("bad literal"))
        }
    }

    fn object(&mut self) -> Result<Json> {
        self.pos += 1; // '{'
        let mut fields = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            if fields.len() >= MAX_COLLECTION_LEN {
                return Err(self.err("object has too many fields"));
            }
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected object key"));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':'"));
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.value()?;
            // Last-wins on duplicate keys (matches serde_json's default).
            match fields.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => fields.push((key, value)),
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(fields));
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self) -> Result<Json> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            if items.len() >= MAX_COLLECTION_LEN {
                return Err(self.err("array has too many items"));
            }
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn string(&mut self) -> Result<String> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or_else(|| self.err("unterminated string"))?;
            self.pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.peek().ok_or_else(|| self.err("bad escape"))?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            // Surrogate pair handling — secrets and titles are
                            // user-shaped text, emoji happen.
                            if (0xD800..=0xDBFF).contains(&cp) {
                                if self.peek() == Some(b'\\') {
                                    self.pos += 1;
                                    if self.peek() == Some(b'u') {
                                        self.pos += 1;
                                        let low = self.hex4()?;
                                        if (0xDC00..=0xDFFF).contains(&low) {
                                            let combined =
                                                0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                                            out.push(
                                                char::from_u32(combined).ok_or_else(|| {
                                                    self.err("bad surrogate pair")
                                                })?,
                                            );
                                            continue;
                                        }
                                    }
                                }
                                return Err(self.err("lone high surrogate"));
                            }
                            out.push(char::from_u32(cp).ok_or_else(|| self.err("bad codepoint"))?);
                        }
                        _ => return Err(self.err("unknown escape")),
                    }
                }
                // Raw control characters are invalid per RFC 8259.
                c if c < 0x20 => return Err(self.err("control character in string")),
                c if c < 0x80 => out.push(c as char),
                _ => {
                    // Multi-byte UTF-8: find the full sequence. The input is
                    // already a &str so it's valid UTF-8 — just consume it.
                    let start = self.pos - 1;
                    let width = utf8_width(c).ok_or_else(|| self.err("bad utf8"))?;
                    let end = start + width;
                    if end > self.bytes.len() {
                        return Err(self.err("bad utf8"));
                    }
                    let s = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| self.err("bad utf8"))?;
                    out.push_str(s);
                    self.pos = end;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32> {
        let hex = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.err("truncated \\u escape"))?;
        let s = std::str::from_utf8(hex).map_err(|_| self.err("bad hex"))?;
        let v = u32::from_str_radix(s, 16).map_err(|_| self.err("bad hex"))?;
        self.pos += 4;
        Ok(v)
    }

    fn number(&mut self) -> Result<Json> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.err("bad number"))?;
        let n: f64 = s.parse().map_err(|_| self.err("bad number"))?;
        Ok(Json::Num(n))
    }
}

fn utf8_width(first: u8) -> Option<usize> {
    match first {
        0xC0..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF7 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(s: &str) -> Json {
        parse(s).unwrap()
    }

    #[test]
    fn scalars() {
        assert_eq!(j("null"), Json::Null);
        assert_eq!(j("true"), Json::Bool(true));
        assert_eq!(j(" 42 "), Json::Num(42.0));
        assert_eq!(j("-3.5e2"), Json::Num(-350.0));
        assert_eq!(j("\"hi\""), Json::Str("hi".into()));
    }

    #[test]
    fn strings_and_escapes() {
        assert_eq!(j(r#""a\nb\tc\"d\\e""#).as_str().unwrap(), "a\nb\tc\"d\\e");
        assert_eq!(j(r#""é""#).as_str().unwrap(), "é");
        assert_eq!(j(r#""😀""#).as_str().unwrap(), "😀"); // surrogate pair
        assert_eq!(j(r#""A""#).as_str().unwrap(), "A");
        assert!(parse(r#""\ud83d""#).is_err()); // lone high surrogate
        assert!(parse("\"a\nb\"").is_err()); // raw control char
        assert!(parse(r#""unterminated"#).is_err());
    }

    #[test]
    fn objects_and_arrays() {
        let v = j(r#"{"a": [1, 2, {"b": null}], "c": "x"}"#);
        assert_eq!(v.get("c").unwrap().as_str().unwrap(), "x");
        let a = match v.get("a").unwrap() {
            Json::Arr(items) => items.clone(),
            _ => panic!("expected array"),
        };
        assert_eq!(a.len(), 3);
        assert_eq!(a[0], Json::Num(1.0));
        assert!(matches!(a[2].get("b"), Some(Json::Null)));
        // duplicate key: last wins
        let d = j(r#"{"k": 1, "k": 2}"#);
        assert_eq!(d.get("k").unwrap().as_num().unwrap(), 2.0);
    }

    #[test]
    fn malformed() {
        assert!(parse("").is_err());
        assert!(parse("{").is_err());
        assert!(parse("[1,]").is_err()); // trailing comma
        assert!(parse(r#"{"a" 1}"#).is_err()); // missing colon
        assert!(parse("tru").is_err());
        assert!(parse("1 2").is_err()); // trailing characters
        assert!(parse(r#"-x"#).is_err());
    }

    #[test]
    fn nesting_depth_capped() {
        // 100 levels parse fine; 500 levels error instead of overflowing the stack.
        let ok = "[".repeat(100) + &"]".repeat(100);
        assert!(parse(&ok).is_ok());
        let too_deep = "[".repeat(500) + &"]".repeat(500);
        let err = parse(&too_deep).unwrap_err().to_string();
        assert!(err.contains("nesting too deep"), "{err}");
    }

    #[test]
    fn collection_length_capped() {
        let too_many = "[".to_string() + &"0,".repeat(MAX_COLLECTION_LEN) + "0]";
        let err = parse(&too_many).unwrap_err().to_string();
        assert!(err.contains("too many items"), "{err}");
    }

    /// The importer's realistic shape: an export schema v1 file.
    #[test]
    fn export_schema_shape() {
        let doc = j(r#"{
            "format_version": 1,
            "exported_at": 1750000000,
            "items": {
                "1": {
                    "title": "example.com",
                    "username": "alice",
                    "password": "correct horse battery staple",
                    "url": "https://example.com",
                    "notes": "",
                    "totp": {
                        "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                        "period": 30,
                        "digits": 6,
                        "algorithm": "SHA1"
                    },
                    "created_unix": 1750000000,
                    "modified_unix": 1750000000
                },
                "2": {
                    "title": "github.com",
                    "username": "bob",
                    "password": "pw",
                    "url": "",
                    "notes": "",
                    "totp": null,
                    "created_unix": 1750000000,
                    "modified_unix": 1750000000
                }
            }
        }"#);
        let items = doc.get("items").unwrap().as_obj().unwrap();
        assert_eq!(items.len(), 2);
        let one = doc.get("items").unwrap().get("1").unwrap();
        assert_eq!(one.get("username").unwrap().as_str().unwrap(), "alice");
        let t = one.get("totp").unwrap();
        assert_eq!(t.get("period").unwrap().as_num().unwrap(), 30.0);
        assert!(matches!(
            doc.get("items").unwrap().get("2").unwrap().get("totp"),
            Some(Json::Null)
        ));
    }
}
