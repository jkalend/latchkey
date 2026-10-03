//! Bounded JSON reader for `latchkey import` (CLI_REFERENCE schema v1).
//!
//! The grammar (objects, arrays, strings, \u escapes, numbers) is delegated
//! to `serde_json` — a maintained parser — inside a depth- and size-bounded
//! conversion into our own wiping value tree. This module owns policy:
//! redacted Debug, drop-zeroize, nesting/collection caps, lossless integer
//! access. Interpretation lives in the importer.
//!
//! The writer side (export) emits a strict subset by construction; this
//! reader is liberal in what it accepts per the import contract
//! ("unrecognized top-level keys = ignored, forward-compat").

use crate::crypto::error::{Error, Result};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Parsed JSON value with wiping ownership. Integers are kept lossless
/// (i64/u64); floats only where the input actually had a fraction or
/// exponent. Importers that need integer fields use `as_i64`/`as_u64`
/// instead of routing through an f64.
#[derive(Clone, PartialEq, Zeroize)]
#[zeroize(drop)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl fmt::Debug for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Json(<redacted>)")
    }
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
    /// Lossless unsigned-integer view: None for floats, fractions,
    /// negatives, or values outside u64.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::UInt(n) => Some(*n),
            Json::Int(n) => u64::try_from(*n).ok(),
            _ => None,
        }
    }

    /// Lossless signed-integer view: None for floats, fractions, or values
    /// outside i64.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(n) => Some(*n),
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

/// Hard nesting cap: the conversion recurses, so unbounded depth on a
/// hostile import file means stack exhaustion, not a clean error. 128 is
/// far past any real export.
const MAX_DEPTH: u32 = 128;
const MAX_COLLECTION_LEN: usize = 10_000;

/// Parse `input` with serde_json, then convert into the wiping tree with
/// explicit depth and collection-size limits. The whole input must be a
/// single JSON value with no trailing characters (serde_json enforces).
pub fn parse(input: &str) -> Result<Json> {
    let value = serde_json::from_str::<serde_json::Value>(input)
        .map_err(|e| Error::Encrypt(format!("json: {e}")))?;
    // The intermediate serde tree cannot be zeroized (it does not implement
    // the needed trait); conversion below copies secret-bearing strings into
    // our wiping tree, and the serde tree is dropped immediately after.
    let converted = convert(&value, 0);
    drop(value);
    converted
}

fn convert(value: &serde_json::Value, depth: u32) -> Result<Json> {
    if depth >= MAX_DEPTH {
        return Err(Error::Encrypt(
            "json: nesting too deep (max 128 levels)".into(),
        ));
    }
    match value {
        serde_json::Value::Null => Ok(Json::Null),
        serde_json::Value::Bool(b) => Ok(Json::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Json::Int(i))
            } else if let Some(u) = n.as_u64() {
                Ok(Json::UInt(u))
            } else if let Some(f) = n.as_f64() {
                Ok(Json::Float(f))
            } else {
                Err(Error::Encrypt("json: unrepresentable number".into()))
            }
        }
        serde_json::Value::String(s) => Ok(Json::Str(s.clone())),
        serde_json::Value::Array(items) => {
            if items.len() > MAX_COLLECTION_LEN {
                return Err(Error::Encrypt("json: array has too many items".into()));
            }
            let mut out = Zeroizing::new(Vec::with_capacity(items.len()));
            for item in items {
                out.push(convert(item, depth + 1)?);
            }
            Ok(Json::Arr(std::mem::take(&mut *out)))
        }
        serde_json::Value::Object(map) => {
            if map.len() > MAX_COLLECTION_LEN {
                return Err(Error::Encrypt("json: object has too many fields".into()));
            }
            let mut out = Zeroizing::new(Vec::with_capacity(map.len()));
            for (key, item) in map {
                // Last-wins on duplicate keys is impossible here: serde_json's
                // map deduplicates at parse time (last value wins there too).
                out.push((key.clone(), convert(item, depth + 1)?));
            }
            Ok(Json::Obj(std::mem::take(&mut *out)))
        }
    }
}
