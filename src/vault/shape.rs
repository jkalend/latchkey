//! Vault shape — in-memory representations mirroring VAULT_FORMAT.md.
//! serde is intentionally not used: on-disk bytes are defined by the spec,
//! not by any Rust serializer.

use crate::crypto::error::{Error, Result};
use std::fmt;
use zeroize::Zeroize;

pub const LIVE_STATE: u8 = 0x01;
pub const TOMBSTONE_STATE: u8 = 0x02;

/// One entry in the encrypted index (VAULT_FORMAT §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub item_id: u32,
    pub slot: u32,
    pub state: u8,
    pub title: String,
    pub username: String,
}

/// Serialized index payload (plaintext before AEAD encryption).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexPayload {
    pub entries: Vec<IndexEntry>,
}

/// ItemRecord plaintext (VAULT_FORMAT §6.2). Password, notes optional.
/// Every plaintext buffer is zeroized when the record is dropped.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct ItemRecord {
    pub password: Option<Vec<u8>>,
    pub url: String,
    pub notes: Option<Vec<u8>>,
    pub totp: Option<TotpSubRecord>,
    pub created_unix: u64,
    pub modified_unix: u64,
}
impl fmt::Debug for ItemRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemRecord")
            .field("password_len", &self.password.as_ref().map(Vec::len))
            .field("url", &self.url)
            .field("notes_len", &self.notes.as_ref().map(Vec::len))
            .field("totp", &self.totp.as_ref().map(|_| "<redacted>"))
            .field("created_unix", &self.created_unix)
            .field("modified_unix", &self.modified_unix)
            .finish()
    }
}

impl fmt::Debug for TotpSubRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpSubRecord")
            .field("secret_len", &self.secret.len())
            .field("period", &self.period)
            .field("digits", &self.digits)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct TotpSubRecord {
    pub secret: Vec<u8>,
    pub period: u32,
    pub digits: u32,
    #[zeroize(skip)]
    pub algorithm: TotpAlgorithm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TotpAlgorithm {
    Sha1 = 0x01,
    Sha256 = 0x02,
    Sha512 = 0x03,
}

impl TotpAlgorithm {
    pub fn id(self) -> u8 {
        self as u8
    }

    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0x01 => Ok(Self::Sha1),
            0x02 => Ok(Self::Sha256),
            0x03 => Ok(Self::Sha512),
            other => Err(Error::Encrypt(format!(
                "unknown TOTP algorithm id 0x{other:02x}"
            ))),
        }
    }
}

pub fn serialize_index(p: &IndexPayload) -> Result<Vec<u8>> {
    if p.entries.len() > u32::MAX as usize {
        return Err(Error::Encrypt("too many index entries".into()));
    }
    let mut out = Vec::with_capacity(estimate_index_size(p));
    out.extend_from_slice(&(p.entries.len() as u32).to_be_bytes());
    for e in &p.entries {
        if !matches!(e.state, LIVE_STATE | TOMBSTONE_STATE | 0xFF) {
            return Err(Error::Encrypt(format!("bad index state 0x{:02x}", e.state)));
        }
        out.extend_from_slice(&e.item_id.to_be_bytes());
        out.extend_from_slice(&e.slot.to_be_bytes());
        out.push(if e.state == LIVE_STATE {
            LIVE_STATE
        } else {
            TOMBSTONE_STATE
        });
        push_str(&mut out, &e.title, 256)?;
        push_str(&mut out, &e.username, 512)?;
    }
    Ok(out)
}

fn estimate_index_size(p: &IndexPayload) -> usize {
    4 + p
        .entries
        .iter()
        .map(|e| 9 + 2 + e.title.len() + 2 + e.username.len())
        .sum::<usize>()
}

pub fn parse_index(buf: &[u8]) -> Result<IndexPayload> {
    let mut cur = Cursor::new(buf);
    let count = cur.read_u32()?;
    let cap = count.min(1_000_000).min(buf.len() as u32 / 9 + 1);
    let mut entries = Vec::with_capacity(cap as usize);
    for _ in 0..count {
        let item_id = cur.read_u32()?;
        let slot = cur.read_u32()?;
        let raw_state = cur.read_u8()?;
        if !matches!(raw_state, LIVE_STATE | TOMBSTONE_STATE | 0xFF) {
            return Err(Error::Encrypt(format!("bad index state 0x{raw_state:02x}")));
        }
        let state = if raw_state == LIVE_STATE {
            LIVE_STATE
        } else {
            TOMBSTONE_STATE
        };

        entries.push(IndexEntry {
            item_id,
            slot,
            state,
            title: cur.read_str_max(256)?,
            username: cur.read_str_max(512)?,
        });
    }
    if cur.remaining() != 0 {
        return Err(Error::Encrypt("trailing bytes in index".into()));
    }
    Ok(IndexPayload { entries })
}

pub fn serialize_item(r: &ItemRecord, item_id: u32) -> Result<Vec<u8>> {
    if r.password.as_ref().is_some_and(|v| v.len() > 1024)
        || r.url.len() > 2048
        || r.notes.as_ref().is_some_and(|v| v.len() > 8192)
        || r.totp.as_ref().is_some_and(|t| t.secret.len() > 128)
    {
        return Err(Error::Encrypt("item field exceeds format limit".into()));
    }
    if let Some(t) = &r.totp {
        if t.period == 0 || !matches!(t.digits, 6 | 8) {
            return Err(Error::Encrypt("invalid TOTP parameters".into()));
        }
    }

    let mut out = Vec::new();
    push_opt_bytes(&mut out, &r.password, 1024)?;
    push_str(&mut out, &r.url, 2048)?;
    push_opt_bytes(&mut out, &r.notes, 8192)?;
    match &r.totp {
        None => out.push(0x00),
        Some(t) => {
            out.push(0x01);
            push_bytes(&mut out, &t.secret, 128)?;
            out.extend_from_slice(&t.period.to_be_bytes());
            out.extend_from_slice(&t.digits.to_be_bytes());
            out.push(t.algorithm.id());
        }
    }
    out.extend_from_slice(&r.created_unix.to_be_bytes());
    out.extend_from_slice(&r.modified_unix.to_be_bytes());
    out.extend_from_slice(&item_id.to_be_bytes());
    Ok(out)
}

/// Returns the record plus the embedded `item_id`, which the caller
/// must cross-check against the index entry.
pub fn parse_item(buf: &[u8]) -> Result<(ItemRecord, u32)> {
    let mut cur = Cursor::new(buf);
    let password = cur.read_opt_bytes_max(1024)?;
    let url = cur.read_str_max(2048)?;
    let notes = cur.read_opt_bytes_max(8192)?;
    let totp = match cur.read_u8()? {
        0x00 => None,
        0x01 => {
            let secret = cur.read_bytes_max(128)?;
            let period = cur.read_u32()?;
            let digits = cur.read_u32()?;
            if period == 0 || !matches!(digits, 6 | 8) {
                return Err(Error::Encrypt("invalid TOTP parameters".into()));
            }
            let algorithm = TotpAlgorithm::from_id(cur.read_u8()?)?;
            Some(TotpSubRecord {
                secret,
                period,
                digits,
                algorithm,
            })
        }
        value => {
            return Err(Error::Encrypt(format!(
                "bad totp presence byte 0x{value:02x}"
            )))
        }
    };
    let created_unix = cur.read_u64()?;
    let modified_unix = cur.read_u64()?;
    let item_id = cur.read_u32()?;
    if cur.remaining() != 0 {
        return Err(Error::Encrypt("trailing bytes in item".into()));
    }
    Ok((
        ItemRecord {
            password,
            url,
            notes,
            totp,
            created_unix,
            modified_unix,
        },
        item_id,
    ))
}

fn push_str(out: &mut Vec<u8>, s: &str, max: usize) -> Result<()> {
    if s.len() > max || s.len() > u16::MAX as usize {
        return Err(Error::Encrypt("string field exceeds format limit".into()));
    }
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn push_bytes(out: &mut Vec<u8>, b: &[u8], max: usize) -> Result<()> {
    if b.len() > max {
        return Err(Error::Encrypt("byte field exceeds format limit".into()));
    }
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn push_opt_bytes(out: &mut Vec<u8>, v: &Option<Vec<u8>>, max: usize) -> Result<()> {
    match v {
        None => out.push(0x00),
        Some(b) => {
            out.push(0x01);
            push_bytes(out, b, max)?;
        }
    }
    Ok(())
}

pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Encrypt("deserialize: unexpected end".into()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        let s = self.take(8)?;
        Ok(u64::from_be_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    pub fn read_bytes_max(&mut self, max: usize) -> Result<Vec<u8>> {
        let len = self.read_u32()? as usize;
        if len > max {
            return Err(Error::Encrypt("byte string too large".into()));
        }
        Ok(self.take(len)?.to_vec())
    }

    pub fn read_str_max(&mut self, max: usize) -> Result<String> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        if len > max {
            return Err(Error::Encrypt("utf8 string too large".into()));
        }
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| Error::Encrypt("invalid utf8".into()))
    }

    pub fn read_opt_bytes_max(&mut self, max: usize) -> Result<Option<Vec<u8>>> {
        match self.read_u8()? {
            0x00 => Ok(None),
            0x01 => Ok(Some(self.read_bytes_max(max)?)),
            value => Err(Error::Encrypt(format!("bad presence byte 0x{value:02x}"))),
        }
    }
}
