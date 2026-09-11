//! Vault shape — in-memory representations mirroring VAULT_FORMAT.md.
//! serde is intentionally not used: on-disk bytes are defined by the spec,
//! not by any Rust serializer.

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
/// Kept heap-allocated so dropping a `Vault` scrubs every sub-buffer once via
/// zeroize-on-drop of the vault (not automatic here — see note in vault_impl).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemRecord {
    /// v1 treats password as UTF-8 bytes; `get -p` returns them, `--show` converts.
    pub password: Option<Vec<u8>>,
    pub url: String,
    pub notes: Option<Vec<u8>>,
    pub totp: Option<TotpSubRecord>,
    pub created_unix: u64,
    pub modified_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TotpSubRecord {
    pub secret: Vec<u8>, // raw bytes, NOT base32
    pub period: u32,
    pub digits: u32,
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

use crate::crypto::error::{Error, Result};

/// Wooden in-memory vault, holding decrypted data for the current session.
/// The index (titles/usernames, no secrets) and open items live here;
/// closed items only exist on disk.
pub struct VaultState {
    pub entries: Vec<IndexEntry>,
    /// Slots with non-tombstone state. Only slots actually fetched are
    /// present; on-demand map.
    pub open_items: std::collections::BTreeMap<u32, ItemRecord>,
}

// ─── Index serde ────────────────────────────────────────────────────────────

pub fn serialize_index(p: &IndexPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(estimate_index_size(p));
    out.extend_from_slice(&(p.entries.len() as u32).to_be_bytes());
    for e in &p.entries {
        out.extend_from_slice(&e.item_id.to_be_bytes());
        out.extend_from_slice(&e.slot.to_be_bytes());
        out.push(e.state);
        push_str(&mut out, &e.title);
        push_str(&mut out, &e.username);
    }
    out
}

fn estimate_index_size(p: &IndexPayload) -> usize {
    let mut n = 4;
    for e in &p.entries {
        n += 9 + 2 + e.title.len() + 2 + e.username.len();
    }
    n
}

pub fn parse_index(buf: &[u8]) -> Result<IndexPayload> {
    let mut cur = Cursor::new(buf);
    let count = cur.read_u32()?;
    let mut entries = Vec::with_capacity(count.min(1_000_000) as usize);
    for _ in 0..count {
        entries.push(IndexEntry {
            item_id: cur.read_u32()?,
            slot: cur.read_u32()?,
            state: cur.read_u8()?,
            title: cur.read_str()?,
            username: cur.read_str()?,
        });
    }
    Ok(IndexPayload { entries })
}

// ─── ItemRecord serde ───────────────────────────────────────────────────────

pub fn serialize_item(r: &ItemRecord, item_id: u32) -> Vec<u8> {
    let mut out = Vec::new();
    push_opt_bytes(&mut out, &r.password);
    push_str(&mut out, &r.url);
    push_opt_bytes(&mut out, &r.notes);
    match &r.totp {
        None => out.push(0x00),
        Some(t) => {
            out.push(0x01);
            push_bytes(&mut out, &t.secret);
            out.extend_from_slice(&t.period.to_be_bytes());
            out.extend_from_slice(&t.digits.to_be_bytes());
            out.push(t.algorithm.id());
        }
    }
    out.extend_from_slice(&r.created_unix.to_be_bytes());
    out.extend_from_slice(&r.modified_unix.to_be_bytes());
    out.extend_from_slice(&item_id.to_be_bytes());
    out
}

/// Returns the record plus the embedded `item_id` (§6.2), which the caller
/// must cross-check against the index entry.
pub fn parse_item(buf: &[u8]) -> Result<(ItemRecord, u32)> {
    let mut cur = Cursor::new(buf);
    let password = cur.read_opt_bytes()?;
    let url = cur.read_str()?;
    let notes = cur.read_opt_bytes()?;
    let totp_present = cur.read_u8()?;
    let totp = match totp_present {
        0x00 => None,
        0x01 => {
            let secret = cur.read_bytes()?;
            let period = cur.read_u32()?;
            let digits = cur.read_u32()?;
            let algorithm = TotpAlgorithm::from_id(cur.read_u8()?)?;
            Some(TotpSubRecord {
                secret,
                period,
                digits,
                algorithm,
            })
        }
        o => return Err(Error::Encrypt(format!("bad totp presence byte 0x{o:02x}"))),
    };
    let created_unix = cur.read_u64()?;
    let modified_unix = cur.read_u64()?;
    let item_id = cur.read_u32()?;
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

// ─── Helpers ────────────────────────────────────────────────────────────────

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}
fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}
fn push_opt_bytes(out: &mut Vec<u8>, v: &Option<Vec<u8>>) {
    match v {
        None => out.push(0x00),
        Some(b) => {
            out.push(0x01);
            push_bytes(out, b);
        }
    }
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
    pub fn read_u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
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
    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()? as usize;
        if len > 16 * 1024 * 1024 {
            return Err(Error::Encrypt("byte string too large".into()));
        }
        Ok(self.take(len)?.to_vec())
    }
    pub fn read_str(&mut self) -> Result<String> {
        let len = self.read_u16()? as usize;
        if len > 8192 {
            return Err(Error::Encrypt("utf8 string too large".into()));
        }
        let s = self.take(len)?;
        String::from_utf8(s.to_vec()).map_err(|_| Error::Encrypt("invalid utf8".into()))
    }
    pub fn read_opt_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        match self.read_u8()? {
            0x00 => Ok(None),
            0x01 => Ok(Some(self.read_bytes()?)),
            o => Err(Error::Encrypt(format!("bad presence byte 0x{o:02x}"))),
        }
    }
}
