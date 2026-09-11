//! Vault reader/writer (VAULT_FORMAT.md §3-§7).
//!
//! Layout (bytes on disk):
//!   [0    .. 117]      header
//!   [117  .. 117+16 ]  index outer frame (12B nonce || 4B ct_len; ct+tag inline)
//!   [..   ..       ]   items region: u32 slot_count || per-slot frames
//!   [last 8       ]    trailer: u32 slot_count || u32 crc32c
//!
//! All AEADs use the cipher declared in the header. The index AAD is
//! `vault_version || 0x49`; each item's AAD is `vault_version || 0x53 || item_id_be`,
//! matching CRYPTO_SPEC §5's domain separation.

use std::path::{Path, PathBuf};

use crate::crypto::ciphers::{AeadCipher, Algorithm, NONCE_LEN};
use crate::crypto::error::{Error, Result};
use crate::crypto::kdf::{KdfParams, SecretVec};
use crate::crypto::keys::{random_dek, random_salt};
use crate::vault::atomic_write::atomic_write;
use crate::vault::parse::{self, ParsedHeader, HEADER_LEN, WRAPPED_DEK_CIPHER_LEN, WRAP_TAG_LEN};
use crate::vault::shape::{
    parse_index, parse_item, serialize_index, serialize_item, IndexEntry, IndexPayload, ItemRecord,
};

// Drop orphan reference to shape module (was needed in earlier draft, now unused).

/// Build AEAD AAD for the index ciphertext: `[version || 0x49 ('I')]`.
pub fn index_aad(version: u8) -> [u8; 2] {
    [version, 0x49]
}

/// Build AEAD AAD for an item ciphertext: `[version || 0x53 ('S') || item_id_be(u32)]`.
pub fn item_aad(version: u8, item_id: u32) -> [u8; 6] {
    let mut a = [0u8; 6];
    a[0] = version;
    a[1] = 0x53;
    a[2..6].copy_from_slice(&item_id.to_be_bytes());
    a
}

pub const INDEX_NONCE_LEN: usize = NONCE_LEN;
const SLOT_FRAME_FOOTER: usize = 16; // AEAD tag after every item ciphertext

fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut n = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut n).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(n)
}

/// In-memory vault with the index decrypted. Item payloads are decrypted lazily
/// (in `open_item` / `store_item`) so `list` doesn't materialize secrets.
pub struct Vault {
    pub path: PathBuf,
    /// Public crypto config reflected from the header.
    pub header: VaultCryptoConfig,
    /// DEK, in-memory only, wrapped on drop (zeroize via SecretVec).
    pub dek: SecretVec,
    /// Index — encrypted metadata. Items are not decrypted here.
    pub entries: Vec<IndexEntry>,
    /// Decrypted items, slot → record. Populated by `open_item`.
    pub open_items: std::collections::BTreeMap<u32, ItemRecord>,
    /// One-past-highest used item_id (monotonic, never reused).
    pub next_item_id: u32,
}

#[derive(Clone, Debug)]
pub struct VaultCryptoConfig {
    pub version: u8,
    pub wrap_alg: Algorithm,
    pub item_alg: Algorithm,
    pub kdf_params: KdfParams,
    pub kdf_salt: [u8; SALT_LEN_CONST],
    pub enc_counter: u32,
}

const SALT_LEN_CONST: usize = crate::crypto::kdf::SALT_LEN;

impl Vault {
    /// Create a brand-new vault file at `path`. Caller chooses algorithms.
    /// `kdf_params` should come from `KdfParams::default()` (production) or test values.
    pub fn create(
        path: &Path,
        password: &SecretVec,
        kdf_params: KdfParams,
        wrap_alg: Algorithm,
        item_alg: Algorithm,
    ) -> Result<Self> {
        let kdf_salt = random_salt();
        let kdf = crate::crypto::kdf::Kdf::new(kdf_params);
        let kek = kdf.derive(password, &kdf_salt)?;

        // Generate DEK
        let dek_vec = random_dek().to_vec();
        let dek: SecretVec = SecretVec::new(dek_vec.clone().into_boxed_slice());

        // Wrap the DEK (zero nonce for v1 — one wrap per KEK lifetime)
        let wrap_cipher = AeadCipher::new(wrap_alg);
        let wrap_nonce = [0u8; NONCE_LEN]; // VAULT_FORMAT §4.2: zero in v1
        let placeholder = ParsedHeader {
            version: parse::CURRENT_VERSION,
            kdf_id: 0x01,
            wrap_alg_id: wrap_alg.id(),
            item_alg_id: item_alg.id(),
            reserved: [0, 0, 0],
            argon2_m_mib: kdf_params.argon2_m_mib,
            argon2_t: kdf_params.argon2_t,
            argon2_p: kdf_params.argon2_p,
            kdf_salt,
            enc_counter: 0,
            wrap_nonce,
            wrapped_dek: [0u8; WRAPPED_DEK_CIPHER_LEN],
            wrap_tag: [0u8; WRAP_TAG_LEN],
            future_pad: [0u8; parse::FUTURE_PAD_LEN],
        };
        let aad = parse::header_aad(&placeholder);
        let ct_with_tag = wrap_cipher.encrypt_raw(&kek, &wrap_nonce, &dek_vec, &aad)?;
        debug_assert_eq!(ct_with_tag.len(), WRAPPED_DEK_CIPHER_LEN + WRAP_TAG_LEN);
        let mut wrapped_dek = [0u8; WRAPPED_DEK_CIPHER_LEN];
        wrapped_dek.copy_from_slice(&ct_with_tag[..WRAPPED_DEK_CIPHER_LEN]);
        let mut wrap_tag = [0u8; WRAP_TAG_LEN];
        wrap_tag.copy_from_slice(&ct_with_tag[WRAPPED_DEK_CIPHER_LEN..]);

        let header = ParsedHeader {
            wrapped_dek,
            wrap_tag,
            ..placeholder
        };
        let this = Self {
            path: path.to_path_buf(),
            header: VaultCryptoConfig {
                version: header.version,
                wrap_alg,
                item_alg,
                kdf_params,
                kdf_salt,
                enc_counter: 0,
            },
            dek,
            entries: Vec::new(),
            open_items: Default::default(),
            next_item_id: 1,
        };

        // Serialize and atomically write
        this.save_with_header(&header)?;
        Ok(this)
    }

    /// Open an existing vault: parse + KDF + unwrap DEK + decrypt index.
    /// Item payloads are NOT decrypted yet.
    pub fn open(path: &Path, password: &SecretVec) -> Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::Encrypt(format!("read vault {}: {e}", path.display())))?;
        let header = parse::parse_header(&bytes)?;

        let kdf_params = header.kdf_params();
        let kdf = crate::crypto::kdf::Kdf::new(kdf_params);
        let kek = kdf.derive(password, &header.kdf_salt)?;

        let wrap_cipher = AeadCipher::new(header.wrap_algorithm()?);
        // wrapped_dek + wrap_tag together form the AEAD ciphertext (ct || tag)
        let mut ct_with_tag = Vec::with_capacity(WRAPPED_DEK_CIPHER_LEN + WRAP_TAG_LEN);
        ct_with_tag.extend_from_slice(&header.wrapped_dek);
        ct_with_tag.extend_from_slice(&header.wrap_tag);
        let aad = parse::header_aad(&header);
        let dek_vec = wrap_cipher.decrypt_raw(&kek, &header.wrap_nonce, &ct_with_tag, &aad)?;
        if dek_vec.len() != crate::crypto::ciphers::DEK_LEN {
            return Err(Error::KeyLength {
                expected: 32,
                actual: dek_vec.len(),
            });
        }
        let dek: SecretVec = SecretVec::new(dek_vec.into_boxed_slice());

        // Index
        let item_alg = header.item_algorithm()?;
        let mut cursor = HEADER_LEN;
        let index_nonce: [u8; NONCE_LEN] = bytes
            .get(cursor..cursor + NONCE_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| Error::Encrypt("truncated index nonce".into()))?;
        cursor += NONCE_LEN;
        let index_ct_len = be_u32_at(&bytes, cursor)?;
        cursor += 4;
        let index_ct = bytes
            .get(cursor..cursor + index_ct_len as usize)
            .ok_or_else(|| Error::Encrypt("truncated index ciphertext".into()))?;
        let index_pt = AeadCipher::new(item_alg).decrypt_raw(
            &dek,
            &index_nonce,
            index_ct,
            &index_aad(header.version),
        )?;
        let index = parse_index(&index_pt)?;

        let next_item_id = index
            .entries
            .iter()
            .map(|e| e.item_id)
            .max()
            .map_or(1, |m| m + 1);

        Ok(Self {
            path: path.to_path_buf(),
            header: VaultCryptoConfig {
                version: header.version,
                wrap_alg: header.wrap_algorithm()?,
                item_alg,
                kdf_params,
                kdf_salt: header.kdf_salt,
                enc_counter: header.enc_counter,
            },
            dek,
            entries: index.entries,
            open_items: Default::default(),
            next_item_id,
        })
    }

    /// Decrypt one item into `open_items`.
    pub fn open_item(&mut self, item_id: u32) -> Result<()> {
        if let Some(entry) = self
            .entries
            .iter()
            .find(|e| e.item_id == item_id && e.state != 0xFF)
        {
            let slot = entry.slot;
            if self.open_items.contains_key(&slot) {
                return Ok(());
            }

            // Re-read the vault bytes — we don't keep them in memory.
            let bytes = std::fs::read(&self.path)
                .map_err(|e| Error::Encrypt(format!("read vault: {e}")))?;

            // Skip past index frame
            let mut cursor = HEADER_LEN + NONCE_LEN;
            let index_ct_len = be_u32_at(&bytes, cursor)? as usize;
            cursor += 4 + index_ct_len;

            // Items region header
            let slot_count = be_u32_at(&bytes, cursor)? as usize;
            cursor += 4;

            // Walk to the desired slot
            let mut target: Option<(usize, usize)> = None; // (ct_off, ct_len)
            for i in 0..slot_count {
                let frame_off = cursor;
                cursor += NONCE_LEN;
                let ct_len = be_u32_at(&bytes, cursor)? as usize;
                cursor += 4;
                let ct_off = cursor;
                cursor += ct_len + SLOT_FRAME_FOOTER;
                if i as u32 == slot {
                    target = Some((ct_off, ct_len));
                    break;
                }
                let _ = frame_off;
            }
            let (ct_off, ct_len) =
                target.ok_or_else(|| Error::Encrypt(format!("slot {slot} out of range")))?;

            let nonce_off = ct_off - NONCE_LEN - 4;
            let nonce: [u8; NONCE_LEN] =
                bytes[nonce_off..nonce_off + NONCE_LEN].try_into().unwrap();
            let ct = &bytes[ct_off..ct_off + ct_len];

            let item_alg = self.header.item_alg;
            let cipher = AeadCipher::new(item_alg);
            let pt = cipher.decrypt_raw(
                &self.dek,
                &nonce,
                ct,
                &item_aad(self.header.version, item_id),
            )?;
            let (record, embedded_id) = parse_item(&pt)?;
            if embedded_id != item_id {
                return Err(Error::Encrypt(format!(
                    "item id mismatch: index={item_id}, body={embedded_id}"
                )));
            }
            self.open_items.insert(slot, record);
            Ok(())
        } else {
            Err(Error::Encrypt(format!("no such item {item_id}")))
        }
    }

    /// Serialize the full vault from in-memory state, and atomically write.
    /// Caller must have `open_items` populated for every slot referenced in `entries`.
    pub fn save(&self) -> Result<()> {
        // Reuse the on-disk wrap material (salt, KDF params, wrapped_dek, wrap_tag). Only
        // the index and items change between saves. KDF rekey / DEK rotation are separate.
        let raw = std::fs::read(&self.path)
            .map_err(|e| Error::Encrypt(format!("read vault for save: {e}")))?;
        let old = parse::parse_header(&raw)?;
        let new_header = ParsedHeader { ..old.clone() };
        self.save_with_header(&new_header)
    }

    /// Write the entire file from (header, entries, open_items). The header's wrap
    /// material and salt must already be final; only enc_counter/index/items vary.
    fn save_with_header(&self, header: &ParsedHeader) -> Result<()> {
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(&parse::build_header(header));

        // Index
        let index_pt = serialize_index(&IndexPayload {
            entries: self.entries.clone(),
        });
        let index_nonce = random_nonce()?;
        let index_ct = AeadCipher::new(self.header.item_alg).encrypt_raw(
            &self.dek,
            &index_nonce,
            &index_pt,
            &index_aad(header.version),
        )?;
        out.extend_from_slice(&index_nonce);
        out.extend_from_slice(&(index_ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&index_ct);

        // Items region (ordered by slot)
        let live_count = self.entries.iter().filter(|e| e.state != 0xFF).count() as u32;
        out.extend_from_slice(&live_count.to_be_bytes());
        let mut live: Vec<&IndexEntry> = self.entries.iter().filter(|e| e.state != 0xFF).collect();
        live.sort_by_key(|e| e.slot);
        for e in &live {
            let rec = self
                .open_items
                .get(&e.slot)
                .ok_or_else(|| Error::Encrypt(format!("slot {} not open", e.slot)))?;
            let pt = serialize_item(rec, e.item_id);
            let nonce = random_nonce()?;
            let ct = AeadCipher::new(self.header.item_alg).encrypt_raw(
                &self.dek,
                &nonce,
                &pt,
                &item_aad(header.version, e.item_id),
            )?;
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
            out.extend_from_slice(&ct);
        }

        // Trailer (spec §7): u32 slot_count || u32 crc32c over the whole preceding file.
        let crc = crc32c::crc32c(&out);
        out.extend_from_slice(&live_count.to_be_bytes());
        out.extend_from_slice(&crc.to_be_bytes());

        atomic_write(&self.path, &out)
    }

    pub fn add_item(&mut self, title: String, username: String, record: ItemRecord) -> Result<u32> {
        let item_id = self.next_item_id;
        self.next_item_id = self
            .next_item_id
            .checked_add(1)
            .ok_or_else(|| Error::Encrypt("item_id space exhausted".into()))?;
        let slot = self
            .entries
            .iter()
            .filter(|e| e.state != 0xFF)
            .map(|e| e.slot)
            .max()
            .map_or(0, |m| m + 1);
        self.entries.push(IndexEntry {
            item_id,
            slot,
            state: 0x01,
            title,
            username,
        });
        self.open_items.insert(slot, record);
        Ok(item_id)
    }
}

fn be_u32_at(b: &[u8], off: usize) -> Result<u32> {
    b.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| Error::Encrypt("truncated u32".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;

    fn pswd(s: &str) -> SecretVec {
        SecretVec::new(s.as_bytes().to_vec().into_boxed_slice())
    }

    #[test]
    fn create_open_roundtrip_empty() {
        let tmp = std::env::temp_dir().join(format!("rpass_v_rt_{}.rpass", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let kdf_params = KdfParams::new(8, 1, 1).unwrap();
        let password = pswd("test-password");
        {
            let _ = Vault::create(
                &tmp,
                &password,
                kdf_params.clone(),
                Algorithm::Aes256Gcm,
                Algorithm::Aes256Gcm,
            )
            .unwrap();
        }
        let v = Vault::open(&tmp, &password).unwrap();
        assert!(v.entries.is_empty());
        assert_eq!(v.next_item_id, 1);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn wrong_password_rejected() {
        let tmp = std::env::temp_dir().join(format!("rpass_v_wp_{}.rpass", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let kdf_params = KdfParams::new(8, 1, 1).unwrap();
        let right = pswd("right");
        Vault::create(
            &tmp,
            &right,
            kdf_params,
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        let wrong = pswd("wrong");
        assert!(Vault::open(&tmp, &wrong).is_err());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn add_get_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("rpass_v_ag_{}.rpass", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let kdf_params = KdfParams::new(8, 1, 1).unwrap();
        let password = pswd("pw");
        let mut v = Vault::create(
            &tmp,
            &password,
            kdf_params,
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        let rec = ItemRecord {
            password: Some(b"hunter2".to_vec()),
            url: "https://example.com".to_string(),
            notes: None,
            totp: None,
            created_unix: 1,
            modified_unix: 1,
        };
        let id = v
            .add_item("example".to_string(), "alice".to_string(), rec.clone())
            .unwrap();
        v.save().unwrap();
        drop(v);

        let mut v2 = Vault::open(&tmp, &password).unwrap();
        v2.open_item(id).unwrap();
        let rec2 = v2.open_items.values().next().unwrap();
        assert_eq!(*rec2, rec);
        let _ = std::fs::remove_file(&tmp);
    }
}
