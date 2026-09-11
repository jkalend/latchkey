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

use secrecy::ExposeSecret;

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
        this.save_with_header(&header, &this.dek)?;
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
        let (entries, _) = Self::read_index_entries_with(&bytes, &header, &dek, item_alg)?;
        let index = IndexPayload { entries };

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

            // Walk the items region; frame position == slot (save renumbers
            // densely, so the index's slot is a direct frame index).
            let frames = Self::split_item_frames(&bytes)?;
            let frame = frames
                .get(slot as usize)
                .ok_or_else(|| Error::Encrypt(format!("slot {slot} out of range")))?;

            let nonce: [u8; NONCE_LEN] = frame[..NONCE_LEN].try_into().unwrap();
            let ct_len =
                u32::from_be_bytes(frame[NONCE_LEN..NONCE_LEN + 4].try_into().unwrap()) as usize;
            let ct = &frame[NONCE_LEN + 4..NONCE_LEN + 4 + ct_len];

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
        self.save_with_header(&new_header, &self.dek)
    }

    /// Write the entire file from (header, entries, open_items). The header's wrap
    /// material and salt must already be final; only enc_counter/index/items vary.
    ///
    /// `disk_dek` is the DEK the on-disk file's index/items are encrypted with —
    /// it equals `self.dek` for ordinary saves, but differs after `rotate()`
    /// (the old file is still old-DEK-encrypted until we overwrite it).
    ///
    /// Items NOT in `open_items` are copied verbatim from the on-disk file —
    /// deleting or editing one item must not require decrypting every other.
    /// Every save renumbers slots densely (frame position = slot), so the
    /// index's `slot` fields are regenerated here, not trusted from callers.
    fn save_with_header(&self, header: &ParsedHeader, disk_dek: &SecretVec) -> Result<()> {
        // A vault being created has no prior file — nothing to copy frames from.
        let old = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(Error::Encrypt(format!("read vault for save: {e}"))),
        };
        // item_id → frame position on disk, derived by decrypting the OLD
        // index (we hold the DEK; titles are already known to us in-memory —
        // this just maps identity to position without touching item secrets).
        let old_index: std::collections::HashMap<u32, u32> = if old.is_empty() {
            Default::default()
        } else {
            let old_header = parse::parse_header(&old)?;
            let old_alg = old_header.item_algorithm()?;
            let (old_entries, _) =
                Self::read_index_entries_with(&old, &old_header, disk_dek, old_alg)?;
            old_entries
                .into_iter()
                .filter(|e| e.state != 0xFF)
                .map(|e| (e.item_id, e.slot))
                .collect()
        };
        let old_frames: Vec<Vec<u8>> = if old.is_empty() {
            Vec::new()
        } else {
            Self::split_item_frames(&old)?
        };

        let mut out = Vec::with_capacity(old.len());
        out.extend_from_slice(&parse::build_header(header));

        // Live entries in index order; renumber slots to frame position.
        let live: Vec<IndexEntry> = self
            .entries
            .iter()
            .filter(|e| e.state != 0xFF)
            .cloned()
            .collect();
        let renumbered: Vec<IndexEntry> = live
            .iter()
            .enumerate()
            .map(|(i, e)| IndexEntry {
                slot: i as u32,
                ..e.clone()
            })
            .collect();

        // Index
        let index_pt = serialize_index(&IndexPayload {
            entries: renumbered.clone(),
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

        // Items region. open_items is keyed by each entry's CURRENT slot (as
        // last written/read); the dense renumbered slot only becomes valid
        // once this save lands — look up by the original slot.
        out.extend_from_slice(&(renumbered.len() as u32).to_be_bytes());
        for (e, orig) in renumbered.iter().zip(live.iter()) {
            match self.open_items.get(&orig.slot) {
                Some(rec) => {
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
                None => {
                    // Not open: copy the existing frame verbatim.
                    let old_slot = old_index.get(&e.item_id).ok_or_else(|| {
                        Error::Encrypt(format!(
                            "item {} not open and not on disk — open it before saving",
                            e.item_id
                        ))
                    })?;
                    let frame = &old_frames[*old_slot as usize];
                    out.extend_from_slice(frame);
                }
            }
        }

        // Trailer (spec §7): u32 slot_count || u32 crc32c over the whole preceding file.
        let crc = crc32c::crc32c(&out);
        out.extend_from_slice(&(renumbered.len() as u32).to_be_bytes());
        out.extend_from_slice(&crc.to_be_bytes());

        atomic_write(&self.path, &out)
    }

    /// Split an on-disk vault into (per-slot frames, item_id → slot map).
    /// Frames include the full nonce || ct_len || ct || tag bytes.
    /// Decrypt the index from raw vault bytes. Returns (entries, end offset of
    /// the index frame) — the offset is where the items region starts.
    fn read_index_entries_with(
        raw: &[u8],
        header: &parse::ParsedHeader,
        dek: &SecretVec,
        item_alg: Algorithm,
    ) -> Result<(Vec<IndexEntry>, usize)> {
        let mut cursor = HEADER_LEN;
        let index_nonce: [u8; NONCE_LEN] = raw
            .get(cursor..cursor + NONCE_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| Error::Encrypt("truncated index nonce".into()))?;
        cursor += NONCE_LEN;
        let index_ct_len = be_u32_at(raw, cursor)? as usize;
        cursor += 4;
        let index_ct = raw
            .get(cursor..cursor + index_ct_len)
            .ok_or_else(|| Error::Encrypt("truncated index ciphertext".into()))?;
        let index_pt = AeadCipher::new(item_alg).decrypt_raw(
            dek,
            &index_nonce,
            index_ct,
            &index_aad(header.version),
        )?;
        let index = parse_index(&index_pt)?;
        Ok((index.entries, cursor + index_ct_len))
    }

    /// Split an on-disk vault into per-slot item frames (nonce || ct_len ||
    /// ciphertext+tag). Frame position == slot after any save (slots are
    /// renumbered densely on write).
    fn split_item_frames(raw: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut cursor = HEADER_LEN + NONCE_LEN;
        let index_ct_len = be_u32_at(raw, cursor)? as usize;
        cursor += 4 + index_ct_len;
        let slot_count = be_u32_at(raw, cursor)? as usize;
        cursor += 4;

        let mut frames = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            let start = cursor;
            cursor += NONCE_LEN;
            let ct_len = be_u32_at(raw, cursor)? as usize;
            // ct_len covers ciphertext + AEAD tag (the aead crate appends the
            // tag to the ciphertext; VAULT_FORMAT §6.1's separate "16 tag"
            // field is subsumed into ct_len in this implementation).
            cursor += 4 + ct_len;
            frames.push(raw[start..cursor].to_vec());
        }
        Ok(frames)
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

    /// Rotate the DEK and re-wrap under the CURRENT default KDF params and a
    /// fresh salt (CLI_REFERENCE `rpass rotate`). Every live item is re-encrypted
    /// under the new DEK — unlike `save()`, this is a full rewrite, so the
    /// caller must first `open_item()` everything (or pass nothing to open and
    /// let unopened frames copy verbatim — but their ciphertext then stays on
    /// the old DEK, which defeats rotation, so we require all items open).
    pub fn rotate(&mut self, password: &SecretVec) -> Result<()> {
        // Snapshot the old DEK: the on-disk file is still encrypted with it,
        // and save_with_header needs it to decrypt the old index.
        let old_dek = SecretVec::new(self.dek.expose_secret().to_vec().into_boxed_slice());

        let new_params = KdfParams::default();
        let kdf_salt = random_salt();
        let kdf = crate::crypto::kdf::Kdf::new(new_params);
        let kek = kdf.derive(password, &kdf_salt)?;

        let new_dek = random_dek();
        let wrap_cipher = AeadCipher::new(self.header.wrap_alg);
        let wrap_nonce = [0u8; NONCE_LEN];
        let mut placeholder = ParsedHeader {
            version: self.header.version,
            kdf_id: 0x01,
            wrap_alg_id: self.header.wrap_alg.id(),
            item_alg_id: self.header.item_alg.id(),
            reserved: [0, 0, 0],
            argon2_m_mib: new_params.argon2_m_mib,
            argon2_t: new_params.argon2_t,
            argon2_p: new_params.argon2_p,
            kdf_salt,
            enc_counter: 0,
            wrap_nonce,
            wrapped_dek: [0u8; WRAPPED_DEK_CIPHER_LEN],
            wrap_tag: [0u8; WRAP_TAG_LEN],
            future_pad: [0u8; parse::FUTURE_PAD_LEN],
        };
        let aad = parse::header_aad(&placeholder);
        let dek_vec = new_dek.to_vec();
        let ct_with_tag = wrap_cipher.encrypt_raw(&kek, &wrap_nonce, &dek_vec, &aad)?;
        debug_assert_eq!(ct_with_tag.len(), WRAPPED_DEK_CIPHER_LEN + WRAP_TAG_LEN);
        let mut wrapped_dek = [0u8; WRAPPED_DEK_CIPHER_LEN];
        wrapped_dek.copy_from_slice(&ct_with_tag[..WRAPPED_DEK_CIPHER_LEN]);
        let mut wrap_tag = [0u8; WRAP_TAG_LEN];
        wrap_tag.copy_from_slice(&ct_with_tag[WRAPPED_DEK_CIPHER_LEN..]);
        placeholder.wrapped_dek = wrapped_dek;
        placeholder.wrap_tag = wrap_tag;

        // Swap the in-memory state over to the new key material BEFORE the
        // save, so every open item re-encrypts under the new DEK.
        self.dek = SecretVec::new(dek_vec.into_boxed_slice());
        self.header.kdf_params = new_params;
        self.header.kdf_salt = kdf_salt;
        self.header.enc_counter = 0;

        self.save_with_header(&placeholder, &old_dek)
    }

    /// Change the master password: same DEK, re-wrapped under a KEK derived
    /// from the new password (and fresh salt/current-policy KDF params).
    /// Item ciphertext is untouched — only the header's wrap material changes.
    pub fn change_password(&mut self, new_password: &SecretVec) -> Result<()> {
        let new_params = KdfParams::default();
        let kdf_salt = random_salt();
        let kdf = crate::crypto::kdf::Kdf::new(new_params);
        let new_kek = kdf.derive(new_password, &kdf_salt)?;

        let old = std::fs::read(&self.path)
            .map_err(|e| Error::Encrypt(format!("read vault for save: {e}")))?;
        let mut header = parse::parse_header(&old)?;
        let wrap_cipher = AeadCipher::new(self.header.wrap_alg);
        let dek_copy: [u8; crate::crypto::ciphers::DEK_LEN] = self
            .dek
            .expose_secret()
            .as_ref()
            .try_into()
            .map_err(|_| Error::KeyLength {
                expected: 32,
                actual: self.dek.expose_secret().len(),
            })?;
        let dek_box = SecretVec::new(dek_copy.to_vec().into_boxed_slice());
        let wrap_nonce = [0u8; NONCE_LEN];

        // The header AAD covers bytes 4..51 — KDF params and salt live inside
        // that range, so build the final header first, then wrap against it.
        header.kdf_salt = kdf_salt;
        header.argon2_m_mib = new_params.argon2_m_mib;
        header.argon2_t = new_params.argon2_t;
        header.argon2_p = new_params.argon2_p;
        header.enc_counter = 0;
        header.wrap_nonce = wrap_nonce;
        let aad = parse::header_aad(&header);
        let ct_with_tag =
            wrap_cipher.encrypt_raw(&new_kek, &wrap_nonce, dek_box.expose_secret(), &aad)?;
        let mut wrapped_dek = [0u8; WRAPPED_DEK_CIPHER_LEN];
        wrapped_dek.copy_from_slice(&ct_with_tag[..WRAPPED_DEK_CIPHER_LEN]);
        let mut wrap_tag = [0u8; WRAP_TAG_LEN];
        wrap_tag.copy_from_slice(&ct_with_tag[WRAPPED_DEK_CIPHER_LEN..]);
        header.wrapped_dek = wrapped_dek;
        header.wrap_tag = wrap_tag;

        self.header.kdf_params = new_params;
        self.header.kdf_salt = kdf_salt;
        self.header.enc_counter = 0;
        self.save_with_header(&header, &self.dek)
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
                kdf_params,
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
