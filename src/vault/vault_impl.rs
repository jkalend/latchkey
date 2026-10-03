//! Vault reader/writer (VAULT_FORMAT.md §3-§7).
//!
//! Layout (bytes on disk):
//!   [0    .. 117]      header
//!   [117  .. 117+16 ]  index outer frame (12B nonce || 4B ct_len; ct+tag inline)
//!   [..   ..       ]   items region: u32 slot_count || per-slot frames
//!   [last 40      ]    trailer: u32 slot_count || u32 crc32c || 32B file MAC
//!
//! All AEADs use the cipher declared in the header. The index AAD is
//! `vault_version || 0x49`; each item's AAD is `vault_version || 0x53 || item_id_be`,
//! matching CRYPTO_SPEC §5's domain separation.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use secrecy::ExposeSecret;

use crate::crypto::ciphers::{AeadCipher, Algorithm, NONCE_LEN};
use crate::crypto::error::{Error, Result};
use crate::crypto::kdf::{KdfParams, SecretVec};
use crate::crypto::keys::{random_dek, random_salt};
use crate::vault::atomic_write::{acquire_write_lock, atomic_create_locked, atomic_write_locked};
use crate::vault::parse::{self, ParsedHeader, HEADER_LEN, WRAPPED_DEK_CIPHER_LEN, WRAP_TAG_LEN};
use crate::vault::shape::{
    parse_index, parse_item, serialize_index, serialize_item, IndexEntry, IndexPayload, ItemRecord,
    LIVE_STATE, TOMBSTONE_STATE,
};

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

const FRAME_LAYOUT_V2: u8 = 0xA5;
const TRAILER_LEN: usize = 40;
const FILE_MAC_LEN: usize = 32;
const ROTATION_LIMIT: u32 = 1 << 24;
#[cfg(not(test))]
const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(test)]
const MAX_VAULT_BYTES: u64 = 1024 * 1024;

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
    /// KEK and DEK, in-memory only, zeroized on drop.
    kek: SecretVec,
    pub dek: SecretVec,
    /// Index — encrypted metadata. Items are not decrypted here.
    pub entries: Vec<IndexEntry>,
    /// Decrypted items, slot → record. Populated by `open_item`.
    pub open_items: std::collections::BTreeMap<u32, ItemRecord>,
    /// One-past-highest used item_id (monotonic, never reused).
    pub next_item_id: u32,
    /// Authenticated full-file commit identity; CRC is not a security boundary.
    last_disk_tag: Option<[u8; FILE_MAC_LEN]>,
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
        kdf_params.validate_policy()?;
        let kdf_salt = random_salt();
        let kdf = crate::crypto::kdf::Kdf::new(kdf_params);
        let kek = kdf.derive(password, &kdf_salt)?;

        // Generate DEK
        let dek_vec = Zeroizing::new(random_dek().to_vec());
        let dek: SecretVec = SecretVec::new(dek_vec.as_slice().to_vec().into_boxed_slice());

        // Randomize the KEK-wrapping nonce for every new vault.
        let wrap_cipher = AeadCipher::new(wrap_alg);
        let wrap_nonce = random_nonce()?;
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
        let mut this = Self {
            path: path.to_path_buf(),
            header: VaultCryptoConfig {
                version: header.version,
                wrap_alg,
                item_alg,
                kdf_params,
                kdf_salt,
                enc_counter: 0,
            },
            kek,
            dek,
            entries: Vec::new(),
            open_items: Default::default(),
            next_item_id: 1,
            last_disk_tag: None,
        };

        // Serialize and atomically write.
        let disk_dek = this.dek.clone();
        this.save_with_header(&header, &disk_dek)?;
        Ok(this)
    }

    /// Open an existing vault: parse + KDF + unwrap DEK + decrypt index.
    /// Item payloads are NOT decrypted yet.
    pub fn open(path: &Path, password: &SecretVec) -> Result<Self> {
        Self::open_with_version(path, password, false)
    }

    fn open_with_version(path: &Path, password: &SecretVec, legacy: bool) -> Result<Self> {
        let bytes = read_vault_bytes(path)?;
        Self::open_bytes(path, password, &bytes, legacy)
    }

    fn open_bytes(path: &Path, password: &SecretVec, bytes: &[u8], legacy: bool) -> Result<Self> {
        let header = if legacy {
            parse::parse_legacy_header(bytes)?
        } else {
            parse::parse_header(bytes)?
        };

        let kdf_params = header.kdf_params();
        kdf_params.validate_policy()?;
        let kdf = crate::crypto::kdf::Kdf::new(kdf_params);
        let kek = kdf.derive(password, &header.kdf_salt)?;

        let wrap_cipher = AeadCipher::new(header.wrap_algorithm()?);
        // wrapped_dek + wrap_tag together form the AEAD ciphertext (ct || tag)
        let mut ct_with_tag = Vec::with_capacity(WRAPPED_DEK_CIPHER_LEN + WRAP_TAG_LEN);
        ct_with_tag.extend_from_slice(&header.wrapped_dek);
        ct_with_tag.extend_from_slice(&header.wrap_tag);
        let aad = parse::header_aad(&header);
        let mut dek_vec = Zeroizing::new(wrap_cipher.decrypt_raw(
            &kek,
            &header.wrap_nonce,
            &ct_with_tag,
            &aad,
        )?);
        if dek_vec.len() != crate::crypto::ciphers::DEK_LEN {
            return Err(Error::KeyLength {
                expected: 32,
                actual: dek_vec.len(),
            });
        }
        let dek: SecretVec = SecretVec::new(std::mem::take(&mut *dek_vec).into_boxed_slice());
        let commit_tag = if legacy {
            let trailer = bytes
                .len()
                .checked_sub(8)
                .ok_or_else(|| Error::Encrypt("truncated legacy trailer".into()))?;
            if crc32c::crc32c(&bytes[..trailer]) != be_u32_at(bytes, trailer + 4)? {
                return Err(Error::Encrypt("legacy vault CRC mismatch".into()));
            }
            None
        } else {
            Some(authenticate_snapshot(bytes, &dek)?)
        };

        // Index
        let item_alg = header.item_algorithm()?;
        let (entries, _) = Self::read_index_entries_with(bytes, &header, &dek, item_alg)?;
        let index = IndexPayload { entries };

        // The trailer count must match the number of serialized item slots.
        let frames = if legacy {
            Self::split_item_frames_with_layout(bytes, header.reserved[0] == FRAME_LAYOUT_V2, 8)?
        } else {
            Self::split_item_frames_with_layout(bytes, true, TRAILER_LEN)?
        };
        if frames.len() != index.entries.len() {
            return Err(Error::Encrypt(
                "slot count mismatch between index and items region".into(),
            ));
        }

        let next_item_id = match index.entries.iter().map(|e| e.item_id).max() {
            Some(m) => m
                .checked_add(1)
                .ok_or_else(|| Error::Encrypt("item_id space exhausted".into()))?,
            None => 1,
        };

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
            kek,
            dek,
            entries: index.entries,
            open_items: Default::default(),
            next_item_id,
            last_disk_tag: commit_tag,
        })
    }

    /// Explicitly migrate v1, verifying every record and publishing a fresh v2
    /// vault without replacing any existing target. The source is never written.
    pub fn migrate(source: &Path, target: &Path, password: &SecretVec) -> Result<Self> {
        let _lock = acquire_write_lock(target)?;
        match std::fs::symlink_metadata(target) {
            Ok(_) => return Err(Error::Encrypt("migration target already exists".into())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Encrypt(format!("inspect migration target: {error}"))),
        }
        let bytes = read_vault_bytes(source)?;
        let mut vault = Self::open_bytes(source, password, &bytes, true)?;
        let legacy_header = parse::parse_legacy_header(&bytes)?;
        let frames = Self::split_item_frames_with_layout(
            &bytes,
            legacy_header.reserved[0] == FRAME_LAYOUT_V2,
            8,
        )?;
        let mut seen = vec![false; frames.len()];
        for entry in &vault.entries {
            let slot = entry.slot as usize;
            let frame = frames
                .get(slot)
                .ok_or_else(|| Error::Encrypt("legacy item slot out of range".into()))?;
            if std::mem::replace(&mut seen[slot], true) {
                return Err(Error::Encrypt("duplicate legacy item slot".into()));
            }
            let record = vault.decrypt_item_frame(frame, entry.item_id)?;
            vault.open_items.insert(entry.slot, record);
        }
        let params = KdfParams::default();
        let salt = random_salt();
        vault.kek = crate::crypto::kdf::Kdf::new(params).derive(password, &salt)?;
        vault.dek = SecretVec::new(random_dek().to_vec().into_boxed_slice());
        vault.path = target.to_path_buf();
        vault.header.version = parse::CURRENT_VERSION;
        vault.header.kdf_params = params;
        vault.header.kdf_salt = salt;
        vault.header.enc_counter = 0;
        let header = ParsedHeader {
            version: parse::CURRENT_VERSION,
            kdf_id: 1,
            wrap_alg_id: vault.header.wrap_alg.id(),
            item_alg_id: vault.header.item_alg.id(),
            reserved: [0; 3],
            argon2_m_mib: params.argon2_m_mib,
            argon2_t: params.argon2_t,
            argon2_p: params.argon2_p,
            kdf_salt: salt,
            enc_counter: 0,
            wrap_nonce: random_nonce()?,
            wrapped_dek: [0; WRAPPED_DEK_CIPHER_LEN],
            wrap_tag: [0; WRAP_TAG_LEN],
            future_pad: [0; parse::FUTURE_PAD_LEN],
        };
        let disk_dek = vault.dek.clone();
        vault.save_with_header_locked(&header, &disk_dek)?;
        Ok(vault)
    }

    /// One authenticated, immutable disk image for bulk read operations
    /// (export, rotation). The file is read, MAC-verified against the
    /// session's committed tag, and frame-split exactly once; records
    /// decrypt on demand from the image — no per-item re-read.
    pub fn snapshot(&self) -> Result<VaultSnapshot> {
        let bytes = read_vault_bytes(&self.path)?;
        self.authenticate_current(&bytes, &self.dek)?;
        let frames = Self::split_item_frames_with_layout(&bytes, true, TRAILER_LEN)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        if frames.len() != self.entries.len() {
            return Err(Error::Encrypt(
                "index entry count does not match item frame count".into(),
            ));
        }
        Ok(VaultSnapshot {
            header: self.header.clone(),
            dek: self.dek.clone(),
            frames,
        })
    }

    /// Decrypt one item into `open_items`.
    pub fn open_item(&mut self, item_id: u32) -> Result<()> {
        // Even a cached record must not conceal a corrupted or stale disk commit.
        let bytes = read_vault_bytes(&self.path)?;
        self.authenticate_current(&bytes, &self.dek)?;
        if let Some(entry) = self
            .entries
            .iter()
            .find(|e| e.item_id == item_id && e.state == LIVE_STATE)
        {
            let slot = entry.slot;
            if self.open_items.contains_key(&slot) {
                return Ok(());
            }

            // Walk the items region; frame position == slot (save renumbers
            // densely, so the index's slot is a direct frame index).
            let frames = Self::split_item_frames_with_layout(&bytes, true, TRAILER_LEN)?;
            let frame = frames
                .get(slot as usize)
                .ok_or_else(|| Error::Encrypt(format!("slot {slot} out of range")))?;

            let record = self.decrypt_item_frame(frame, item_id)?;
            self.open_items.insert(slot, record);
            Ok(())
        } else {
            Err(Error::Encrypt(format!("no such item {item_id}")))
        }
    }

    /// Authenticate and parse every item frame without retaining plaintext.
    pub fn verify_all_items(&self) -> Result<(usize, usize)> {
        let bytes = read_vault_bytes(&self.path)?;
        self.authenticate_current(&bytes, &self.dek)?;
        let frames = Self::split_item_frames_with_layout(&bytes, true, TRAILER_LEN)?;
        if frames.len() != self.entries.len() {
            return Err(Error::Encrypt(
                "index entry count does not match item frame count".into(),
            ));
        }

        let mut seen_slots = vec![false; frames.len()];
        let mut live = 0;
        let mut tombstones = 0;
        for entry in &self.entries {
            let slot = usize::try_from(entry.slot)
                .map_err(|_| Error::Encrypt("item slot is out of range".into()))?;
            let frame = frames
                .get(slot)
                .ok_or_else(|| Error::Encrypt(format!("slot {} out of range", entry.slot)))?;
            if std::mem::replace(&mut seen_slots[slot], true) {
                return Err(Error::Encrypt(format!(
                    "duplicate item slot {}",
                    entry.slot
                )));
            }
            let record = self.decrypt_item_frame(frame, entry.item_id)?;
            drop(record);
            if entry.state == LIVE_STATE {
                live += 1;
            } else {
                tombstones += 1;
            }
        }
        Ok((live, tombstones))
    }

    fn decrypt_item_frame(&self, frame: &[u8], item_id: u32) -> Result<ItemRecord> {
        decrypt_item_frame_with(
            &self.dek,
            self.header.item_alg,
            self.header.version,
            frame,
            item_id,
        )
    }

    fn authenticate_current(&self, bytes: &[u8], disk_dek: &SecretVec) -> Result<()> {
        let tag = authenticate_snapshot(bytes, disk_dek)?;
        if self.last_disk_tag != Some(tag) {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub fn save(&mut self) -> Result<()> {
        let _lock = acquire_write_lock(&self.path)?;
        let raw = read_vault_bytes(&self.path)?;
        let old = parse::parse_header(&raw)?;
        let disk_dek = self.dek.clone();
        self.save_with_header_locked(&old, &disk_dek)
    }

    /// Acquire the vault write lock before rebuilding the complete file.
    fn save_with_header(&mut self, header: &ParsedHeader, disk_dek: &SecretVec) -> Result<()> {
        let _lock = acquire_write_lock(&self.path)?;
        self.save_with_header_locked(header, disk_dek)
    }

    /// Write the complete file while the caller holds the write lock.
    fn save_with_header_locked(
        &mut self,
        header: &ParsedHeader,
        disk_dek: &SecretVec,
    ) -> Result<()> {
        let old = if self.path.exists() {
            read_vault_bytes(&self.path)?
        } else {
            Vec::new()
        };
        if !old.is_empty() {
            self.authenticate_current(&old, disk_dek)?;
        } else if self.last_disk_tag.is_some() {
            return Err(Error::Stale);
        }
        let old_index: std::collections::HashMap<u32, u32> = if old.is_empty() {
            Default::default()
        } else {
            let old_header = parse::parse_header(&old)?;
            let old_alg = old_header.item_algorithm()?;
            let (entries, _) = Self::read_index_entries_with(&old, &old_header, disk_dek, old_alg)?;
            entries.into_iter().map(|e| (e.item_id, e.slot)).collect()
        };
        let old_frames = if old.is_empty() {
            Vec::new()
        } else {
            Self::split_item_frames_with_layout(&old, true, TRAILER_LEN)?
        };

        let encrypt_count = self
            .entries
            .iter()
            .filter(|e| {
                e.state == TOMBSTONE_STATE
                    || e.state == 0xFF
                    || self.open_items.contains_key(&e.slot)
            })
            .count();
        let encrypt_count = u32::try_from(encrypt_count)
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| Error::Encrypt("encryption counter exhausted; run rotate".into()))?;
        let next_counter = header
            .enc_counter
            .checked_add(encrypt_count)
            .ok_or_else(|| Error::Encrypt("encryption counter exhausted; run rotate".into()))?;
        if next_counter > ROTATION_LIMIT {
            return Err(Error::Encrypt(
                "encryption counter near limit; run rotate".into(),
            ));
        }

        let renumbered: Vec<IndexEntry> = self
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                Ok(IndexEntry {
                    slot: u32::try_from(i)
                        .map_err(|_| Error::Encrypt("too many item slots".into()))?,
                    ..e.clone()
                })
            })
            .collect::<Result<_>>()?;

        // Compute the complete candidate size before encryption or allocation.
        let index_pt = Zeroizing::new(serialize_index(&IndexPayload {
            entries: renumbered.clone(),
        })?);
        let mut candidate_len =
            HEADER_LEN + NONCE_LEN + 4 + index_pt.len() + WRAP_TAG_LEN + 4 + TRAILER_LEN;
        for entry in &self.entries {
            let frame_len = if let Some(record) = self.open_items.get(&entry.slot) {
                crate::vault::shape::validate_item(record)?;
                NONCE_LEN + 4 + item_plaintext_len(record) + WRAP_TAG_LEN
            } else if matches!(entry.state, TOMBSTONE_STATE | 0xFF) {
                NONCE_LEN + 4 + 25 + WRAP_TAG_LEN
            } else {
                let slot = *old_index.get(&entry.item_id).ok_or_else(|| {
                    Error::Encrypt(format!("item {} not open and not on disk", entry.item_id))
                })? as usize;
                old_frames
                    .get(slot)
                    .ok_or_else(|| Error::Encrypt("old item slot out of range".into()))?
                    .len()
            };
            candidate_len = candidate_len
                .checked_add(frame_len)
                .ok_or_else(|| Error::Encrypt("vault size overflow".into()))?;
            ensure_vault_size(candidate_len)?;
        }
        ensure_vault_size(candidate_len)?;

        let mut final_header = header.clone();
        final_header.reserved[0] = FRAME_LAYOUT_V2;
        final_header.enc_counter = next_counter;
        // CRYPTO_SPEC §5: a fresh random wrap nonce on every header write.
        // save() passes the header parsed from disk, so without this the
        // unchanged KEK would re-encrypt the DEK under the previous write's
        // nonce — repeated (KEK, nonce) pairs across successive vault
        // versions are the GCM forbidden-attack setup.
        final_header.wrap_nonce = random_nonce()?;
        let wrap_cipher = AeadCipher::new(final_header.wrap_algorithm()?);
        let wrap_ct = wrap_cipher.encrypt_raw(
            &self.kek,
            &final_header.wrap_nonce,
            self.dek.expose_secret(),
            &parse::header_aad(&final_header),
        )?;
        if wrap_ct.len() != WRAPPED_DEK_CIPHER_LEN + WRAP_TAG_LEN {
            return Err(Error::Encrypt("unexpected wrapped DEK length".into()));
        }
        final_header
            .wrapped_dek
            .copy_from_slice(&wrap_ct[..WRAPPED_DEK_CIPHER_LEN]);
        final_header
            .wrap_tag
            .copy_from_slice(&wrap_ct[WRAPPED_DEK_CIPHER_LEN..]);

        let mut out = Vec::with_capacity(candidate_len);
        out.extend_from_slice(&parse::build_header(&final_header));

        let index_nonce = random_nonce()?;
        let index_ct = AeadCipher::new(final_header.item_algorithm()?).encrypt_raw(
            &self.dek,
            &index_nonce,
            &index_pt,
            &index_aad(final_header.version),
        )?;
        out.extend_from_slice(&index_nonce);
        out.extend_from_slice(&(index_ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&index_ct);

        out.extend_from_slice(&(renumbered.len() as u32).to_be_bytes());
        for (entry, original) in renumbered.iter().zip(self.entries.iter()) {
            if let Some(record) = self.open_items.get(&original.slot) {
                let pt = Zeroizing::new(serialize_item(record, entry.item_id)?);
                let nonce = random_nonce()?;
                let ct_with_tag = AeadCipher::new(final_header.item_algorithm()?).encrypt_raw(
                    &self.dek,
                    &nonce,
                    &pt,
                    &item_aad(final_header.version, entry.item_id),
                )?;
                let split = ct_with_tag
                    .len()
                    .checked_sub(WRAP_TAG_LEN)
                    .ok_or_else(|| Error::Encrypt("short item ciphertext".into()))?;
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&(split as u32).to_be_bytes());
                out.extend_from_slice(&ct_with_tag[..split]);
                out.extend_from_slice(&ct_with_tag[split..]);
            } else if original.state == TOMBSTONE_STATE || original.state == 0xFF {
                let record = ItemRecord {
                    password: None,
                    url: String::new(),
                    notes: None,
                    totp: None,
                    created_unix: 0,
                    modified_unix: 0,
                };
                let pt = Zeroizing::new(serialize_item(&record, entry.item_id)?);
                let nonce = random_nonce()?;
                let ct_with_tag = AeadCipher::new(final_header.item_algorithm()?).encrypt_raw(
                    &self.dek,
                    &nonce,
                    &pt,
                    &item_aad(final_header.version, entry.item_id),
                )?;
                let split = ct_with_tag.len() - WRAP_TAG_LEN;
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&(split as u32).to_be_bytes());
                out.extend_from_slice(&ct_with_tag[..split]);
                out.extend_from_slice(&ct_with_tag[split..]);
            } else {
                let old_slot = *old_index.get(&entry.item_id).ok_or_else(|| {
                    Error::Encrypt(format!(
                        "item {} not open and not on disk — open it before saving",
                        entry.item_id
                    ))
                })? as usize;
                let frame = old_frames
                    .get(old_slot)
                    .ok_or_else(|| Error::Encrypt("old item slot out of range".into()))?;
                out.extend_from_slice(frame);
            }
        }

        let crc = crc32c::crc32c(&out);
        out.extend_from_slice(&(renumbered.len() as u32).to_be_bytes());
        out.extend_from_slice(&crc.to_be_bytes());
        let tag = file_mac(&out, &self.dek)?;
        out.extend_from_slice(&tag);
        ensure_vault_size(out.len())?;
        if self.last_disk_tag.is_none() {
            atomic_create_locked(&self.path, &out)?;
        } else {
            atomic_write_locked(&self.path, &out)?;
        }
        let mut items = std::mem::take(&mut self.open_items);
        for (entry, original) in renumbered.iter().zip(&self.entries) {
            if let Some(record) = items.remove(&original.slot) {
                self.open_items.insert(entry.slot, record);
            }
        }
        self.entries = renumbered;
        self.header.enc_counter = final_header.enc_counter;
        self.last_disk_tag = Some(tag);
        Ok(())
    }

    /// Split an on-disk vault into per-slot item frames.
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
        let index_pt = Zeroizing::new(AeadCipher::new(item_alg).decrypt_raw(
            dek,
            &index_nonce,
            index_ct,
            &index_aad(header.version),
        )?);
        let index = parse_index(&index_pt)?;
        Ok((index.entries, cursor + index_ct_len))
    }

    /// Split normal v2 frames. Legacy framing is private to migration.
    pub fn split_item_frames(raw: &[u8]) -> Result<Vec<Vec<u8>>> {
        parse::parse_header(raw)?;
        Ok(Self::split_item_frames_with_layout(raw, true, TRAILER_LEN)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect())
    }

    fn split_item_frames_with_layout(
        raw: &[u8],
        separate_tag: bool,
        trailer_len: usize,
    ) -> Result<Vec<&[u8]>> {
        let mut cursor = HEADER_LEN + NONCE_LEN;
        let index_ct_len = be_u32_at(raw, cursor)? as usize;
        cursor = cursor
            .checked_add(4 + index_ct_len)
            .ok_or_else(|| Error::Encrypt("index length overflow".into()))?;
        let slot_count = be_u32_at(raw, cursor)? as usize;
        cursor += 4;
        let trailer_start = raw
            .len()
            .checked_sub(trailer_len)
            .ok_or_else(|| Error::Encrypt("truncated vault trailer".into()))?;
        if be_u32_at(raw, trailer_start)? as usize != slot_count {
            return Err(Error::Encrypt(
                "slot count mismatch between items region and trailer".into(),
            ));
        }

        let mut frames = Vec::new();
        for _ in 0..slot_count {
            let start = cursor;
            cursor = cursor
                .checked_add(NONCE_LEN + 4)
                .ok_or_else(|| Error::Encrypt("item frame length overflow".into()))?;
            let ct_len = be_u32_at(raw, start + NONCE_LEN)? as usize;
            cursor = cursor
                .checked_add(ct_len + if separate_tag { WRAP_TAG_LEN } else { 0 })
                .ok_or_else(|| Error::Encrypt("item ciphertext length overflow".into()))?;
            if cursor > trailer_start {
                return Err(Error::Encrypt("truncated item frame".into()));
            }
            frames.push(&raw[start..cursor]);
        }
        if cursor != trailer_start {
            return Err(Error::Encrypt(
                "unexpected bytes before vault trailer".into(),
            ));
        }
        Ok(frames)
    }

    pub fn add_item(&mut self, title: String, username: String, record: ItemRecord) -> Result<u32> {
        let item_id = self.next_item_id;
        self.next_item_id = self
            .next_item_id
            .checked_add(1)
            .ok_or_else(|| Error::Encrypt("item_id space exhausted".into()))?;
        let slot = u32::try_from(self.entries.len())
            .map_err(|_| Error::Encrypt("too many item slots".into()))?;
        self.entries.push(IndexEntry {
            item_id,
            slot,
            state: LIVE_STATE,
            title,
            username,
        });
        self.open_items.insert(slot, record);
        Ok(item_id)
    }

    /// Rotate the DEK, KDF salt, and password-derived KEK. Every live item is
    /// decrypted from one authenticated snapshot before the key swap so no
    /// old-DEK frame can be copied.
    pub fn rotate(&mut self, password: &SecretVec) -> Result<()> {
        // One authenticated read: decrypt every live record up front, then
        // install them into the cache so save() re-encrypts them under the
        // new DEK. No per-item re-read of the file.
        let snapshot = self.snapshot()?;
        let mut live_records = std::collections::BTreeMap::new();
        for entry in self.entries.clone() {
            if entry.state == LIVE_STATE {
                let record = snapshot.decrypt_item(&entry)?;
                live_records.insert(entry.slot, record);
            }
        }
        for (slot, record) in live_records {
            self.open_items.insert(slot, record);
        }
        let old_dek = self.dek.clone();
        let new_params = KdfParams::default();
        let kdf_salt = random_salt();
        let new_kek = crate::crypto::kdf::Kdf::new(new_params).derive(password, &kdf_salt)?;
        let new_dek = SecretVec::new(random_dek().to_vec().into_boxed_slice());
        let header = ParsedHeader {
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
            wrap_nonce: random_nonce()?,
            wrapped_dek: [0u8; WRAPPED_DEK_CIPHER_LEN],
            wrap_tag: [0u8; WRAP_TAG_LEN],
            future_pad: [0u8; parse::FUTURE_PAD_LEN],
        };

        let old_kek = std::mem::replace(&mut self.kek, new_kek);
        self.dek = new_dek;
        let old_config = self.header.clone();
        self.header.kdf_params = new_params;
        self.header.kdf_salt = kdf_salt;
        self.header.enc_counter = 0;
        if let Err(error) = self.save_with_header(&header, &old_dek) {
            self.dek = old_dek;
            self.kek = old_kek;
            self.header = old_config;
            return Err(error);
        }
        Ok(())
    }

    /// Change the master password without changing the DEK or item frames.
    pub fn change_password(&mut self, new_password: &SecretVec) -> Result<()> {
        let _lock = acquire_write_lock(&self.path)?;
        let new_params = KdfParams::default();
        let kdf_salt = random_salt();
        let new_kek = crate::crypto::kdf::Kdf::new(new_params).derive(new_password, &kdf_salt)?;
        let old = read_vault_bytes(&self.path)?;
        let mut header = parse::parse_header(&old)?;
        header.kdf_salt = kdf_salt;
        header.argon2_m_mib = new_params.argon2_m_mib;
        header.argon2_t = new_params.argon2_t;
        header.argon2_p = new_params.argon2_p;
        header.wrap_nonce = random_nonce()?;

        let old_kek = std::mem::replace(&mut self.kek, new_kek);
        let old_config = self.header.clone();
        self.header.kdf_params = new_params;
        self.header.kdf_salt = kdf_salt;
        let disk_dek = self.dek.clone();
        if let Err(error) = self.save_with_header_locked(&header, &disk_dek) {
            self.kek = old_kek;
            self.header = old_config;
            return Err(error);
        }
        Ok(())
    }
}

/// A single authenticated, immutable image of the vault file, taken from one
/// `Vault` session. Created by [`Vault::snapshot`]. The complete file is
/// read and MAC-verified once against the session's committed tag; frames
/// are located once and decrypted on demand. Each decrypted record wipes on
/// drop as usual.
pub struct VaultSnapshot {
    header: VaultCryptoConfig,
    dek: SecretVec,
    frames: Vec<Vec<u8>>,
}

impl VaultSnapshot {
    /// Decrypt one item's record from this image without touching the
    /// session cache. Embedded IDs are cross-checked as in `open_item`.
    pub fn decrypt_item(&self, entry: &IndexEntry) -> Result<ItemRecord> {
        let slot = usize::try_from(entry.slot)
            .map_err(|_| Error::Encrypt("item slot is out of range".into()))?;
        let frame = self
            .frames
            .get(slot)
            .ok_or_else(|| Error::Encrypt(format!("slot {} out of range", entry.slot)))?;
        decrypt_item_frame_with(
            &self.dek,
            self.header.item_alg,
            self.header.version,
            frame,
            entry.item_id,
        )
    }

    /// Frame count in this image (matches the session's index length —
    /// verified by the commit-tag match in `Vault::snapshot`).
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
}

fn decrypt_item_frame_with(
    dek: &SecretVec,
    item_alg: Algorithm,
    version: u8,
    frame: &[u8],
    item_id: u32,
) -> Result<ItemRecord> {
    let nonce: [u8; NONCE_LEN] = frame
        .get(..NONCE_LEN)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::Encrypt("truncated item nonce".into()))?;
    let ct_len = u32::from_be_bytes(
        frame
            .get(NONCE_LEN..NONCE_LEN + 4)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| Error::Encrypt("truncated item ciphertext length".into()))?,
    ) as usize;
    let ct_end = NONCE_LEN
        .checked_add(4)
        .and_then(|start| start.checked_add(ct_len))
        .ok_or_else(|| Error::Encrypt("item ciphertext length overflow".into()))?;
    let ct = frame
        .get(NONCE_LEN + 4..ct_end)
        .ok_or_else(|| Error::Encrypt("truncated item ciphertext".into()))?;
    let tag = frame
        .get(ct_end..)
        .ok_or_else(|| Error::Encrypt("truncated item tag".into()))?;
    let mut ct_with_tag = Vec::with_capacity(ct.len() + tag.len());
    ct_with_tag.extend_from_slice(ct);
    ct_with_tag.extend_from_slice(tag);

    let pt = Zeroizing::new(AeadCipher::new(item_alg).decrypt_raw(
        dek,
        &nonce,
        &ct_with_tag,
        &item_aad(version, item_id),
    )?);
    let (record, embedded_id) = parse_item(&pt)?;
    if embedded_id != item_id {
        return Err(Error::Encrypt(format!(
            "item id mismatch: index={item_id}, body={embedded_id}"
        )));
    }
    Ok(record)
}

fn read_vault_bytes(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path)
        .map_err(|e| Error::Encrypt(format!("read vault {}: {e}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(MAX_VAULT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::Encrypt(format!("read vault {}: {e}", path.display())))?;
    if bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err(Error::Encrypt(format!(
            "vault exceeds the {} MiB size limit",
            MAX_VAULT_BYTES / 1024 / 1024
        )));
    }
    Ok(bytes)
}

fn be_u32_at(b: &[u8], off: usize) -> Result<u32> {
    b.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| Error::Encrypt("truncated u32".into()))
}

fn ensure_vault_size(len: usize) -> Result<()> {
    if len as u64 > MAX_VAULT_BYTES {
        return Err(Error::Encrypt(format!(
            "vault exceeds the {} MiB size limit",
            MAX_VAULT_BYTES / 1024 / 1024
        )));
    }
    Ok(())
}

fn item_plaintext_len(record: &ItemRecord) -> usize {
    25 + record.url.len()
        + record.password.as_ref().map_or(0, |p| 4 + p.len())
        + record.notes.as_ref().map_or(0, |p| 4 + p.len())
        + record.totp.as_ref().map_or(0, |t| 13 + t.secret.len())
}

fn file_mac(bytes: &[u8], dek: &SecretVec) -> Result<[u8; FILE_MAC_LEN]> {
    let mut key = Zeroizing::new([0u8; FILE_MAC_LEN]);
    Hkdf::<Sha256>::new(None, dek.expose_secret())
        .expand(b"latchkey/v2/file-mac", &mut *key)
        .map_err(|_| Error::Encrypt("file MAC key derivation failed".into()))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&*key)
        .map_err(|_| Error::Encrypt("file MAC key length invalid".into()))?;
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().into())
}

fn authenticate_snapshot(bytes: &[u8], dek: &SecretVec) -> Result<[u8; FILE_MAC_LEN]> {
    parse::parse_header(bytes)?;
    let trailer_start = bytes
        .len()
        .checked_sub(TRAILER_LEN)
        .ok_or_else(|| Error::Encrypt("truncated vault trailer".into()))?;
    let mac_start = bytes.len() - FILE_MAC_LEN;
    let mut key = Zeroizing::new([0u8; FILE_MAC_LEN]);
    Hkdf::<Sha256>::new(None, dek.expose_secret())
        .expand(b"latchkey/v2/file-mac", &mut *key)
        .map_err(|_| Error::Encrypt("file MAC key derivation failed".into()))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&*key)
        .map_err(|_| Error::Encrypt("file MAC key length invalid".into()))?;
    mac.update(&bytes[..mac_start]);
    mac.verify_slice(&bytes[mac_start..])
        .map_err(|_| Error::Decrypt)?;
    if crc32c::crc32c(&bytes[..trailer_start]) != be_u32_at(bytes, trailer_start + 4)? {
        return Err(Error::Encrypt("vault file CRC mismatch".into()));
    }
    Ok(bytes[mac_start..].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;

    fn pswd(s: &str) -> SecretVec {
        SecretVec::new(s.as_bytes().to_vec().into_boxed_slice())
    }

    #[test]
    fn oversized_vault_is_rejected_before_parsing() {
        let path =
            std::env::temp_dir().join(format!("latchkey_v_big_{}.latchkey", std::process::id()));
        let file = File::create(&path).unwrap();
        file.set_len(MAX_VAULT_BYTES + 1).unwrap();
        drop(file);

        let err = read_vault_bytes(&path).unwrap_err().to_string();
        assert!(err.contains("size limit"), "{err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn create_open_roundtrip_empty() {
        let tmp =
            std::env::temp_dir().join(format!("latchkey_v_rt_{}.latchkey", std::process::id()));
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
    fn ordinary_save_refreshes_wrap_nonce() {
        // CRYPTO_SPEC §5: every header write must use a fresh wrap nonce.
        // save() re-parses the on-disk header, so without the explicit
        // re-randomization the same (KEK, nonce) pair would encrypt the DEK
        // twice — the GCM forbidden-attack setup.
        let tmp =
            std::env::temp_dir().join(format!("latchkey_v_nonce_{}.latchkey", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let password = pswd("nonce-test");
        let kdf = KdfParams::new(8, 1, 1).unwrap();
        let record = crate::vault::shape::ItemRecord {
            password: Some(b"pw".to_vec()),
            url: String::new(),
            notes: None,
            totp: None,
            created_unix: 1,
            modified_unix: 1,
        };
        {
            let mut v = Vault::create(
                &tmp,
                &password,
                kdf,
                Algorithm::Aes256Gcm,
                Algorithm::Aes256Gcm,
            )
            .unwrap();
            v.add_item("t".into(), "u".into(), record).unwrap();
            v.save().unwrap();
        }
        let raw1 = read_vault_bytes(&tmp).unwrap();
        {
            let mut v = Vault::open(&tmp, &password).unwrap();
            v.open_item(1).unwrap();
            let mut rec = v.open_items.remove(&0).unwrap();
            rec.password = Some(b"pw2".to_vec());
            v.open_items.insert(0, rec);
            v.save().unwrap();
        }
        let raw2 = read_vault_bytes(&tmp).unwrap();
        let h1 = parse::parse_header(&raw1).unwrap();
        let h2 = parse::parse_header(&raw2).unwrap();
        assert_ne!(
            h1.wrap_nonce, h2.wrap_nonce,
            "second save must not reuse the first save's wrap nonce"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn wrong_password_rejected() {
        let tmp =
            std::env::temp_dir().join(format!("latchkey_v_wp_{}.latchkey", std::process::id()));
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
        let tmp =
            std::env::temp_dir().join(format!("latchkey_v_ag_{}.latchkey", std::process::id()));
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

    #[test]
    fn verify_all_detects_index_item_tombstone_and_trailer_corruption() {
        let path =
            std::env::temp_dir().join(format!("latchkey_v_check_{}.latchkey", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let password = pswd("check-password");
        let record = || ItemRecord {
            password: Some(b"secret".to_vec()),
            url: String::new(),
            notes: None,
            totp: None,
            created_unix: 1,
            modified_unix: 1,
        };
        let mut vault = Vault::create(
            &path,
            &password,
            KdfParams::new(8, 1, 1).unwrap(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        let live_id = vault.add_item("live".into(), "u".into(), record()).unwrap();
        let tombstone_id = vault
            .add_item("deleted".into(), "u".into(), record())
            .unwrap();
        vault.save().unwrap();
        let tombstone = vault
            .entries
            .iter_mut()
            .find(|entry| entry.item_id == tombstone_id)
            .unwrap();
        tombstone.state = TOMBSTONE_STATE;
        vault.open_items.remove(&tombstone.slot);
        vault.save().unwrap();
        drop(vault);

        let verified = Vault::open(&path, &password).unwrap();
        assert_eq!(verified.verify_all_items().unwrap(), (1, 1));
        let original = std::fs::read(&path).unwrap();

        let repair_crc = |bytes: &mut Vec<u8>| {
            let len = bytes.len();
            let crc = crc32c::crc32c(&bytes[..len - TRAILER_LEN]);
            bytes[len - FILE_MAC_LEN - 4..len - FILE_MAC_LEN].copy_from_slice(&crc.to_be_bytes());
        };
        let index_ct_len = be_u32_at(&original, HEADER_LEN + NONCE_LEN).unwrap() as usize;
        let index_ciphertext = HEADER_LEN + NONCE_LEN + 4;
        let mut cursor = index_ciphertext + index_ct_len;
        assert_eq!(be_u32_at(&original, cursor).unwrap(), 2);
        cursor += 4;
        let mut item_ciphertexts = Vec::new();
        for _ in 0..2 {
            let ct_len = be_u32_at(&original, cursor + NONCE_LEN).unwrap() as usize;
            item_ciphertexts.push(cursor + NONCE_LEN + 4);
            cursor += NONCE_LEN + 4 + ct_len + WRAP_TAG_LEN;
        }

        for position in item_ciphertexts {
            let mut corrupted = original.clone();
            corrupted[position] ^= 1;
            repair_crc(&mut corrupted);
            std::fs::write(&path, corrupted).unwrap();
            assert!(verified.verify_all_items().is_err());
        }

        let mut corrupted_index = original.clone();
        corrupted_index[index_ciphertext] ^= 1;
        repair_crc(&mut corrupted_index);
        std::fs::write(&path, corrupted_index).unwrap();
        assert!(Vault::open(&path, &password).is_err());

        let mut corrupted_trailer = original.clone();
        let last = corrupted_trailer.len() - 1;
        corrupted_trailer[last] ^= 1;
        std::fs::write(&path, corrupted_trailer).unwrap();
        assert!(Vault::open(&path, &password).is_err());

        std::fs::write(&path, original).unwrap();
        let mut final_vault = Vault::open(&path, &password).unwrap();
        final_vault.open_item(live_id).unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn verify_all_leaves_valid_vault_byte_identical() {
        // NEXT_RELEASE §8: "check on a valid vault leaves the file
        // byte-identical" — the read-only property was documented but
        // never asserted. Hash the file before and after a full verify.
        let path = std::env::temp_dir().join(format!(
            "latchkey_v_readonly_{}.latchkey",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let password = pswd("readonly");
        let record = ItemRecord {
            password: Some(b"secret".to_vec()),
            url: String::new(),
            notes: None,
            totp: None,
            created_unix: 1,
            modified_unix: 1,
        };
        let mut vault = Vault::create(
            &path,
            &password,
            KdfParams::new(8, 1, 1).unwrap(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        vault.add_item("t".into(), "u".into(), record).unwrap();
        vault.save().unwrap();
        drop(vault);

        let before = std::fs::read(&path).unwrap();
        let opened = Vault::open(&path, &password).unwrap();
        let (live, _tombstones) = opened.verify_all_items().unwrap();
        assert_eq!(live, 1);
        drop(opened);
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            before, after,
            "verify_all_items must not rewrite a valid vault"
        );
        let _ = std::fs::remove_file(&path);
    }

    fn security_vault(tag: &str) -> (Vault, SecretVec) {
        let path = std::env::temp_dir().join(format!(
            "latchkey_security_{tag}_{}.bin",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let password = pswd("security-test");
        let vault = Vault::create(
            &path,
            &password,
            KdfParams::new(8, 1, 1).unwrap(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        (vault, password)
    }

    fn security_record() -> ItemRecord {
        ItemRecord {
            password: Some(b"preserved-secret".to_vec()),
            url: "https://example.test".into(),
            notes: Some(b"preserved-note".to_vec()),
            totp: Some(crate::vault::shape::TotpSubRecord {
                secret: b"12345678901234567890".to_vec(),
                period: 30,
                digits: 6,
                algorithm: crate::vault::shape::TotpAlgorithm::Sha1,
            }),
            created_unix: 123,
            modified_unix: 456,
        }
    }

    #[test]
    fn counts_index_items_and_enforces_exact_rotation_boundary() {
        let (mut vault, password) = security_vault("counter");
        assert_eq!(vault.header.enc_counter, 1);
        vault.save().unwrap();
        assert_eq!(vault.header.enc_counter, 2);
        vault
            .add_item("one".into(), "user".into(), security_record())
            .unwrap();
        vault.save().unwrap();
        assert_eq!(vault.header.enc_counter, 4);
        drop(vault);
        let path = std::env::temp_dir().join(format!(
            "latchkey_security_counter_{}.bin",
            std::process::id()
        ));
        let mut vault = Vault::open(&path, &password).unwrap();
        let mut header = parse::parse_header(&std::fs::read(&path).unwrap()).unwrap();
        header.enc_counter = ROTATION_LIMIT - 1;
        let dek = vault.dek.clone();
        vault.save_with_header(&header, &dek).unwrap();
        assert_eq!(vault.header.enc_counter, ROTATION_LIMIT);
        let committed = std::fs::read(&path).unwrap();
        assert!(
            vault.save().is_err(),
            "even index-only encryption must obey cap"
        );
        assert_eq!(std::fs::read(&path).unwrap(), committed);
        assert_eq!(
            Vault::open(&path, &password).unwrap().header.enc_counter,
            ROTATION_LIMIT
        );
        let _ = std::fs::remove_file(&path);

        let (mut vault, _) = security_vault("counter_item");
        vault
            .add_item("one".into(), "user".into(), security_record())
            .unwrap();
        let mut header = parse::parse_header(&std::fs::read(&vault.path).unwrap()).unwrap();
        let dek = vault.dek.clone();
        header.enc_counter = ROTATION_LIMIT - 1;
        let committed = std::fs::read(&vault.path).unwrap();
        assert!(
            vault.save_with_header(&header, &dek).is_err(),
            "item plus index need two remaining encryptions"
        );
        assert_eq!(std::fs::read(&vault.path).unwrap(), committed);
        header.enc_counter = ROTATION_LIMIT - 2;
        vault.save_with_header(&header, &dek).unwrap();
        assert_eq!(vault.header.enc_counter, ROTATION_LIMIT);
        let _ = std::fs::remove_file(&vault.path);
    }

    #[test]
    fn oversized_candidate_preserves_disk_and_failed_key_changes_preserve_session() {
        let (mut vault, password) = security_vault("oversize");
        let committed = std::fs::read(&vault.path).unwrap();
        let old_dek = vault.dek.clone();
        let mut record = security_record();
        record.password = Some(vec![b'p'; 1024]);
        record.notes = Some(vec![b'n'; 8192]);
        for _ in 0..120 {
            vault
                .add_item("entry".into(), "user".into(), record.clone())
                .unwrap();
        }
        assert!(vault.save().unwrap_err().to_string().contains("size limit"));
        assert_eq!(std::fs::read(&vault.path).unwrap(), committed);
        assert!(Vault::open(&vault.path, &password)
            .unwrap()
            .entries
            .is_empty());
        assert!(vault.change_password(&pswd("new-password")).is_err());
        assert!(vault.rotate(&password).is_err());
        assert_eq!(vault.dek.expose_secret(), old_dek.expose_secret());
        assert_eq!(std::fs::read(&vault.path).unwrap(), committed);
        vault.entries.clear();
        vault.open_items.clear();
        vault.save().unwrap();
        assert!(Vault::open(&vault.path, &password)
            .unwrap()
            .entries
            .is_empty());
        let _ = std::fs::remove_file(&vault.path);
    }

    fn legacy_bytes(vault: &Vault, separate_tag: bool) -> Vec<u8> {
        let raw = std::fs::read(&vault.path).unwrap();
        let mut header = parse::parse_header(&raw).unwrap();
        header.version = 1;
        header.reserved[0] = if separate_tag { FRAME_LAYOUT_V2 } else { 0 };
        header.wrap_nonce = random_nonce().unwrap();
        let wrap = AeadCipher::new(vault.header.wrap_alg)
            .encrypt_raw(
                &vault.kek,
                &header.wrap_nonce,
                vault.dek.expose_secret(),
                &parse::header_aad(&header),
            )
            .unwrap();
        header.wrapped_dek.copy_from_slice(&wrap[..32]);
        header.wrap_tag.copy_from_slice(&wrap[32..]);
        let mut bytes = parse::build_header(&header).to_vec();
        let index = Zeroizing::new(
            serialize_index(&IndexPayload {
                entries: vault.entries.clone(),
            })
            .unwrap(),
        );
        let nonce = random_nonce().unwrap();
        let ct = AeadCipher::new(vault.header.item_alg)
            .encrypt_raw(&vault.dek, &nonce, &index, &index_aad(1))
            .unwrap();
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&ct);
        bytes.extend_from_slice(&(vault.entries.len() as u32).to_be_bytes());
        for entry in &vault.entries {
            let pt = Zeroizing::new(
                serialize_item(&vault.open_items[&entry.slot], entry.item_id).unwrap(),
            );
            let nonce = random_nonce().unwrap();
            let ct = AeadCipher::new(vault.header.item_alg)
                .encrypt_raw(&vault.dek, &nonce, &pt, &item_aad(1, entry.item_id))
                .unwrap();
            bytes.extend_from_slice(&nonce);
            let ct_len = ct.len() - if separate_tag { WRAP_TAG_LEN } else { 0 };
            bytes.extend_from_slice(&(ct_len as u32).to_be_bytes());
            bytes.extend_from_slice(&ct);
        }
        let crc = crc32c::crc32c(&bytes);
        bytes.extend_from_slice(&(vault.entries.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&crc.to_be_bytes());
        bytes
    }

    #[test]
    fn migration_preserves_tombstone_records_ids_and_authenticates_both_legacy_layouts() {
        for separate_tag in [false, true] {
            let (mut source, password) = security_vault(if separate_tag {
                "legacy_separate"
            } else {
                "legacy_combined"
            });
            let record = security_record();
            source
                .add_item("live".into(), "user".into(), record.clone())
                .unwrap();
            let deleted = source
                .add_item("deleted".into(), "user2".into(), record.clone())
                .unwrap();
            source.entries[1].state = TOMBSTONE_STATE;
            source.save().unwrap();
            let original = legacy_bytes(&source, separate_tag);
            std::fs::write(&source.path, &original).unwrap();
            assert!(Vault::open(&source.path, &password).is_err());
            let target = source.path.with_extension("migrated");
            let _ = std::fs::remove_file(&target);
            let migrated = Vault::migrate(&source.path, &target, &password).unwrap();
            assert_eq!(migrated.entries, source.entries);
            assert_eq!(migrated.next_item_id, deleted + 1);
            assert_eq!(migrated.verify_all_items().unwrap(), (1, 1));
            assert_eq!(std::fs::read(&source.path).unwrap(), original);
            let migrated_raw = std::fs::read(&target).unwrap();
            let frames = Vault::split_item_frames(&migrated_raw).unwrap();
            for entry in &migrated.entries {
                assert_eq!(
                    migrated
                        .decrypt_item_frame(&frames[entry.slot as usize], entry.item_id)
                        .unwrap(),
                    record
                );
            }
            let mut reopened = Vault::open(&target, &password).unwrap();
            assert_eq!(
                reopened
                    .add_item("new".into(), "user".into(), security_record())
                    .unwrap(),
                deleted + 1
            );

            // A repaired CRC does not bypass a legacy item's AEAD tag, including
            // tombstones that normal lazy lookup never opens.
            for index in 0..2 {
                let mut corrupt = original.clone();
                let frames =
                    Vault::split_item_frames_with_layout(&original, separate_tag, 8).unwrap();
                let offset =
                    frames[index].as_ptr() as usize - original.as_ptr() as usize + NONCE_LEN + 4;
                corrupt[offset] ^= 1;
                let len = corrupt.len();
                let crc = crc32c::crc32c(&corrupt[..len - 8]);
                corrupt[len - 4..].copy_from_slice(&crc.to_be_bytes());
                std::fs::write(&source.path, &corrupt).unwrap();
                let failed_target = source.path.with_extension(format!("rejected{index}"));
                let _ = std::fs::remove_file(&failed_target);
                assert!(Vault::migrate(&source.path, &failed_target, &password).is_err());
                assert!(!failed_target.exists());
                assert_eq!(std::fs::read(&source.path).unwrap(), corrupt);
            }
            let _ = std::fs::remove_file(&source.path);
            let _ = std::fs::remove_file(&target);
        }
    }
}
