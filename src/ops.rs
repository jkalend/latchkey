//! Application operations shared by the CLI and TUI adapters.
//!
//! This module owns credential state transitions and save timing. It never
//! prompts, prints, renders, or touches the clipboard.

use crate::crypto::error::{Error, Result};
use crate::vault::shape::{validate_item, ItemRecord, TotpSubRecord};
use crate::vault::vault_impl::Vault;
use zeroize::Zeroize;

// No Debug: these hold raw password/notes bytes (CRYPTO_SPEC §6 — secret
// types do not derive Debug; the compiler enforces the redaction policy).
#[derive(Default, Zeroize)]
pub struct NewEntry {
    pub title: String,
    pub username: String,
    pub password: Option<Vec<u8>>,
    pub url: String,
    pub notes: Option<Vec<u8>>,
    pub totp: Option<TotpSubRecord>,
}

#[derive(Debug)]
pub struct ImportedEntry {
    pub title: String,
    pub username: String,
    pub record: ItemRecord,
}

#[derive(Debug)]
pub struct ImportedUpdate {
    pub item_id: u32,
    pub record: ItemRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckReport {
    pub format_version: u8,
    pub wrap_algorithm: crate::crypto::ciphers::Algorithm,
    pub item_algorithm: crate::crypto::ciphers::Algorithm,
    pub kdf_params: crate::crypto::kdf::KdfParams,
    pub live_items: usize,
    pub tombstones: usize,
}

#[derive(Debug, Default, PartialEq, Eq, Zeroize)]
pub enum Change<T: Zeroize> {
    #[default]
    Keep,
    Set(T),
    Clear,
}
// No Debug: Change<Vec<u8>> fields hold raw secret bytes (CRYPTO_SPEC §6).
#[derive(Default, Zeroize)]
pub struct EntryPatch {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Change<Vec<u8>>,
    pub url: Option<String>,
    pub notes: Change<Vec<u8>>,
    pub totp: Change<TotpSubRecord>,
}

pub fn add_entry(vault: &mut Vault, input: NewEntry) -> Result<u32> {
    let now = unix_now();
    let record = ItemRecord {
        password: input.password,
        url: input.url,
        notes: input.notes,
        totp: input.totp,
        created_unix: now,
        modified_unix: now,
    };
    validate_metadata(&input.title, &input.username)?;
    validate_item(&record)?;

    let id = vault.add_item(input.title, input.username, record)?;
    vault.save()?;
    Ok(id)
}

pub fn update_entry(vault: &mut Vault, item_id: u32, patch: EntryPatch) -> Result<bool> {
    // Prepare: work on clones of only the affected entry and record. The
    // session keeps its original state until save() succeeds.
    let (entry, mut record) = vault.record_for_update(item_id)?;

    let title = patch.title.unwrap_or_else(|| entry.title.clone());
    let username = patch.username.unwrap_or_else(|| entry.username.clone());
    let mut changed = title != entry.title || username != entry.username;

    match patch.password {
        Change::Keep => {}
        Change::Set(value) => {
            changed |= record.password.as_deref() != Some(value.as_slice());
            record.password.zeroize();
            record.password = Some(value);
        }
        Change::Clear => {
            changed |= record.password.is_some();
            record.password.zeroize();
            record.password = None;
        }
    }
    if let Some(value) = patch.url {
        changed |= record.url != value;
        record.url.zeroize();
        record.url = value;
    }
    match patch.notes {
        Change::Keep => {}
        Change::Set(value) => {
            changed |= record.notes.as_deref() != Some(value.as_slice());
            record.notes.zeroize();
            record.notes = Some(value);
        }
        Change::Clear => {
            changed |= record.notes.is_some();
            record.notes.zeroize();
            record.notes = None;
        }
    }
    match patch.totp {
        Change::Keep => {}
        Change::Set(value) => {
            changed |= record.totp.as_ref() != Some(&value);
            record.totp = Some(value);
        }
        Change::Clear => {
            changed |= record.totp.is_some();
            record.totp = None;
        }
    }

    if !changed {
        // A no-op edit returns Ok(false) without saving. The session cache
        // still holds the original record (the working copy was a clone).
        return Ok(false);
    }

    record.modified_unix = unix_now();
    // Validate the whole candidate BEFORE touching session state; on failure
    // the original cached record and metadata stay intact.
    validate_metadata(&title, &username)?;
    validate_item(&record)?;
    vault.commit_entry(item_id, title, username, record)?;
    Ok(true)
}

pub fn delete_entry(vault: &mut Vault, item_id: u32) -> Result<()> {
    vault.commit_tombstone(item_id)
}

pub fn apply_import(
    vault: &mut Vault,
    adds: Vec<ImportedEntry>,
    updates: Vec<ImportedUpdate>,
) -> Result<()> {
    // Validate the complete candidate BEFORE mutating session state. IDs are
    // only simulated here; add_item allocates the real ones at commit time,
    // so a failure does not consume any item_id.
    let mut next_id = vault.next_item_id();
    for add in &adds {
        validate_metadata(&add.title, &add.username)?;
        validate_item(&add.record)?;
        next_id = next_id
            .checked_add(1)
            .ok_or_else(|| Error::Encrypt("item_id space exhausted".into()))?;
    }

    let mut prepared_updates = Vec::with_capacity(updates.len());
    for mut update in updates {
        let entry = vault.entry_for_update(update.item_id)?;
        // Cache the current record (identical to the committed disk bytes)
        // to read created_unix for the candidate.
        vault.open_item(update.item_id)?;
        let existing = vault
            .open_record(entry.slot)
            .ok_or_else(|| Error::Encrypt("item not open".into()))?;
        update.record.created_unix = existing.created_unix;
        validate_metadata(&entry.title, &entry.username)?;
        validate_item(&update.record)?;
        prepared_updates.push((entry.slot, update.record));
    }

    vault.commit_import(
        adds.into_iter()
            .map(|add| (add.title, add.username, add.record))
            .collect(),
        prepared_updates,
    )
}

pub fn check_vault(vault: &Vault) -> Result<CheckReport> {
    let (live_items, tombstones) = vault.verify_all_items()?;
    let config = vault.config();
    Ok(CheckReport {
        format_version: config.version,
        wrap_algorithm: config.wrap_alg,
        item_algorithm: config.item_alg,
        kdf_params: config.kdf_params,
        live_items,
        tombstones,
    })
}

fn validate_metadata(title: &str, username: &str) -> Result<()> {
    if title.len() > 256 {
        return Err(Error::Encrypt("title exceeds 256-byte format limit".into()));
    }
    if username.len() > 512 {
        return Err(Error::Encrypt(
            "username exceeds 512-byte format limit".into(),
        ));
    }
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ciphers::Algorithm;
    use crate::crypto::kdf::{KdfParams, SecretVec};

    fn test_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "latchkey_ops_{}_{}.bin",
            std::process::id(),
            unix_now()
        ))
    }

    #[test]
    fn mutations_persist_through_shared_operations() {
        let path = test_path();
        let _ = std::fs::remove_file(&path);
        let password = SecretVec::new(b"test-password".to_vec().into_boxed_slice());
        let mut vault = Vault::create(
            &path,
            &password,
            KdfParams::new(8, 1, 1).unwrap(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();

        let id = add_entry(
            &mut vault,
            NewEntry {
                title: "old.example".into(),
                username: "alice".into(),
                password: Some(b"old-secret".to_vec()),
                url: String::new(),
                notes: Some(b"remove me".to_vec()),
                totp: None,
            },
        )
        .unwrap();
        assert!(update_entry(
            &mut vault,
            id,
            EntryPatch {
                title: Some("new.example".into()),
                username: Some("bob".into()),
                password: Change::Set(b"new-secret".to_vec()),
                notes: Change::Clear,
                ..EntryPatch::default()
            }
        )
        .unwrap());
        drop(vault);

        let mut reopened = Vault::open(&path, &password).unwrap();
        let entry = reopened
            .entries()
            .iter()
            .find(|entry| entry.item_id == id)
            .unwrap();
        assert_eq!(entry.title, "new.example");
        assert_eq!(entry.username, "bob");
        let slot = entry.slot;
        reopened.open_item(id).unwrap();
        let record = reopened.open_record(slot).unwrap();
        assert_eq!(record.password.as_deref(), Some(b"new-secret".as_slice()));
        assert!(record.notes.is_none());

        delete_entry(&mut reopened, id).unwrap();
        let before = std::fs::read(&path).unwrap();
        let report = check_vault(&reopened).unwrap();
        assert_eq!((report.live_items, report.tombstones), (0, 1));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn new_entry_and_patch_zeroize() {
        let mut entry = NewEntry {
            title: "example".into(),
            username: "user".into(),
            password: Some(b"supersecret".to_vec()),
            url: "https://example.com".into(),
            notes: Some(b"topsecretnotes".to_vec()),
            totp: None,
        };
        entry.zeroize();
        assert!(entry.password.is_none());
        assert!(entry.notes.is_none());
        assert!(entry.title.is_empty());
        assert!(entry.username.is_empty());
        assert!(entry.url.is_empty());

        let mut patch = EntryPatch {
            title: Some("title".into()),
            username: None,
            password: Change::Set(b"secret".to_vec()),
            url: None,
            notes: Change::Keep,
            totp: Change::Clear,
        };
        patch.zeroize();
        assert!(patch.title.is_none());
        match patch.password {
            Change::Set(ref v) => assert!(v.is_empty() || v.iter().all(|&b| b == 0)),
            Change::Keep => {}
            Change::Clear => {}
        }
    }
}
