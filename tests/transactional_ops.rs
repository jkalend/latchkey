//! Transactional operation failures must leave the session exactly as it
//! was (IMPROVEMENT_HANDOFF §3): invalid edits retain the original cached
//! record and metadata, failed adds do not consume an item_id, failed
//! deletes leave the item live and readable, and a successful import is a
//! single commit. All errors here are deterministic (validation failures or
//! a stale commit produced by a second session writing to disk) — no timing
//! or antivirus races.

use latchkey::crypto::ciphers::Algorithm;
use latchkey::crypto::kdf::{KdfParams, SecretVec};
use latchkey::ops::{add_entry, delete_entry, update_entry, Change, EntryPatch, NewEntry};
use latchkey::vault::shape::ItemRecord;
use latchkey::vault::vault_impl::Vault;
use std::path::PathBuf;

fn pw(s: &str) -> SecretVec {
    SecretVec::new(s.as_bytes().to_vec().into_boxed_slice())
}

fn tmp_vault(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "latchkey_txn_{}_{}_{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("vault.bin")
}

fn test_kdf() -> KdfParams {
    KdfParams::new(8, 1, 1).unwrap()
}

fn new_entry(title: &str, password: &[u8]) -> NewEntry {
    NewEntry {
        title: title.into(),
        username: "alice".into(),
        password: Some(password.to_vec()),
        url: String::new(),
        notes: None,
        totp: None,
    }
}

fn sample_record() -> ItemRecord {
    ItemRecord {
        password: Some(b"correct horse battery staple".to_vec()),
        url: "https://example.com".to_string(),
        notes: Some(b"note".to_vec()),
        totp: None,
        created_unix: 1,
        modified_unix: 1,
    }
}

/// (a) An invalid edit (title over the 256-byte format limit) fails with a
/// validation error and leaves the session's cached record and metadata
/// exactly as they were.
#[test]
fn invalid_edit_retains_original_cached_record_and_metadata() {
    let path = tmp_vault("edit");
    let password = pw("txn-master");
    let mut vault = Vault::create(
        &path,
        &password,
        test_kdf(),
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Gcm,
    )
    .unwrap();
    let id = add_entry(
        &mut vault,
        new_entry("original.example", b"original-secret"),
    )
    .unwrap();

    // Read the committed state the edit must not disturb.
    let before_entry = vault
        .entries()
        .iter()
        .find(|e| e.item_id == id)
        .unwrap()
        .clone();
    let before_record = vault.open_record(before_entry.slot).unwrap().clone();
    let before_disk = std::fs::read(&path).unwrap();
    let before_counter = vault.config().enc_counter;

    // 257 bytes of title: over the format limit, rejected before any
    // session mutation or save.
    let too_long = "x".repeat(257);
    let error = update_entry(
        &mut vault,
        id,
        EntryPatch {
            title: Some(too_long),
            password: Change::Set(b"attacker-replacement".to_vec()),
            ..EntryPatch::default()
        },
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("256-byte"),
        "expected title-limit validation error, got: {error}"
    );

    let after_entry = vault.entries().iter().find(|e| e.item_id == id).unwrap();
    assert_eq!(after_entry.title, before_entry.title);
    assert_eq!(after_entry.username, before_entry.username);
    assert_eq!(
        vault.open_record(after_entry.slot).unwrap(),
        &before_record,
        "failed edit must retain the original cached record"
    );
    assert_eq!(vault.config().enc_counter, before_counter);
    assert_eq!(std::fs::read(&path).unwrap(), before_disk);
    assert!(
        vault.has_open_records(),
        "the cached record must remain open"
    );

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// (b) A failed add (validation error) does not consume an item_id: the
/// next successful add receives the id the failed one would have gotten.
#[test]
fn failed_add_does_not_consume_an_item_id() {
    let path = tmp_vault("add");
    let password = pw("txn-master");
    let mut vault = Vault::create(
        &path,
        &password,
        test_kdf(),
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Gcm,
    )
    .unwrap();
    let first = add_entry(&mut vault, new_entry("first.example", b"pw-1")).unwrap();
    assert_eq!(first, 1);
    let next_before = vault.next_item_id();

    // Oversized notes trip item validation before any state change.
    let oversized = NewEntry {
        notes: Some(vec![b'n'; 100_000]),
        ..new_entry("oversized.example", b"pw")
    };
    let error = add_entry(&mut vault, oversized).unwrap_err();
    assert!(
        error.to_string().contains("format limit"),
        "expected a size-limit validation error, got: {error}"
    );

    assert_eq!(
        vault.next_item_id(),
        next_before,
        "a failed add must not consume an item_id"
    );
    assert_eq!(
        vault.entries().iter().filter(|e| e.state == 1).count(),
        1,
        "no partially prepared record may be installed"
    );

    let second = add_entry(&mut vault, new_entry("second.example", b"pw-2")).unwrap();
    assert_eq!(second, next_before, "the id space stays contiguous");

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// (c) A failed delete (save rejected because another session already
/// committed to disk) leaves the item live and readable in the same session
/// and after reopening.
#[test]
fn failed_delete_leaves_item_live_and_readable() {
    let path = tmp_vault("delete");
    let password = pw("txn-master");
    let mut vault = Vault::create(
        &path,
        &password,
        test_kdf(),
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Gcm,
    )
    .unwrap();
    let id = add_entry(&mut vault, new_entry("keep-me.example", b"keep-secret")).unwrap();

    // A second session commits a change to disk; the first session's next
    // save must be rejected as stale (deterministic, no races).
    {
        let mut other = Vault::open(&path, &password).unwrap();
        add_entry(&mut other, new_entry("other.example", b"other-pw")).unwrap();
    }

    let error = delete_entry(&mut vault, id).unwrap_err();
    assert!(
        matches!(error, latchkey::crypto::Error::Stale),
        "expected stale-commit error, got: {error}"
    );

    // The item is still live in the same session. open_item on this session
    // would legitimately fail (disk moved on); the invariant is that the
    // failed delete did not mutate the session: the entry is live and the
    // previously cached record (from the add) is still cached.
    let entry = vault
        .entries()
        .iter()
        .find(|e| e.item_id == id)
        .expect("entry must remain after a failed delete");
    assert_eq!(
        entry.state,
        latchkey::vault::shape::LIVE_STATE,
        "failed delete must leave the item live"
    );
    assert_eq!(
        vault
            .open_record(entry.slot)
            .and_then(|record| record.password.as_deref()),
        Some(b"keep-secret".as_slice()),
        "the record added in this session must remain cached"
    );

    // And it is still live and readable after reopening from disk.
    let mut reopened = Vault::open(&path, &password).unwrap();
    let live = reopened
        .entries()
        .iter()
        .filter(|e| e.state == latchkey::vault::shape::LIVE_STATE)
        .count();
    assert_eq!(live, 2, "the failed delete must not reach disk");
    reopened.open_item(id).unwrap();
    let entry = reopened.entries().iter().find(|e| e.item_id == id).unwrap();
    assert_eq!(
        reopened
            .open_record(entry.slot)
            .unwrap()
            .password
            .as_deref(),
        Some(b"keep-secret".as_slice())
    );

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// (d) A successful import is one commit: the encryption counter jumps by
/// exactly the expected amount (one per newly encrypted item frame plus one
/// for the index), not one per intermediate record.
#[test]
fn successful_import_is_a_single_commit() {
    let path = tmp_vault("import");
    let password = pw("txn-master");
    let mut vault = Vault::create(
        &path,
        &password,
        test_kdf(),
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Gcm,
    )
    .unwrap();

    let adds: Vec<latchkey::ops::ImportedEntry> = (0..5)
        .map(|n| latchkey::ops::ImportedEntry {
            title: format!("imported-{n}.example"),
            username: "alice".into(),
            record: sample_record(),
        })
        .collect();
    // Plus one update against an existing item: 5 adds + 1 update = 6
    // newly encrypted item frames + 1 index = 7 encryptions in ONE save.
    let existing_id = add_entry(&mut vault, new_entry("existing.example", b"old")).unwrap();
    let updates = vec![latchkey::ops::ImportedUpdate {
        item_id: existing_id,
        record: sample_record(),
    }];

    let counter_before = vault.config().enc_counter;
    latchkey::ops::apply_import(&mut vault, adds, updates).unwrap();
    let counter_after = vault.config().enc_counter;
    assert_eq!(
        counter_after - counter_before,
        7,
        "one commit must encrypt exactly 6 item frames plus the index"
    );

    // The disk reflects one coherent commit with everything applied.
    let reopened = Vault::open(&path, &password).unwrap();
    assert_eq!(
        reopened
            .entries()
            .iter()
            .filter(|e| e.state == latchkey::vault::shape::LIVE_STATE)
            .count(),
        6
    );
    assert_eq!(reopened.config().enc_counter, counter_after);

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
