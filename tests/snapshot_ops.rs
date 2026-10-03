//! One authenticated snapshot serves bulk reads (export/rotation): the file
//! is read and MAC-verified once, and every record decrypts from that image.

use latchkey::crypto::ciphers::Algorithm;
use latchkey::crypto::kdf::{KdfParams, SecretVec};
use latchkey::vault::shape::ItemRecord;
use latchkey::vault::vault_impl::Vault;
use std::path::PathBuf;

fn pw(s: &str) -> SecretVec {
    SecretVec::new(s.as_bytes().to_vec().into_boxed_slice())
}

fn tmp_vault(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "latchkey_snap_{tag}_{}_{}",
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

fn record(n: u8) -> ItemRecord {
    ItemRecord {
        password: Some(vec![b'a' + n; 24]),
        url: String::new(),
        notes: Some(vec![b'n'; 16]),
        totp: None,
        created_unix: 1,
        modified_unix: 1,
    }
}

#[test]
fn snapshot_serves_bulk_reads_and_rejects_disk_changes() {
    let path = tmp_vault("bulk");
    let password = pw("snap-master");
    let mut vault = Vault::create(
        &path,
        &password,
        test_kdf(),
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Gcm,
    )
    .unwrap();
    let mut ids = Vec::new();
    for n in 0..6u8 {
        let id = vault
            .add_item(format!("item-{n}"), format!("user-{n}"), record(n))
            .unwrap();
        ids.push(id);
    }
    vault.save().unwrap();

    // The snapshot decrypts every record from one image.
    let snapshot = vault.snapshot().unwrap();
    assert_eq!(snapshot.frame_count(), vault.entries().len());
    for entry in vault.entries().to_vec() {
        let rec = snapshot.decrypt_item(&entry).unwrap();
        assert_eq!(
            rec.password.as_deref(),
            Some(vec![b'a' + entry.item_id as u8 - 1; 24].as_slice()),
            "record content must match what was stored"
        );
    }
    drop(snapshot);

    // Rotation: all records decrypt from one snapshot and remain correct
    // after the re-encryption under a fresh DEK.
    vault.rotate(&password).unwrap();
    vault.save().unwrap();
    let mut reopened = Vault::open(&path, &password).unwrap();
    for id in ids {
        reopened.open_item(id).unwrap();
    }
    let entry = reopened.entries()[0].clone();
    assert_eq!(
        reopened
            .open_record(entry.slot)
            .unwrap()
            .password
            .as_deref(),
        Some(vec![b'a'; 24].as_slice()),
        "rotation must preserve record content"
    );

    // A snapshot cannot be taken from a session whose disk state changed:
    // the commit-tag match fails.
    let mut other = Vault::open(&path, &password).unwrap();
    other
        .add_item("extra".into(), "u".into(), record(0))
        .unwrap();
    other.save().unwrap();
    drop(other);
    let stale = vault.snapshot();
    assert!(
        matches!(stale, Err(latchkey::crypto::Error::Stale)),
        "external commit must invalidate the session's snapshot"
    );

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn snapshot_rejects_corrupted_disk_even_with_intact_session_cache() {
    let path = tmp_vault("corrupt");
    let password = pw("snap-corrupt");
    let mut vault = Vault::create(
        &path,
        &password,
        test_kdf(),
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Gcm,
    )
    .unwrap();
    let id = vault
        .add_item("kept".into(), "u".into(), record(9))
        .unwrap();
    vault.save().unwrap();
    vault.open_item(id).unwrap(); // session cache populated

    // Corrupt one ciphertext byte on disk.
    let mut bytes = std::fs::read(&path).unwrap();
    let len = bytes.len();
    bytes[len - 60] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    assert!(
        matches!(vault.snapshot(), Err(latchkey::crypto::Error::Decrypt)),
        "corrupted disk must fail snapshot authentication"
    );
    assert!(
        vault.open_item(id).is_err(),
        "cached item must not conceal a corrupted disk commit"
    );

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
