//! Integration tests over real vault files (DEVELOPMENT.md "Testing
//! expectations"). These exercise the full stack: KDF → wrap → index → items →
//! atomic write → reopen, plus the generator and TOTP layers on top.

use latchkey::crypto::ciphers::Algorithm;
use latchkey::crypto::kdf::{KdfParams, SecretVec};
use latchkey::gen::{GenerateSpec, Preset};
use latchkey::totp::{totp_at, TotpParams};
use latchkey::vault::shape::{IndexEntry, ItemRecord, TotpAlgorithm, TotpSubRecord};
use latchkey::vault::vault_impl::Vault;

fn pw(s: &str) -> SecretVec {
    SecretVec::new(s.as_bytes().to_vec().into_boxed_slice())
}

fn tmp_vault(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "latchkey_it_{}_{}_{}",
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

fn sample_item(totp: bool) -> ItemRecord {
    let now = 1_700_000_000;
    ItemRecord {
        password: Some(b"correct horse battery staple".to_vec()),
        url: "https://example.com".to_string(),
        notes: Some(b"some notes".to_vec()),
        totp: totp.then(|| TotpSubRecord {
            // base32("12345678901234567890") — RFC 6238 test secret
            secret: b"12345678901234567890".to_vec(),
            period: 30,
            digits: 6,
            algorithm: TotpAlgorithm::Sha1,
        }),
        created_unix: now,
        modified_unix: now,
    }
}

#[test]
fn full_roundtrip_multiple_items_with_totp() {
    let path = tmp_vault("rt");
    let password = pw("integration-master-pw");

    {
        let mut v = Vault::create(
            &path,
            &password,
            test_kdf(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        let rec1 = sample_item(true);
        let rec2 = sample_item(false);
        v.add_item("example.com".into(), "alice".into(), rec1.clone())
            .unwrap();
        v.add_item("example.com".into(), "bob".into(), rec2)
            .unwrap();
        v.save().unwrap();
    }

    let mut v = Vault::open(&path, &password).unwrap();
    assert_eq!(v.entries().len(), 2);
    // Duplicate titles are valid (Q7) — both live under "example.com".
    assert_eq!(
        v.entries()
            .iter()
            .filter(|e| e.title == "example.com")
            .count(),
        2
    );

    for entry in v.entries().to_vec() {
        v.open_item(entry.item_id).unwrap();
        let rec = v.open_record(entry.slot).unwrap();
        assert_eq!(
            rec.password.as_deref(),
            Some(b"correct horse battery staple".as_slice())
        );
        assert_eq!(rec.url, "https://example.com");

        if entry.username == "alice" {
            let t = rec.totp.as_ref().expect("alice has TOTP");
            let params = TotpParams::from(t);
            assert_eq!(totp_at(&params, 59).unwrap(), "287082"); // RFC 6238 counter-1, 6 digits
        } else {
            assert!(rec.totp.is_none());
        }
    }

    // Wrong password fails opaquely (CRYPTO_SPEC §7: no oracle).
    assert!(Vault::open(&path, &pw("wrong")).is_err());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn delete_then_reopen_preserves_others() {
    let path = tmp_vault("rm");
    let password = pw("pw");

    {
        let mut v = Vault::create(
            &path,
            &password,
            test_kdf(),
            Algorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305,
        )
        .unwrap();
        v.add_item("keep".into(), "u".into(), sample_item(false))
            .unwrap();
        v.add_item("drop".into(), "u".into(), sample_item(false))
            .unwrap();
        v.save().unwrap();
    }

    {
        let mut v = Vault::open(&path, &password).unwrap();
        let victim = v
            .entries()
            .iter()
            .find(|e| e.title == "drop")
            .unwrap()
            .clone();
        latchkey::ops::delete_entry(&mut v, victim.item_id).unwrap();
    }

    let mut v = Vault::open(&path, &password).unwrap();
    let live: Vec<&IndexEntry> = v
        .entries()
        .iter()
        .filter(|e| e.state == latchkey::vault::shape::LIVE_STATE)
        .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].title, "keep");
    let new_id = v
        .add_item("new".into(), "u".into(), sample_item(false))
        .unwrap();
    assert_eq!(new_id, 3);
    v.save().unwrap();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn tamper_detection_bitflip() {
    let path = tmp_vault("tamper");
    let password = pw("pw");

    {
        let mut v = Vault::create(
            &path,
            &password,
            test_kdf(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        v.add_item("sensitive".into(), "u".into(), sample_item(false))
            .unwrap();
        v.save().unwrap();
    }

    let raw = std::fs::read(&path).unwrap();
    let mut flipped = raw.clone();
    // Flip a byte in the item ciphertext region (well past the 117-byte header
    // + index frame).
    let idx = flipped.len() / 2;
    flipped[idx] ^= 0xFF;
    let len = flipped.len();
    let crc = crc32c::crc32c(&flipped[..len - 40]);
    flipped[len - 36..len - 32].copy_from_slice(&crc.to_be_bytes());

    std::fs::write(&path, &flipped).unwrap();
    let err = Vault::open(&path, &password);
    assert!(err.is_err(), "tampered vault must not open");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn cross_algorithm_vaults_roundtrip() {
    for (wrap, item) in [
        (Algorithm::Aes256Gcm, Algorithm::Aes256Gcm),
        (Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305),
        (Algorithm::ChaCha20Poly1305, Algorithm::Aes256Gcm),
        (Algorithm::ChaCha20Poly1305, Algorithm::ChaCha20Poly1305),
    ] {
        let path = tmp_vault("algos");
        let password = pw("pw");
        {
            let mut v = Vault::create(&path, &password, test_kdf(), wrap, item).unwrap();
            v.add_item("x".into(), "u".into(), sample_item(false))
                .unwrap();
            v.save().unwrap();
        }
        let mut v = Vault::open(&path, &password).unwrap();
        let id = v.entries()[0].item_id;
        v.open_item(id).unwrap();
        assert_eq!(
            v.open_record(v.entries()[0].slot)
                .unwrap()
                .password
                .as_deref(),
            Some(b"correct horse battery staple".as_slice())
        );
        let _ = std::fs::remove_file(&path);
    }
}

#[test]
fn generator_feeds_vault_roundtrip() {
    // The `add --generate` path: generator output stored verbatim.
    let path = tmp_vault("gen");
    let password = pw("pw");
    let g = GenerateSpec {
        preset: Preset::WithSymbols,
        ..Default::default()
    }
    .generate()
    .unwrap();
    assert!(g.entropy_bits > 120.0);

    {
        let mut v = Vault::create(
            &path,
            &password,
            test_kdf(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        v.add_item(
            "generated".into(),
            "u".into(),
            ItemRecord {
                password: Some(g.value.clone().into_bytes()),
                url: String::new(),
                notes: None,
                totp: None,
                created_unix: 1,
                modified_unix: 1,
            },
        )
        .unwrap();
        v.save().unwrap();
    }

    let mut v = Vault::open(&path, &password).unwrap();
    let id = v.entries()[0].item_id;
    v.open_item(id).unwrap();
    assert_eq!(
        v.open_record(v.entries()[0].slot)
            .unwrap()
            .password
            .as_deref(),
        Some(g.value.as_bytes())
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn backup_is_byte_identical() {
    use latchkey::vault::atomic_write::atomic_write;
    let path = tmp_vault("bak");
    let backup = path.parent().unwrap().join("backup.bin");
    let password = pw("pw");

    {
        let mut v = Vault::create(
            &path,
            &password,
            test_kdf(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        v.add_item("x".into(), "u".into(), sample_item(false))
            .unwrap();
        v.save().unwrap();
    }

    let data = std::fs::read(&path).unwrap();
    atomic_write(&backup, &data).unwrap();
    assert_eq!(std::fs::read(&backup).unwrap(), data);

    // The backup opens as a vault with the same password.
    let v = Vault::open(&backup, &password).unwrap();
    assert_eq!(v.entries().len(), 1);

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn edit_updates_index_and_item_atomically() {
    let path = tmp_vault("edit");
    let password = pw("edit-master-pw");

    {
        let mut v = Vault::create(
            &path,
            &password,
            test_kdf(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        v.add_item("example.com".into(), "alice".into(), sample_item(false))
            .unwrap();
        v.save().unwrap();
    }

    // Reopen, mutate username (index) + password (item) in one ops commit.
    {
        let mut v = Vault::open(&path, &password).unwrap();
        let entry = v.entries()[0].clone();
        v.open_item(entry.item_id).unwrap();
        assert!(latchkey::ops::update_entry(
            &mut v,
            entry.item_id,
            latchkey::ops::EntryPatch {
                username: Some("alice2".into()),
                password: latchkey::ops::Change::Set(b"new-password-42".to_vec()),
                url: Some("https://example.org".into()),
                ..latchkey::ops::EntryPatch::default()
            }
        )
        .unwrap());
    }

    let mut v = Vault::open(&path, &password).unwrap();
    assert_eq!(v.entries()[0].username, "alice2");
    v.open_item(v.entries()[0].item_id).unwrap();
    let rec = v.open_record(v.entries()[0].slot).unwrap();
    assert_eq!(rec.password.as_deref(), Some(b"new-password-42".as_ref()));
    assert_eq!(rec.url, "https://example.org");

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn rotate_reencrypts_under_new_dek_and_kdf() {
    let path = tmp_vault("rot");
    let password = pw("rotate-master-pw");

    {
        let mut v = Vault::create(
            &path,
            &password,
            test_kdf(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        v.add_item("a".into(), "ua".into(), sample_item(true))
            .unwrap();
        v.add_item("b".into(), "ub".into(), sample_item(false))
            .unwrap();
        v.save().unwrap();
    }

    // Rotate opens all live items internally before swapping the DEK.
    {
        let mut v = Vault::open(&path, &password).unwrap();
        let before = std::fs::read(&path).unwrap();
        v.rotate(&password).unwrap();
        let after = std::fs::read(&path).unwrap();
        assert_ne!(before, after);
    }

    // Reopen with the same password; KDF params are now the production defaults.
    {
        let mut v = Vault::open(&path, &password).unwrap();
        let def = KdfParams::default();
        assert_eq!(v.config().kdf_params.argon2_m_mib, def.argon2_m_mib);
        assert_eq!(v.config().kdf_params.argon2_t, def.argon2_t);
        assert_eq!(v.entries().len(), 2);
        v.open_item(v.entries()[0].item_id).unwrap();
        let rec = v.open_record(v.entries()[0].slot).unwrap();
        assert_eq!(
            rec.password.as_deref(),
            Some(b"correct horse battery staple".as_ref())
        );
        // TOTP still works after rotation.
        if let Some(t) = &rec.totp {
            let code = totp_at(&TotpParams::from(t), 59).unwrap();
            assert_eq!(code.len(), 6);
        }
    }

    // Old password still works (rotate is not a password change).
    assert!(Vault::open(&path, &password).is_ok());

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn change_password_rewraps_same_dek() {
    let path = tmp_vault("pw");
    let password = pw("original-master-pw");
    let new_password = pw("a-fresh-master-pw");

    {
        let mut v = Vault::create(
            &path,
            &password,
            test_kdf(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        v.add_item("x".into(), "u".into(), sample_item(true))
            .unwrap();
        v.save().unwrap();
        let dek_before = v.dek_fingerprint();
        v.change_password(&new_password).unwrap();
        // Same DEK — only the wrap changed.
        assert_eq!(dek_before, v.dek_fingerprint());
    }

    // Old password fails, new one opens the same content.
    assert!(Vault::open(&path, &password).is_err());
    {
        let mut v = Vault::open(&path, &new_password).unwrap();
        assert_eq!(v.entries().len(), 1);
        v.open_item(v.entries()[0].item_id).unwrap();
        let rec = v.open_record(v.entries()[0].slot).unwrap();
        assert_eq!(
            rec.password.as_deref(),
            Some(b"correct horse battery staple".as_ref())
        );
    }

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// The full export → import round trip through the CLI's own JSON emitter
/// and the hand-rolled JSON reader: what comes out must go back in intact.
#[test]
fn export_import_roundtrip() {
    use latchkey::cli::export_item_json;
    use latchkey::cli::import::import_into;

    let path = tmp_vault("imp");
    let password = pw("import-master-pw");
    let original = sample_item(true);

    // Build a vault with two items, then "export" via the CLI's own emitter.
    let export = {
        let mut v = Vault::create(
            &path,
            &password,
            test_kdf(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        v.add_item("example.com".into(), "alice".into(), original.clone())
            .unwrap();
        v.add_item("github.com".into(), "bob".into(), sample_item(false))
            .unwrap();
        v.add_item(
            "note.example".into(),
            "carol".into(),
            ItemRecord {
                password: None,
                url: "https://note.example".into(),
                notes: None,
                totp: None,
                created_unix: 1_700_000_000,
                modified_unix: 1_700_000_000,
            },
        )
        .unwrap();
        v.save().unwrap();

        let live: Vec<latchkey::vault::shape::IndexEntry> = v
            .entries()
            .iter()
            .filter(|e| e.state != 0xFF)
            .cloned()
            .collect();
        let mut items = Vec::new();
        for e in &live {
            v.open_item(e.item_id).unwrap();
            let rec = v.open_record(e.slot).unwrap().clone();
            items.push(export_item_json(e, &rec));
        }
        format!(
            "{{\n  \"format_version\": 1,\n  \"exported_at\": 99,\n  \"items\": {{\n{}\n  }}\n}}\n",
            items.join(",\n")
        )
    };

    // Import into a fresh vault under a DIFFERENT password.
    let fresh = tmp_vault("imp2");
    let fresh_pw = pw("fresh-master-pw");
    {
        let mut v = Vault::create(
            &fresh,
            &fresh_pw,
            test_kdf(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap();
        // pure adds (fresh vault) → yes=true may skip the prompt
        import_into(&mut v, &export, false, true).unwrap();
    }

    // Verify both items came through with the same plaintext.
    let ids_by_title: std::collections::HashMap<String, u32> = {
        let mut v = Vault::open(&fresh, &fresh_pw).unwrap();
        assert_eq!(v.entries().len(), 3);
        let map: std::collections::HashMap<String, u32> = v
            .entries()
            .iter()
            .map(|e| (e.title.clone(), e.item_id))
            .collect();
        let ex_id = *map.get("example.com").unwrap();
        let gh_id = *map.get("github.com").unwrap();
        let note_id = *map.get("note.example").unwrap();
        assert_ne!(ex_id, gh_id);
        assert_ne!(ex_id, note_id);

        v.open_item(ex_id).unwrap();
        let ex_entry = v
            .entries()
            .iter()
            .find(|e| e.item_id == ex_id)
            .unwrap()
            .clone();
        let rec = v.open_record(ex_entry.slot).unwrap().clone();
        assert_eq!(rec.password, original.password);
        assert_eq!(rec.url, original.url);
        assert_eq!(rec.notes, original.notes);
        assert_eq!(rec.totp, original.totp);

        v.open_item(note_id).unwrap();
        let note_entry = v
            .entries()
            .iter()
            .find(|e| e.item_id == note_id)
            .unwrap()
            .clone();
        let note_rec = v.open_record(note_entry.slot).unwrap().clone();
        assert_eq!(note_rec.password, None);
        assert_eq!(note_rec.notes, None);
        assert_eq!(note_rec.totp, None);
        assert_eq!(note_rec.url, "https://note.example");

        v.open_item(gh_id).unwrap();
        map
    };

    // Now the update path: re-import the same export; both titles match
    // exactly one live entry each → updates, item ids preserved. Confirm is
    // required (updates exist) and stdin is not a terminal in tests, so the
    // run must refuse rather than silently overwrite.
    {
        let mut v = Vault::open(&fresh, &fresh_pw).unwrap();
        let refused = import_into(&mut v, &export, false, true);
        assert!(
            refused.is_err(),
            "import with updates must not --yes past the prompt"
        );
        // --dry-run of the same import must succeed and change nothing.
        import_into(&mut v, &export, true, false).unwrap();
        drop(v);
        let check = Vault::open(&fresh, &fresh_pw).unwrap();
        assert_eq!(check.entries().len(), 3);
        for e in check.entries() {
            assert_eq!(
                e.item_id,
                *ids_by_title.get(&e.title).unwrap(),
                "dry-run must not rewrite items"
            );
        }
    }

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
    let _ = std::fs::remove_dir_all(fresh.parent().unwrap());
}

fn repair_crc(bytes: &mut [u8]) {
    let len = bytes.len();
    let crc = crc32c::crc32c(&bytes[..len - 40]);
    bytes[len - 36..len - 32].copy_from_slice(&crc.to_be_bytes());
}

fn index_end(bytes: &[u8]) -> usize {
    133 + u32::from_be_bytes(bytes[129..133].try_into().unwrap()) as usize
}

#[test]
fn historical_index_and_item_splices_rejected_on_every_read_and_save_path() {
    let path = tmp_vault("splice");
    let password = pw("splice-password");
    let mut vault = Vault::create(
        &path,
        &password,
        test_kdf(),
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Gcm,
    )
    .unwrap();
    let id = vault
        .add_item("old-title".into(), "user".into(), sample_item(false))
        .unwrap();
    vault.save().unwrap();
    let old = std::fs::read(&path).unwrap();
    // Produce a second commit through the public seam: an edit rewrites the
    // index (title) and the item (password) in one save.
    assert!(latchkey::ops::update_entry(
        &mut vault,
        id,
        latchkey::ops::EntryPatch {
            title: Some("new-title".into()),
            password: latchkey::ops::Change::Set(b"replacement-password".to_vec()),
            ..latchkey::ops::EntryPatch::default()
        }
    )
    .unwrap());
    let current = std::fs::read(&path).unwrap();
    drop(vault);
    let old_index_end = index_end(&old);
    let new_index_end = index_end(&current);

    for replace_index in [true, false] {
        std::fs::write(&path, &current).unwrap();
        let mut lazy = Vault::open(&path, &password).unwrap();
        let mut cached = Vault::open(&path, &password).unwrap();
        cached.open_item(id).unwrap();
        let mut splice = current[..117].to_vec();
        if replace_index {
            splice.extend_from_slice(&old[117..old_index_end]);
            splice.extend_from_slice(&current[new_index_end..]);
        } else {
            splice.extend_from_slice(&current[117..new_index_end + 4]);
            splice.extend_from_slice(&old[old_index_end + 4..old.len() - 40]);
            splice.extend_from_slice(&current[current.len() - 40..]);
        }
        repair_crc(&mut splice);
        std::fs::write(&path, &splice).unwrap();
        assert!(matches!(
            Vault::open(&path, &password),
            Err(latchkey::crypto::Error::Decrypt)
        ));
        assert!(matches!(
            lazy.open_item(id),
            Err(latchkey::crypto::Error::Decrypt)
        ));
        assert!(
            !lazy.has_open_records(),
            "failed authentication must not populate cache"
        );
        assert!(
            matches!(cached.open_item(id), Err(latchkey::crypto::Error::Decrypt)),
            "cache cannot hide corrupt disk"
        );
        assert!(matches!(
            lazy.verify_all_items(),
            Err(latchkey::crypto::Error::Decrypt)
        ));
        assert!(matches!(lazy.save(), Err(latchkey::crypto::Error::Decrypt)));
        assert_eq!(std::fs::read(&path).unwrap(), splice);
    }
    std::fs::write(&path, &current).unwrap();
    assert_eq!(
        Vault::open(&path, &password)
            .unwrap()
            .verify_all_items()
            .unwrap(),
        (1, 0)
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn explicit_migration_preserves_legacy_fixture_and_refuses_existing_target() {
    let source = std::path::Path::new("test-vectors/vault-legacy-v1.bin");
    let original = std::fs::read(source).unwrap();
    let password = pw("test-vector-master-password");
    let target = tmp_vault("migration");
    assert!(Vault::open(source, &password).is_err());
    let mut migrated = Vault::migrate(source, &target, &password).unwrap();
    assert_eq!(std::fs::read(source).unwrap(), original);
    assert_eq!(migrated.next_item_id(), 4);
    assert_eq!(migrated.config().version, 2);
    assert_eq!(migrated.verify_all_items().unwrap(), (3, 0));
    let mut golden = Vault::open(
        std::path::Path::new("test-vectors/vault-golden.bin"),
        &password,
    )
    .unwrap();
    assert_eq!(migrated.entries(), golden.entries());
    for entry in migrated.entries().to_vec() {
        migrated.open_item(entry.item_id).unwrap();
        golden.open_item(entry.item_id).unwrap();
        assert_eq!(
            migrated.open_record(entry.slot).unwrap(),
            golden.open_record(entry.slot).unwrap()
        );
    }
    let committed = std::fs::read(&target).unwrap();
    assert!(Vault::migrate(source, &target, &password).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), committed);
    assert_eq!(std::fs::read(source).unwrap(), original);
    assert!(Vault::migrate(&target, &target.with_extension("another"), &password).is_err());
    let _ = std::fs::remove_dir_all(target.parent().unwrap());
}
