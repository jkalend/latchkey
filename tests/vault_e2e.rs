//! Integration tests over real vault files (DEVELOPMENT.md "Testing
//! expectations"). These exercise the full stack: KDF → wrap → index → items →
//! atomic write → reopen, plus the generator and TOTP layers on top.

use rpass::crypto::ciphers::Algorithm;
use rpass::crypto::kdf::{KdfParams, SecretVec};
use rpass::gen::{GenerateSpec, Preset};
use rpass::totp::{totp_at, TotpParams};
use rpass::vault::shape::{IndexEntry, ItemRecord, TotpAlgorithm, TotpSubRecord};
use rpass::vault::vault_impl::Vault;
use secrecy::ExposeSecret;

fn pw(s: &str) -> SecretVec {
    SecretVec::new(s.as_bytes().to_vec().into_boxed_slice())
}

fn tmp_vault(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rpass_it_{}_{}_{}",
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
    assert_eq!(v.entries.len(), 2);
    // Duplicate titles are valid (Q7) — both live under "example.com".
    assert_eq!(
        v.entries
            .iter()
            .filter(|e| e.title == "example.com")
            .count(),
        2
    );

    for entry in v.entries.clone() {
        v.open_item(entry.item_id).unwrap();
        let rec = &v.open_items[&entry.slot];
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
            .entries
            .iter()
            .find(|e| e.title == "drop")
            .unwrap()
            .clone();
        let idx = v
            .entries
            .iter()
            .position(|e| e.item_id == victim.item_id)
            .unwrap();
        v.entries[idx].state = 0xFF;
        v.open_items.remove(&victim.slot);
        v.save().unwrap();
    }

    let v = Vault::open(&path, &password).unwrap();
    let live: Vec<&IndexEntry> = v.entries.iter().filter(|e| e.state != 0xFF).collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].title, "keep");

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
        let id = v.entries[0].item_id;
        v.open_item(id).unwrap();
        assert_eq!(
            v.open_items[&v.entries[0].slot].password.as_deref(),
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
    let id = v.entries[0].item_id;
    v.open_item(id).unwrap();
    assert_eq!(
        v.open_items[&v.entries[0].slot].password.as_deref(),
        Some(g.value.as_bytes())
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn backup_is_byte_identical() {
    use rpass::vault::atomic_write::atomic_write;
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
    assert_eq!(v.entries.len(), 1);

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

    // Reopen, mutate username (index) + password (item) in one save.
    {
        let mut v = Vault::open(&path, &password).unwrap();
        let entry = v.entries[0].clone();
        v.open_item(entry.item_id).unwrap();
        let mut rec = v.open_items.get(&entry.slot).unwrap().clone();
        rec.password = Some(b"new-password-42".to_vec());
        rec.url = "https://example.org".into();
        rec.modified_unix += 1;
        v.entries[0].username = "alice2".into();
        v.open_items.insert(entry.slot, rec);
        v.save().unwrap();
    }

    let mut v = Vault::open(&path, &password).unwrap();
    assert_eq!(v.entries[0].username, "alice2");
    v.open_item(v.entries[0].item_id).unwrap();
    let rec = v.open_items.values().next().unwrap();
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

    // Rotate with everything open: all frames must re-encrypt under the new DEK.
    {
        let mut v = Vault::open(&path, &password).unwrap();
        for e in &v.entries.clone() {
            v.open_item(e.item_id).unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        v.rotate(&password).unwrap();
        let after = std::fs::read(&path).unwrap();
        // Same plaintext content, completely different ciphertext.
        assert_ne!(before, after);
    }

    // Reopen with the same password; KDF params are now the production defaults.
    {
        let mut v = Vault::open(&path, &password).unwrap();
        let def = KdfParams::default();
        assert_eq!(v.header.kdf_params.argon2_m_mib, def.argon2_m_mib);
        assert_eq!(v.header.kdf_params.argon2_t, def.argon2_t);
        assert_eq!(v.entries.len(), 2);
        v.open_item(v.entries[0].item_id).unwrap();
        let rec = v.open_items.values().next().unwrap();
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
        let dek_before = v.dek.expose_secret().to_vec();
        v.change_password(&new_password).unwrap();
        // Same DEK — only the wrap changed.
        assert_eq!(dek_before, v.dek.expose_secret().to_vec());
    }

    // Old password fails, new one opens the same content.
    assert!(Vault::open(&path, &password).is_err());
    {
        let mut v = Vault::open(&path, &new_password).unwrap();
        assert_eq!(v.entries.len(), 1);
        v.open_item(v.entries[0].item_id).unwrap();
        let rec = v.open_items.values().next().unwrap();
        assert_eq!(
            rec.password.as_deref(),
            Some(b"correct horse battery staple".as_ref())
        );
    }

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
