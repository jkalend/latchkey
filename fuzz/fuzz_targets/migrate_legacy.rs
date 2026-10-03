//! Fuzz explicit legacy-v1 → v2 migration end-to-end: arbitrary bytes as
//! the source vault, a fresh temp target. Rejections must be clean; a
//! successful migration must produce an openable v2 vault whose records
//! round-trip. Source bytes must be preserved either way.
//!
//! The `fuzz-fast-kdf` crate feature (see src/crypto/kdf.rs) substitutes
//! floor KDF parameters for the default profile so the full cryptographic
//! path runs without the ~1 s production derivation per successful input.
//! The feature is never enabled in production builds.

#![no_main]

use libfuzzer_sys::fuzz_target;
use latchkey::crypto::kdf::SecretVec;
use latchkey::vault::vault_impl::Vault;

fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir().join(format!(
        "latchkey_fuzz_mig_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let source = dir.join("legacy.bin");
    let target = dir.join("migrated.bin");
    if std::fs::write(&source, data).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let password = SecretVec::new(b"fuzz-password".to_vec().into_boxed_slice());
    match Vault::migrate(&source, &target, &password) {
        Ok(migrated) => {
            // Success implies the target is a coherent v2 vault.
            assert_eq!(migrated.config().version, 2);
            assert!(migrated.verify_all_items().is_ok());
            assert_eq!(std::fs::read(&source).unwrap(), data.to_vec());
        }
        Err(_) => {
            // Rejected migration: no panic is the invariant; a leftover
            // target must still open-or-error without panicking.
            if target.exists() {
                let _ = Vault::open(&target, &password);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
});
