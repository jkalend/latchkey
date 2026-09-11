//! Golden vault vectors (test-vectors/README.md).
//!
//! test-vectors/vault-golden.bin is produced by `cargo run --release
//! --example make_test_vectors` and independently decrypted by
//! test-vectors/cross_check.py (Python: argon2-cffi + cryptography, zero
//! rpass code). If both the Python reader and this Rust reader agree on
//! the contents, the format implementation matches the spec, not just
//! itself.
//!
//! The committed vault's salts/nonces are random per regeneration, so this
//! test can't assert exact bytes — it asserts the STRUCTURE: correct
//! entries, correct decrypted plaintext, correct CRC, and that a
//! bit-flip anywhere in the body is rejected.

use rpass::crypto::kdf::SecretVec;
use rpass::vault::vault_impl::Vault;

const PASSWORD: &str = "test-vector-master-password";

fn pw(s: &str) -> SecretVec {
    SecretVec::new(s.as_bytes().to_vec().into_boxed_slice())
}

#[test]
fn golden_vault_reads_back() {
    let path = std::path::Path::new("test-vectors/vault-golden.bin");
    if !path.exists() {
        panic!(
            "golden vault missing — run `cargo run --release --example make_test_vectors` first"
        );
    }

    let mut v = Vault::open(path, &pw(PASSWORD)).expect("golden vault must open");
    assert_eq!(v.entries.len(), 3);

    let expected = std::fs::read_to_string("test-vectors/expected.txt").unwrap();
    for (entry, line) in v.entries.iter().zip(expected.lines()) {
        let rendered = format!(
            "{:>3} {:<24} {:<12}",
            entry.item_id, entry.title, entry.username
        );
        assert!(line.starts_with(&rendered), "line '{line}' vs '{rendered}'");
    }

    // Spot-check every item's decrypted content.
    for e in v.entries.clone() {
        v.open_item(e.item_id).unwrap();
        let rec = v.open_items.get(&e.slot).unwrap();

        match e.item_id {
            1 => {
                assert_eq!(
                    rec.password.as_deref(),
                    Some(b"correct horse battery staple".as_ref())
                );
                assert_eq!(rec.url, "https://example.com/login");
                assert_eq!(rec.notes.as_deref(), Some(b"work account".as_ref()));
                let t = rec.totp.as_ref().expect("item 1 has TOTP");
                assert_eq!(t.secret, b"12345678901234567890");
                assert_eq!(t.period, 30);
                assert_eq!(t.digits, 6);
            }
            2 => {
                assert_eq!(rec.password.as_deref(), Some(b"Tr0ub4dor&3".as_ref()));
                assert_eq!(rec.url, "");
                assert!(rec.notes.is_none());
                assert!(rec.totp.is_none());
            }
            3 => {
                assert!(rec.password.is_none());
                assert_eq!(rec.url, "https://github.com");
                assert!(rec.totp.is_none());
            }
            _ => panic!("unexpected item_id {}", e.item_id),
        }
    }

    // Wrong password must fail (generic error — indistinguishable from
    // corruption by design, CRYPTO_SPEC §7).
    assert!(Vault::open(path, &pw("wrong-password")).is_err());
}

#[test]
fn golden_vault_bit_flip_rejected_everywhere() {
    let path = std::path::Path::new("test-vectors/vault-golden.bin");
    if !path.exists() {
        panic!(
            "golden vault missing — run `cargo run --release --example make_test_vectors` first"
        );
    }
    let original = std::fs::read(path).unwrap();

    // Flip one bit at a spread of offsets: header, index, items, trailer.
    for &off in &[
        4usize,             // kdf_id
        19,                 // salt
        51,                 // wrapped_dek
        100,                // future_pad
        120,                // index frame
        130,                // index ciphertext
        130 + 70,           // mid items region
        original.len() - 8, // trailer slot_count
        original.len() - 4, // trailer crc
    ] {
        let mut corrupted = original.clone();
        corrupted[off] ^= 0x01;
        let tmp =
            std::env::temp_dir().join(format!("rpass_golden_flip_{}_{}", off, std::process::id()));
        std::fs::write(&tmp, &corrupted).unwrap();
        let opened = Vault::open(&tmp, &pw(PASSWORD));
        // Every flip must be rejected: either the AEAD tag, the CRC, or a
        // structural check fires. If any flip opens cleanly, that byte is
        // unauthenticated.
        assert!(
            opened.is_err(),
            "bit flip at offset {off} was ACCEPTED — unauthenticated field"
        );
        let _ = std::fs::remove_file(&tmp);
    }
}
