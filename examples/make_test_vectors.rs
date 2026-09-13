//! Build the golden test-vector vault (test-vectors/README.md documents the
//! procedure and the cross-check). Deterministic given the password — every
//! random input is either pinned here or irrelevant to the expected output.
//!
//! Run: cargo run --release --example make_test_vectors

use latchkey::crypto::ciphers::Algorithm;
use latchkey::crypto::kdf::{KdfParams, SecretVec};
use latchkey::vault::shape::{ItemRecord, TotpAlgorithm, TotpSubRecord};
use latchkey::vault::vault_impl::Vault;

fn pw(s: &str) -> SecretVec {
    SecretVec::new(s.as_bytes().to_vec().into_boxed_slice())
}

fn main() {
    let dir = std::path::Path::new("test-vectors");
    std::fs::create_dir_all(dir).unwrap();

    // Fast KDF so the cross-check isn't dominated by Argon2; the crypto
    // under test (wrap, index, items) is identical regardless of KDF cost.
    let kdf = KdfParams::new(8, 1, 1).unwrap();
    let password = pw("test-vector-master-password");

    let path = dir.join("vault-golden.bin");
    let _ = std::fs::remove_file(&path);

    let mut v = Vault::create(
        &path,
        &password,
        kdf,
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Gcm,
    )
    .unwrap();

    let now: u64 = 1_750_000_000;
    let items: Vec<(&str, &str, ItemRecord)> = vec![
        (
            "example.com",
            "alice",
            ItemRecord {
                password: Some(b"correct horse battery staple".to_vec()),
                url: "https://example.com/login".into(),
                notes: Some(b"work account".to_vec()),
                totp: Some(TotpSubRecord {
                    secret: b"12345678901234567890".to_vec(), // RFC 6238 secret
                    period: 30,
                    digits: 6,
                    algorithm: TotpAlgorithm::Sha1,
                }),
                created_unix: now,
                modified_unix: now,
            },
        ),
        (
            "github.com",
            "bob",
            ItemRecord {
                password: Some(b"Tr0ub4dor&3".to_vec()),
                url: String::new(),
                notes: None,
                totp: None,
                created_unix: now,
                modified_unix: now,
            },
        ),
        (
            "github.com",
            "bob-personal",
            ItemRecord {
                password: None,
                url: "https://github.com".into(),
                notes: Some(b"token in the totp slot? no - plain note".to_vec()),
                totp: None,
                created_unix: now,
                modified_unix: now,
            },
        ),
    ];
    for (title, user, rec) in items {
        v.add_item(title.into(), user.into(), rec).unwrap();
    }
    v.save().unwrap();

    // Expected content — what cross_check.py must print for this vault.
    let expected = concat!(
    "  1 example.com              alice        pw='correct horse battery staple' url='https://example.com/login' totp=SHA1 notes=b'work account' created=1750000000\n",
    "  2 github.com               bob          pw='Tr0ub4dor&3' url='' totp=None notes=None created=1750000000\n",
    "  3 github.com               bob-personal pw=None url='https://github.com' totp=None notes=b'token in the totp slot? no - plain note' created=1750000000\n",
    );
    std::fs::write(dir.join("expected.txt"), expected).unwrap();
    println!(
        "wrote {} ({} bytes)",
        path.display(),
        std::fs::metadata(&path).unwrap().len()
    );
    println!("wrote {}", dir.join("expected.txt").display());
}
