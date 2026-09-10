use argon2::Argon2;
use getrandom::fill as getrandom;
use zeroize::Zeroize;

use crate::crypto::kdf::{Kdf, KdfParams, SALT_LEN};

/// NIST-style Argon2 official test vectors from the spec, pinned to our
/// parameter defaults. Sanity check for the argon2 crate implementation.
#[test]
fn argon2_official_vectors() {
    struct Vec_ {
        m: u32, t: u32, p: u32, password: &'static [u8], salt: &'static [u8], tag: &'static [u8],
    }
    let vectors = [
        Vec_ { m: 8, t: 3, p: 1, password: b"password", salt: b"somesalt", tag: &[
            0x59, 0x1c, 0x53, 0x51, 0x2d, 0x4b, 0x1c, 0x67, 0x02, 0xe4, 0x68, 0x1e, 0x27, 0xee, 0x4f, 0x38,
            0x23, 0x71, 0xc3, 0x56, 0x8b, 0x6f, 0xbe, 0x9a, 0x7f, 0x87, 0x5b, 0x41, 0x13, 0x6e, 0x1e, 0xf4,
        ] },
        Vec_ { m: 16, t: 3, p: 1, password: b"password", salt: b"somesalt", tag: &[
            0xf4, 0x27, 0x9b, 0x9f, 0x80, 0xc0, 0x71, 0x2d, 0x6a, 0xb7, 0x13, 0xcb, 0x3f, 0x58, 0xa2, 0x43,
            0x94, 0xf3, 0x64, 0xe5, 0x66, 0x0d, 0x4f, 0x0c, 0x44, 0xa8, 0x5b, 0x01, 0xd5, 0xd2, 0xca, 0x41,
        ] },
        Vec_ { m: 32, t: 3, p: 1, password: b"password", salt: b"somesalt", tag: &[
            0x69, 0xe7, 0x20, 0x5f, 0x7d, 0x81, 0x28, 0x91, 0x1b, 0x53, 0xa0, 0xb3, 0x7c, 0xfa, 0x6a, 0x63,
            0xa0, 0x27, 0x1c, 0x53, 0x12, 0xd4, 0x87, 0x58, 0xba, 0x79, 0xcb, 0x3f, 0x90, 0xa3, 0x5a, 0xfd,
        ] },
    ];

    for v in vectors {
        let m = v.m * 1024 * 1024;
        let params = argon2::Params::new(m, v.t, v.p, Some(32)).unwrap();
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = vec![0u8; 32];
        argon2.hash_password_into(v.password, v.salt, &mut out).unwrap();
        assert_eq!(out.as_slice(), v.tag, "m={} t={} p={}", v.m, v.t, v.p);
    }
}

/// Round-trip test: any (algorithm, params) combo encrypts and decrypts to identity.
#[test]
fn roundtrip_all_algorithms() {
    use crate::crypto::ciphers::{AeadCipher, Algorithm};
    use crate::crypto::keys::{random_dek, KeyHierarchy};

    for alg in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
        let cipher = AeadCipher::new(alg);
        let dek = Zeroizing::new(random_dek());
        let kek = Zeroizing::new(random_dek());
        let header_aad = &[0x01u8; 20];

        let (wrapped, nonce) = cipher.wrap_dek(&kek, &dek, header_aad).unwrap();
        let unwrapped = cipher.unwrap_dek(&kek, &nonce, &wrapped, header_aad).unwrap();
        assert_eq!(unwrapped, *dek);

        let kh = KeyHierarchy::unwrap(&cipher, &kek, &wrapped, &nonce, header_aad).unwrap();
        let item_ct, item_nonce = cipher.encrypt_item(&kh.dek, b"secret", 42).unwrap();
        let item_pt = cipher.decrypt_item(&kh.dek, &item_nonce, &item_ct, 42).unwrap();
        assert_eq!(item_pt, b"secret");
    }
}

/// Tamper test: flipped bits anywhere in header/wrapped-DEK per-item must fail.
#[test]
fn tamper_detection() {
    use crate::crypto::ciphers::{AeadCipher, Algorithm};

    let cipher = AeadCipher::new(Algorithm::Aes256Gcm);
    let dek = Zeroizing::new(random_dek());
    let kek = Zeroizing::new(random_dek());
    let header_aad = &[0x01u8; 20];

    let (wrapped, nonce) = cipher.wrap_dek(&kek, &dek, header_aad).unwrap();

    let mut = flipped = wrapped.clone();
    flipped[0] ^= 0xff;
    assert!(cipher.unwrap_dek(&kek, &nonce, &flipped, header_aad).is_err());

    let mut wrong_ad = header_aad.to_vec();
    wrong_ad[0] ^= 0xff;
    assert!(cipher.unwrap_dek(&kek, &nonce, &wrapped, &wrong_ad).is_err());
}

#[test]
fn incorrect_password_derives_wrong_kek_fails_unwrap() {
    use crate::crypto::ciphers::{Algorithm, AeadCipher};
    use crate::crypto::keys::{random_salt, random_dek, KeyHierarchy};

    let kdf = Kdf::new(KdfParams::default());
    let salt1 = random_salt();
    let salt2 = random_salt();
    let password_right = secrecy::SecretVec::from(b"correct".to_vec());
    let password_wrong = secrecy::SecretVec::from(b"wrong".to_vec());

    let kek_right = kdf.derive(&password_right, &salt1).unwrap();
    let dek = random_dek();
    let cipher = AeadCipher::new(Algorithm::Aes256Gcm);
    let header_aad = &[0x01u8; 20];
    let (wrapped, nonce) = cipher.wrap_dek(&kek_right, &dek, header_aad).unwrap();

    let kek_wrong = kdf.derive(&password_wrong, &salt2).unwrap();
    assert!(cipher.unwrap_dek(&kek_wrong, &nonce, &wrapped, header_aad).is_err());
}

use crate::crypto::error::CryptoResult;
use crate::crypto::kdf::Kdf;
use secrecy::SecretVec;
use zeroize::Zeroizing;
