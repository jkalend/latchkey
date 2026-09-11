use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};
use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::crypto::error::{Error, Result};
use crate::crypto::kdf::SecretVec;

pub const NONCE_LEN: usize = 12;
pub const DEK_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Algorithm {
    pub fn id(&self) -> u8 {
        match self {
            Algorithm::Aes256Gcm => 0x01,
            Algorithm::ChaCha20Poly1305 => 0x02,
        }
    }

    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0x01 => Ok(Algorithm::Aes256Gcm),
            0x02 => Ok(Algorithm::ChaCha20Poly1305),
            other => Err(Error::Unsupported(other)),
        }
    }
}

pub struct AeadCipher {
    alg: Algorithm,
}

impl AeadCipher {
    pub fn new(alg: Algorithm) -> Self {
        Self { alg }
    }

    pub fn encrypt_item(
        &self,
        dek: &SecretVec,
        plaintext: &[u8],
        item_id: u32,
    ) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| Error::Rng(e.to_string()))?;
        let key: &[u8; DEK_LEN] = dek.expose_secret().as_ref().try_into().unwrap();
        let ct = self.encrypt_item_with_nonce(key, plaintext, item_id, &nonce)?;
        Ok((ct, nonce))
    }

    pub fn decrypt_item(
        &self,
        dek: &SecretVec,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        item_id: u32,
    ) -> Result<Vec<u8>> {
        let key: &[u8; DEK_LEN] = dek.expose_secret().as_ref().try_into().unwrap();
        let aad = Self::aad_item(item_id);
        self.decrypt_with_aad(key, nonce, ciphertext, &aad)
    }

    pub fn wrap_dek(
        &self,
        kek: &SecretVec,
        dek: &SecretVec,
        header_aad: &[u8],
    ) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
        let nonce = Zeroizing::new([0u8; NONCE_LEN]);
        let kek_arr: &[u8; DEK_LEN] = kek.expose_secret().as_ref().try_into().unwrap();
        let dek_arr: &[u8; DEK_LEN] = dek.expose_secret().as_ref().try_into().unwrap();
        let ct = self.encrypt_with_aad(kek_arr, &nonce, dek_arr, header_aad)?;
        Ok((ct, *nonce))
    }

    pub fn unwrap_dek(
        &self,
        kek: &SecretVec,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        header_aad: &[u8],
    ) -> Result<Vec<u8>> {
        let key: &[u8; DEK_LEN] = kek.expose_secret().as_ref().try_into().unwrap();
        self.decrypt_with_aad(key, nonce, ciphertext, header_aad)
    }

    /// Encrypt `plaintext` under `key` with a caller-supplied random 96-bit nonce and
    /// caller-supplied AAD. Used by vault.rs to encrypt the index (VAULT_FORMAT §5).
    /// Returns ciphertext || tag (tag appended, as is conventional for the aead crate).
    pub fn encrypt_raw(
        &self,
        key: &SecretVec,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let k: &[u8; DEK_LEN] = key.expose_secret().as_ref().try_into().unwrap();
        self.encrypt_with_aad(k, nonce, plaintext, aad)
    }

    /// Inverse of `encrypt_raw`.
    pub fn decrypt_raw(
        &self,
        key: &SecretVec,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let k: &[u8; DEK_LEN] = key.expose_secret().as_ref().try_into().unwrap();
        self.decrypt_with_aad(k, nonce, ciphertext, aad)
    }

    fn aad_item(item_id: u32) -> [u8; 5] {
        let mut aad = [0u8; 5];
        aad[0] = 0x53;
        aad[1..5].copy_from_slice(&item_id.to_be_bytes());
        aad
    }

    fn encrypt_item_with_nonce(
        &self,
        key: &[u8; DEK_LEN],
        plaintext: &[u8],
        item_id: u32,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let aad = Self::aad_item(item_id);
        self.encrypt_with_aad(key, nonce, plaintext, &aad)
    }

    fn encrypt_with_aad(
        &self,
        key: &[u8; DEK_LEN],
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        match self.alg {
            Algorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
                cipher
                    .encrypt(
                        AesNonce::from_slice(nonce),
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|e| Error::Encrypt(e.to_string()))
            }
            Algorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(key));
                cipher
                    .encrypt(
                        ChaNonce::from_slice(nonce),
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .map_err(|e| Error::Encrypt(e.to_string()))
            }
        }
    }

    fn decrypt_with_aad(
        &self,
        key: &[u8; DEK_LEN],
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        match self.alg {
            Algorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
                cipher
                    .decrypt(
                        AesNonce::from_slice(nonce),
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| Error::Decrypt)
            }
            Algorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(key));
                cipher
                    .decrypt(
                        ChaNonce::from_slice(nonce),
                        Payload {
                            msg: ciphertext,
                            aad,
                        },
                    )
                    .map_err(|_| Error::Decrypt)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::random_dek;

    fn test_dek_and_kek() -> (SecretVec, SecretVec) {
        let dek = Zeroizing::new(random_dek());
        let kek = Zeroizing::new(random_dek());
        (
            SecretVec::new(dek.to_vec().into_boxed_slice()),
            SecretVec::new(kek.to_vec().into_boxed_slice()),
        )
    }

    #[test]
    fn roundtrip_both_algorithms() {
        for alg in [Algorithm::Aes256Gcm, Algorithm::ChaCha20Poly1305] {
            let cipher = AeadCipher::new(alg);
            let (dek, kek) = test_dek_and_kek();
            let _unused: () = ();
            let header_aad: &[u8] = &[0x01u8; 20];

            let (wrapped, wrap_nonce) = cipher.wrap_dek(&kek, &dek, header_aad).unwrap();
            let unwrapped = cipher
                .unwrap_dek(&kek, &wrap_nonce, &wrapped, header_aad)
                .unwrap();
            assert_eq!(unwrapped.as_slice(), dek.expose_secret().as_ref());

            let (item_ct, item_nonce) = cipher.encrypt_item(&dek, b"secret", 42).unwrap();
            let item_pt = cipher
                .decrypt_item(&dek, &item_nonce, &item_ct, 42)
                .unwrap();
            assert_eq!(item_pt, b"secret");
        }
    }

    #[test]
    fn tamper_detection() {
        let cipher = AeadCipher::new(Algorithm::Aes256Gcm);
        let (dek, kek) = test_dek_and_kek();
        let _unused: () = ();
        let header_aad: &[u8] = &[0x01u8; 20];

        let (wrapped, wrap_nonce) = cipher.wrap_dek(&kek, &dek, header_aad).unwrap();

        let mut flipped = wrapped.clone();
        flipped[0] ^= 0xff;
        assert!(cipher
            .unwrap_dek(&kek, &wrap_nonce, &flipped, header_aad)
            .is_err());

        let (item_ct, item_nonce) = cipher.encrypt_item(&dek, b"secret", 42).unwrap();
        let mut bad_aad = vec![0x53u8, 0, 0, 0, 0];
        bad_aad[0] ^= 0xff;
        let key: &[u8; DEK_LEN] = dek.expose_secret().as_ref().try_into().unwrap();
        assert!(cipher
            .decrypt_with_aad(key, &item_nonce, &item_ct, &bad_aad)
            .is_err());
    }

    #[test]
    fn wrong_password_derives_different_kek_fails_unwrap() {
        use crate::crypto::kdf::{Kdf, KdfParams};
        use crate::crypto::keys::random_salt;

        let kdf = Kdf::new(KdfParams::new(8, 1, 1).unwrap());
        let salt = random_salt();
        let right = crate::crypto::kdf::SecretVec::new(b"correct".to_vec().into_boxed_slice());
        let wrong = crate::crypto::kdf::SecretVec::new(b"wrong".to_vec().into_boxed_slice());

        let kek_right = kdf.derive(&right, &salt).unwrap();
        let kek_wrong = kdf.derive(&wrong, &salt).unwrap();

        let dek_box = SecretVec::new(random_dek().to_vec().into_boxed_slice());
        let cipher = AeadCipher::new(Algorithm::Aes256Gcm);
        let header_aad: &[u8] = &[0x01u8; 20];
        let (wrapped, nonce) = cipher.wrap_dek(&kek_right, &dek_box, header_aad).unwrap();

        assert!(cipher
            .unwrap_dek(&kek_wrong, &nonce, &wrapped, header_aad)
            .is_err());
    }
}
