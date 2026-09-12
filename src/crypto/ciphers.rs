use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};
use secrecy::ExposeSecret;

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

/// AEAD over a caller-supplied nonce. Every call site (vault header wrap,
/// index, item frames) generates its nonce with `random_nonce()` in
/// `vault_impl` — this type deliberately does NOT own nonce generation, so
/// there is exactly one place where freshness is enforced.
pub struct AeadCipher {
    alg: Algorithm,
}

impl AeadCipher {
    pub fn new(alg: Algorithm) -> Self {
        Self { alg }
    }

    /// Encrypt `plaintext` under `key` with a caller-supplied random 96-bit
    /// nonce and caller-supplied AAD.
    /// Returns ciphertext || tag (tag appended, as is conventional for the
    /// aead crate).
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

    fn roundtrip(alg: Algorithm) {
        let cipher = AeadCipher::new(alg);
        let key = SecretVec::new(random_dek().to_vec().into_boxed_slice());
        let nonce = [7u8; NONCE_LEN];
        let ct = cipher.encrypt_raw(&key, &nonce, b"secret", b"aad").unwrap();
        assert_eq!(
            cipher.decrypt_raw(&key, &nonce, &ct, b"aad").unwrap(),
            b"secret"
        );

        let mut tampered = ct.clone();
        tampered[0] ^= 0xff;
        assert!(cipher.decrypt_raw(&key, &nonce, &tampered, b"aad").is_err());
        assert!(cipher.decrypt_raw(&key, &nonce, &ct, b"other-aad").is_err());

        let wrong_key = SecretVec::new(random_dek().to_vec().into_boxed_slice());
        assert!(cipher.decrypt_raw(&wrong_key, &nonce, &ct, b"aad").is_err());
    }

    #[test]
    fn roundtrip_both_algorithms() {
        roundtrip(Algorithm::Aes256Gcm);
        roundtrip(Algorithm::ChaCha20Poly1305);
    }
}
