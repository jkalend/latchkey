use secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::crypto::ciphers::{AeadCipher, DEK_LEN};
use crate::crypto::error::Result;
use crate::crypto::kdf::SALT_LEN;
use crate::crypto::kdf::SecretVec;

const ENC_COUNTER_ROTATION_LIMIT: u32 = 1 << 24;

pub struct KeyHierarchy {
    pub dek: SecretVec,
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: [u8; 12],
    pub enc_counter: u32,
}

impl KeyHierarchy {
    pub fn unwrap(
        cipher: &AeadCipher,
        kek: &SecretVec,
        wrapped_dek: &[u8],
        wrap_nonce: &[u8; 12],
        header_aad: &[u8],
    ) -> Result<Self> {
        let dek_bytes = cipher.unwrap_dek(kek, wrap_nonce, wrapped_dek, header_aad)?;
        if dek_bytes.len() != DEK_LEN {
            return Err(crate::crypto::error::Error::KeyLength { expected: DEK_LEN, actual: dek_bytes.len() });
        }
        Ok(Self {
            dek: SecretVec::new(dek_bytes.into_boxed_slice()),
            wrapped_dek: wrapped_dek.to_vec(),
            wrap_nonce: *wrap_nonce,
            enc_counter: 0,
        })
    }

    pub fn generate(cipher: &AeadCipher, kek: &SecretVec, header_aad: &[u8]) -> Result<Self> {
        let dek = random_dek();
        let dek_box = SecretVec::new(dek.to_vec().into_boxed_slice());
        let (wrapped, nonce) = cipher.wrap_dek(kek, &dek_box, header_aad)?;
        Ok(Self {
            dek: SecretVec::new(dek.to_vec().into_boxed_slice()),
            wrapped_dek: wrapped,
            wrap_nonce: nonce,
            enc_counter: 0,
        })
    }

    pub fn needs_rotation(&self) -> bool { self.enc_counter >= ENC_COUNTER_ROTATION_LIMIT }

    pub fn rotate(&mut self, cipher: &AeadCipher, kek: &SecretVec, header_aad: &[u8]) -> Result<()> {
        let new_dek = random_dek();
        let new_dek_box = SecretVec::new(new_dek.to_vec().into_boxed_slice());
        let (new_wrapped, new_nonce) = cipher.wrap_dek(kek, &new_dek_box, header_aad)?;
        self.dek = SecretVec::new(new_dek.to_vec().into_boxed_slice());
        self.wrapped_dek = new_wrapped;
        self.wrap_nonce = new_nonce;
        self.enc_counter = 0;
        Ok(())
    }

    pub fn rekey_kek(&mut self, cipher: &AeadCipher, new_kek: &SecretVec, header_aad: &[u8]) -> Result<()> {
        let dek_copy: [u8; DEK_LEN] = self.dek.expose_secret().as_ref().try_into().unwrap();
        let dek_copy_box = SecretVec::new(dek_copy.to_vec().into_boxed_slice());
        let (new_wrapped, new_nonce) = cipher.wrap_dek(new_kek, &dek_copy_box, header_aad)?;
        self.wrapped_dek = new_wrapped;
        self.wrap_nonce = new_nonce;
        Ok(())
    }
}

pub fn random_dek() -> [u8; DEK_LEN] {
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    getrandom::getrandom(&mut *dek).expect("OS CSPRNG failed");
    *dek
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    getrandom::getrandom(&mut *salt).expect("OS CSPRNG failed");
    *salt
}
