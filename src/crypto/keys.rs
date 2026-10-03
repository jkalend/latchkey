//! CSPRNG key/salt generation and fixed-size key ownership. The KEK↔DEK
//! wrapping protocol lives in the vault layer (`vault_impl`), which wraps
//! with a fresh random nonce per write — a shared helper once lived here and
//! was deleted rather than kept as a second, subtly different path.

use secrecy::SecretBox;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::ciphers::DEK_LEN;
use crate::crypto::error::{Error, Result};
use crate::crypto::kdf::SALT_LEN;

/// Variable-length secret input (master passwords). Not a key type.
pub type SecretVec = SecretBox<[u8]>;

/// A fixed-size, wiping owner for a 256-bit key (KEK or DEK). Constructed
/// only from an exact 32-byte array — never from a slice — so an
/// wrong-length key cannot be installed through the type system. Clones
/// allocate a fresh zeroizing heap box; keys are small and cloned only per
/// session/snapshot, so the fixed-size array lives inline and wipes on drop.
#[derive(Clone)]
pub struct Key32([u8; DEK_LEN]);

impl Drop for Key32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Key32 {
    pub fn from_array(bytes: [u8; DEK_LEN]) -> Self {
        Key32(bytes)
    }

    /// Accept only exactly-32-byte material; anything else is a caller bug
    /// (a wrong-length unwrap) and must fail loudly, not truncate.
    pub fn from_exact(bytes: &[u8]) -> Result<Self> {
        let array: [u8; DEK_LEN] = bytes.try_into().map_err(|_| Error::KeyLength {
            expected: DEK_LEN,
            actual: bytes.len(),
        })?;
        Ok(Key32(array))
    }

    pub fn expose(&self) -> &[u8; DEK_LEN] {
        &self.0
    }

    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key32(<redacted>)")
    }
}

/// Fill a fresh random 256-bit key directly from the OS CSPRNG.
pub fn random_dek() -> Key32 {
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    getrandom::getrandom(&mut *dek).expect("OS CSPRNG failed");
    Key32::from_array(std::mem::take(&mut *dek))
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    getrandom::getrandom(&mut *salt).expect("OS CSPRNG failed");
    *salt
}
