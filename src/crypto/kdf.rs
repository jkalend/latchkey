use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version as Argon2Version};
use secrecy::{ExposeSecret, SecretBox};

use crate::crypto::error::{Error, Result};

pub const SALT_LEN: usize = 16;
pub const KEK_LEN: usize = 32;
const MAX_ARGON2_M_MIB: u32 = 1024;
const MAX_ARGON2_T: u32 = 64;
const MAX_ARGON2_P: u8 = 8;
const MAX_ARGON2_WORK_MIB: u32 = 8192;

pub type SecretVec = SecretBox<[u8]>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub argon2_m_mib: u32,
    pub argon2_t: u32,
    pub argon2_p: u8,
}

#[cfg(not(test))]
fn default_argon2_m_mib() -> u32 {
    64
}
#[cfg(test)]
fn default_argon2_m_mib() -> u32 {
    8
}

/// Iterations tuned so 64 MiB Argon2id takes ~1 s wall-clock on a mid-range
/// 2026 CPU (CRYPTO_SPEC §3). Measured on a Ryzen-class desktop in release:
/// t=34 → 0.94 s, t=36 → 1.00 s, t=38 → 1.09 s. If hardware assumptions
/// change, re-measure with `cargo run --release --example kdf_bench` and
/// update both this constant and CRYPTO_SPEC §3 (DEVELOPMENT.md release
/// checklist).
const DEFAULT_ARGON2_T: u32 = 36;

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            argon2_m_mib: default_argon2_m_mib(),
            argon2_t: DEFAULT_ARGON2_T,
            argon2_p: 1,
        }
    }
}

impl KdfParams {
    pub fn new(m_mib: u32, t: u32, p: u8) -> Result<Self> {
        let kib = m_mib
            .checked_mul(1024)
            .ok_or_else(|| Error::Kdf("memory parameter overflow".into()))?;
        Params::new(kib, t, p as u32, Some(KEK_LEN))
            .map_err(|e| Error::Kdf(format!("invalid params: {e}")))?;
        Ok(Self {
            argon2_m_mib: m_mib,
            argon2_t: t,
            argon2_p: p,
        })
    }

    pub fn validate_policy(self) -> Result<()> {
        if self.argon2_m_mib < 8 || self.argon2_t < 1 || self.argon2_p < 1 {
            return Err(Error::Kdf(
                "KDF parameters below the minimum policy (8 MiB, t=1, p=1)".into(),
            ));
        }
        let work_mib = self
            .argon2_m_mib
            .checked_mul(self.argon2_t)
            .ok_or_else(|| Error::Kdf("KDF work parameter overflow".into()))?;
        if self.argon2_m_mib > MAX_ARGON2_M_MIB
            || self.argon2_t > MAX_ARGON2_T
            || self.argon2_p > MAX_ARGON2_P
            || work_mib > MAX_ARGON2_WORK_MIB
        {
            return Err(Error::Kdf(format!(
                "KDF parameters above the maximum policy \
                 ({MAX_ARGON2_M_MIB} MiB memory, t={MAX_ARGON2_T}, \
                 p={MAX_ARGON2_P}, {MAX_ARGON2_WORK_MIB} MiB-passes)"
            )));
        }
        Ok(())
    }
}

pub struct Kdf {
    params: KdfParams,
}
impl Kdf {
    pub fn new(params: KdfParams) -> Self {
        Self { params }
    }
    pub fn derive(&self, password: &SecretVec, salt: &[u8; SALT_LEN]) -> Result<SecretVec> {
        let kib = self
            .params
            .argon2_m_mib
            .checked_mul(1024)
            .ok_or_else(|| Error::Kdf("memory parameter overflow".into()))?;
        let params = Params::new(
            kib,
            self.params.argon2_t,
            self.params.argon2_p as u32,
            Some(KEK_LEN),
        )
        .map_err(|e| Error::Kdf(format!("invalid params: {e}")))?;

        let argon2 = Argon2::new(Argon2Algorithm::Argon2id, Argon2Version::V0x13, params);
        let mut out = vec![0u8; KEK_LEN];
        argon2
            .hash_password_into(password.expose_secret(), salt, &mut out)
            .map_err(|e| Error::Kdf(format!("hash failed: {e}")))?;
        Ok(SecretVec::new(out.into_boxed_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_deterministic() {
        let params = KdfParams::default();
        let kdf = Kdf::new(params);
        let password = SecretVec::new(b"test-password".to_vec().into_boxed_slice());
        let salt = [0x42u8; SALT_LEN];

        let kek1 = kdf.derive(&password, &salt).unwrap();
        let kek2 = kdf.derive(&password, &salt).unwrap();

        assert_eq!(kek1.expose_secret(), kek2.expose_secret());
    }

    #[test]
    fn different_passwords_different_keks() {
        let params = KdfParams::default();
        let kdf = Kdf::new(params);
        let salt = [0x42u8; SALT_LEN];

        let kek1 = kdf
            .derive(&SecretVec::new(b"one".to_vec().into_boxed_slice()), &salt)
            .unwrap();
        let kek2 = kdf
            .derive(&SecretVec::new(b"two".to_vec().into_boxed_slice()), &salt)
            .unwrap();

        assert_ne!(kek1.expose_secret(), kek2.expose_secret());
    }

    #[test]
    fn argon2id_matches_independent_vector() {
        // Generated independently with argon2-cffi 25.1.0:
        // hash_secret_raw(b"password", b"\x42" * 16, t=3, m=8192, p=1,
        //                 hash_len=32, type=ID, version=19)
        let kdf = Kdf::new(KdfParams::new(8, 3, 1).unwrap());
        let password = SecretVec::new(b"password".to_vec().into_boxed_slice());
        let salt = [0x42u8; SALT_LEN];
        let expected = [
            0x48, 0xeb, 0x43, 0xac, 0x09, 0x0d, 0x66, 0x19, 0x46, 0x85, 0x0e, 0x68, 0x2d, 0x2d,
            0x05, 0xb1, 0xfe, 0x7a, 0x37, 0xcd, 0x2b, 0x96, 0xae, 0x88, 0xe9, 0xce, 0xc5, 0xc2,
            0xc7, 0xa6, 0x8c, 0x38,
        ];

        let actual = kdf.derive(&password, &salt).unwrap();
        assert_eq!(actual.expose_secret(), &expected);
    }

    #[test]
    fn policy_rejects_weak_memory() {
        assert!(KdfParams::new(4, 1, 1).unwrap().validate_policy().is_err());
    }

    #[test]
    fn policy_rejects_excessive_resource_cost() {
        assert!(KdfParams::new(MAX_ARGON2_M_MIB + 1, 1, 1)
            .unwrap()
            .validate_policy()
            .is_err());
        assert!(KdfParams::new(512, 17, 1)
            .unwrap()
            .validate_policy()
            .is_err());
    }
}
