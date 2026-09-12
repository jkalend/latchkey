//! CSPRNG key/salt generation. The KEK↔DEK wrapping protocol lives in the
//! vault layer (`vault_impl`), which wraps with a fresh random nonce per
//! write — a shared helper once lived here and was deleted rather than kept
//! as a second, subtly different path.

use zeroize::Zeroizing;

use crate::crypto::ciphers::DEK_LEN;
use crate::crypto::kdf::SALT_LEN;

pub fn random_dek() -> Zeroizing<[u8; DEK_LEN]> {
    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    getrandom::getrandom(&mut *dek).expect("OS CSPRNG failed");
    dek
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = Zeroizing::new([0u8; SALT_LEN]);
    getrandom::getrandom(&mut *salt).expect("OS CSPRNG failed");
    *salt
}
