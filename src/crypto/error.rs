pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("KDF error: {0}")]
    Kdf(String),
    #[error("encryption error: {0}")]
    Encrypt(String),
    #[error("decryption error: vault corrupt or wrong password")]
    Decrypt,
    #[error("invalid key length: expected {expected} bytes, got {actual}")]
    KeyLength { expected: usize, actual: usize },
    #[error("invalid nonce length: expected {expected} bytes, got {actual}")]
    NonceLength { expected: usize, actual: usize },
    #[error("unsupported algorithm id: {0}")]
    Unsupported(u8),
    #[error("RNG failure: {0}")]
    Rng(String),
}
