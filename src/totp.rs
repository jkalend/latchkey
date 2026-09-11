//! TOTP generation (RFC 6238), hand-rolled from `hmac` + `sha1`/`sha2`-family
//! crates per CRYPTO_SPEC §11.
//!
//! Base32 secrets are decoded and validated at write-time (CLI_REFERENCE
//! `rpass totp`): SHA1 ≥ 10 bytes, SHA256 ≥ 16, SHA512 ≥ 32 (RFC 6238
//! interoperability floor).

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::crypto::error::{Error, Result};
use crate::vault::shape::{TotpAlgorithm, TotpSubRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpParams {
    pub secret: Vec<u8>,
    pub period: u32,
    pub digits: u32,
    pub algorithm: TotpAlgorithm,
}

impl From<&TotpSubRecord> for TotpParams {
    fn from(r: &TotpSubRecord) -> Self {
        TotpParams {
            secret: r.secret.clone(),
            period: r.period,
            digits: r.digits,
            algorithm: r.algorithm,
        }
    }
}

/// The current code and the seconds remaining before it rolls over.
pub struct TotpNow {
    pub code: String,
    pub remaining: u32,
}

/// Compute the TOTP for `unix_now`.
pub fn totp_at(p: &TotpParams, unix_now: u64) -> Result<String> {
    if p.period == 0 {
        return Err(Error::Encrypt("TOTP period must be > 0".into()));
    }
    let counter = unix_now / p.period as u64;
    hotp(p, counter)
}

/// HOTP (RFC 4226) — TOTP is HOTP over the time counter.
fn hotp(p: &TotpParams, counter: u64) -> Result<String> {
    // Tag length differs per algorithm; collect into a Vec<u8> so the match
    // arms agree on a type.
    let mac: Vec<u8> = match p.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut m = <Hmac<Sha1> as Mac>::new_from_slice(&p.secret)
                .map_err(|e| Error::Encrypt(format!("hmac init: {e}")))?;
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&p.secret)
                .map_err(|e| Error::Encrypt(format!("hmac init: {e}")))?;
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut m = <Hmac<sha2::Sha512> as Mac>::new_from_slice(&p.secret)
                .map_err(|e| Error::Encrypt(format!("hmac init: {e}")))?;
            m.update(&counter.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        }
    };
    dynamic_truncate(&mac, p.digits)
}

fn dynamic_truncate(mac: &[u8], digits: u32) -> Result<String> {
    if mac.is_empty() {
        return Err(Error::Encrypt("empty hmac".into()));
    }
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    if offset + 4 > mac.len() {
        return Err(Error::Encrypt(
            "hmac too short for dynamic truncation".into(),
        ));
    }
    let bin = u32::from_be_bytes([
        mac[offset],
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    let otp = bin & 0x7fff_ffff;
    // Zero-pad to the requested width.
    Ok(format!(
        "{:0width$}",
        otp % 10u32.pow(digits),
        width = digits as usize
    ))
}

/// Current code + seconds until the next period boundary.
pub fn totp_now(p: &TotpParams) -> Result<TotpNow> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Encrypt(format!("clock before epoch: {e}")))?
        .as_secs();
    let code = totp_at(p, now)?;
    let remaining = p.period - (now % p.period as u64) as u32;
    Ok(TotpNow { code, remaining })
}

/// Write-time validation (CLI_REFERENCE `rpass totp`): base32 must decode
/// cleanly and the decoded length must meet the algorithm floor.
pub fn validate_secret(secret_b32: &str, algorithm: TotpAlgorithm) -> Result<Vec<u8>> {
    let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret_b32)
        .ok_or_else(|| Error::Encrypt("TOTP secret is not valid base32".into()))?;
    let floor = match algorithm {
        TotpAlgorithm::Sha1 => 10,
        TotpAlgorithm::Sha256 => 16,
        TotpAlgorithm::Sha512 => 32,
    };
    if decoded.len() < floor {
        return Err(Error::Encrypt(format!(
            "base32 decodes to {} bytes, need ≥{floor} for {:?}",
            decoded.len(),
            algorithm
        )));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors (SHA1, 20-byte secret "1234567890...").
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    fn params() -> TotpParams {
        TotpParams {
            secret: RFC_SECRET.to_vec(),
            period: 30,
            digits: 8,
            algorithm: TotpAlgorithm::Sha1,
        }
    }

    #[test]
    fn rfc6238_vectors_sha1() {
        // RFC 6238 Appendix B, SHA1, 8 digits, T0=0, period 30s. Cross-checked
        // against an independent HMAC-SHA1 implementation.
        assert_eq!(totp_at(&params(), 59).unwrap(), "94287082");
        assert_eq!(totp_at(&params(), 1_111_111_109).unwrap(), "07081804");
        assert_eq!(totp_at(&params(), 1_111_111_111).unwrap(), "14050471");
        assert_eq!(totp_at(&params(), 1_234_567_890).unwrap(), "89005924");
        assert_eq!(totp_at(&params(), 2_000_000_000).unwrap(), "69279037");
        assert_eq!(totp_at(&params(), 20_000_000_000).unwrap(), "65353130");
    }

    #[test]
    fn six_digit_mode() {
        // RFC 4226 Appendix D reference vectors with the same secret.
        let p = TotpParams {
            digits: 6,
            ..params()
        };
        // counter 0 → 755224, counter 1 → 287082 (HOTP vectors)
        assert_eq!(hotp(&p, 0).unwrap(), "755224");
        assert_eq!(hotp(&p, 1).unwrap(), "287082");
    }

    #[test]
    fn validation_floors() {
        // 10 bytes = SHA1 floor, passes
        assert!(validate_secret("GEZDGNBVGY3TQOJQ", TotpAlgorithm::Sha1).is_ok());
        // same 10 bytes fail the SHA256 floor of 16
        let err = validate_secret("GEZDGNBVGY3TQOJQ", TotpAlgorithm::Sha256).unwrap_err();
        assert!(err.to_string().contains("need ≥16"));
        // garbage base32
        assert!(validate_secret("!!not-base32!!", TotpAlgorithm::Sha1).is_err());
    }
}
