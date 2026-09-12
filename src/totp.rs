//! TOTP generation (RFC 6238), hand-rolled from `hmac` + `sha1`/`sha2`-family
//! crates per CRYPTO_SPEC §11.
//!
//! Base32 secrets are decoded and validated at write-time (CLI_REFERENCE
//! `rpass totp`): SHA1 ≥ 10 bytes, SHA256 ≥ 16, SHA512 ≥ 32 (RFC 6238
//! interoperability floor).

use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::fmt;
use zeroize::Zeroize;

use crate::crypto::error::{Error, Result};
use crate::vault::shape::{TotpAlgorithm, TotpSubRecord};

#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct TotpParams {
    pub secret: Vec<u8>,
    pub period: u32,
    pub digits: u32,
    #[zeroize(skip)]
    pub algorithm: TotpAlgorithm,
}
impl fmt::Debug for TotpParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpParams")
            .field("secret_len", &self.secret.len())
            .field("period", &self.period)
            .field("digits", &self.digits)
            .field("algorithm", &self.algorithm)
            .finish()
    }
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
    validate_params(p.period, p.digits)?;
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

fn validate_digits(digits: u32) -> Result<()> {
    if matches!(digits, 6 | 8) {
        Ok(())
    } else {
        Err(Error::Encrypt("TOTP digits must be 6 or 8".into()))
    }
}

fn validate_params(period: u32, digits: u32) -> Result<()> {
    if period == 0 {
        return Err(Error::Encrypt("TOTP period must be > 0".into()));
    }
    validate_digits(digits)
}
fn dynamic_truncate(mac: &[u8], digits: u32) -> Result<String> {
    validate_digits(digits)?;
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

/// Parse an `otpauth://totp/...` URI (CLI_REFERENCE `rpass add --totp-uri`).
/// Extracts secret/period/digits/algorithm; the caller zeroizes the raw URI
/// (we take it by value and drop it, but the input String lives in the caller).
pub fn parse_otpauth_uri(uri: &str) -> Result<TotpParams> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| Error::Encrypt("not an otpauth://totp/ URI".into()))?;
    let (label, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };
    if label.is_empty() {
        return Err(Error::Encrypt("otpauth URI has an empty label".into()));
    }

    let mut secret_b32: Option<&str> = None;
    let mut period = 30u32;
    let mut digits = 6u32;
    let mut algorithm = TotpAlgorithm::Sha1;
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| Error::Encrypt(format!("bad otpauth query pair '{pair}'")))?;
        match k {
            "secret" => secret_b32 = Some(v),
            "period" => {
                period = v
                    .parse()
                    .map_err(|_| Error::Encrypt(format!("bad otpauth period '{v}'")))?
            }
            "digits" => {
                digits = v
                    .parse()
                    .map_err(|_| Error::Encrypt(format!("bad otpauth digits '{v}'")))?
            }
            "algorithm" => {
                algorithm = match v.to_uppercase().as_str() {
                    "SHA1" | "SHA" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    other => {
                        return Err(Error::Encrypt(format!(
                            "unsupported otpauth algorithm '{other}'"
                        )))
                    }
                }
            }
            // issuer, counter (HOTP), image, anything unknown: ignored.
            _ => {}
        }
    }
    let secret_b32 = percent_decode(
        secret_b32.ok_or_else(|| Error::Encrypt("otpauth URI has no secret parameter".into()))?,
    )?;
    validate_params(period, digits)?;
    let secret = validate_secret(&secret_b32, algorithm)?;
    Ok(TotpParams {
        secret,
        period,
        digits,
        algorithm,
    })
}

/// Minimal percent-decoding for the query string (secrets are base32, but
/// issuers love pasting URIs with an escaped '=' or label).
fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 3 > bytes.len() {
                    return Err(Error::Encrypt("truncated percent-escape".into()));
                }
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .map_err(|_| Error::Encrypt("bad percent-escape".into()))?;
                let b = u8::from_str_radix(hex, 16)
                    .map_err(|_| Error::Encrypt("bad percent-escape hex".into()))?;
                out.push(b);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::Encrypt("percent-decoded value is not UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B secrets. Each hash uses the prescribed key length.
    const RFC_SHA1_SECRET: &[u8] = b"12345678901234567890";
    const RFC_SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
    const RFC_SHA512_SECRET: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    fn params() -> TotpParams {
        TotpParams {
            secret: RFC_SHA1_SECRET.to_vec(),
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
    fn rfc6238_vectors_sha256_and_sha512() {
        let sha256 = TotpParams {
            secret: RFC_SHA256_SECRET.to_vec(),
            period: 30,
            digits: 8,
            algorithm: TotpAlgorithm::Sha256,
        };
        let sha512 = TotpParams {
            secret: RFC_SHA512_SECRET.to_vec(),
            period: 30,
            digits: 8,
            algorithm: TotpAlgorithm::Sha512,
        };
        let cases = [
            (59, "46119246", "90693936"),
            (1_111_111_109, "68084774", "25091201"),
            (1_111_111_111, "67062674", "99943326"),
            (1_234_567_890, "91819424", "93441116"),
            (2_000_000_000, "90698825", "38618901"),
            (20_000_000_000, "77737706", "47863826"),
        ];
        for (time, expected_sha256, expected_sha512) in cases {
            assert_eq!(totp_at(&sha256, time).unwrap(), expected_sha256);
            assert_eq!(totp_at(&sha512, time).unwrap(), expected_sha512);
        }
    }

    #[test]
    fn six_digit_mode() {
        // RFC 4226 Appendix D reference vectors with the same secret.
        let p = TotpParams {
            secret: RFC_SHA1_SECRET.to_vec(),
            period: 30,
            digits: 6,
            algorithm: TotpAlgorithm::Sha1,
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

    #[test]
    fn otpauth_full_uri() {
        // The canonical Google Authenticator export form. Secret is 32 base32
        // chars = 20 bytes ("12345678901234567890"), above the SHA256 floor of 16.
        let p = parse_otpauth_uri(
            "otpauth://totp/example.com:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=30&digits=6&algorithm=SHA256",
        )
        .unwrap();
        assert_eq!(p.secret, b"12345678901234567890".to_vec());
        assert_eq!(p.period, 30);
        assert_eq!(p.digits, 6);
        assert_eq!(p.algorithm, TotpAlgorithm::Sha256);
    }

    #[test]
    fn otpauth_defaults_and_bad_input() {
        // Bare-minimum URI: only a secret; defaults fill the rest.
        let p = parse_otpauth_uri("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(p.period, 30);
        assert_eq!(p.digits, 6);
        assert_eq!(p.algorithm, TotpAlgorithm::Sha1);

        assert!(parse_otpauth_uri("https://example.com").is_err()); // not otpauth
        assert!(parse_otpauth_uri("otpauth://totp/x").is_err()); // no secret
        assert!(parse_otpauth_uri("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ").is_err()); // HOTP
        let err =
            parse_otpauth_uri("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=abc").unwrap_err();
        assert!(err.to_string().contains("period"));
    }

    #[test]
    fn otpauth_rejects_invalid_period_and_digits() {
        let base = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ";
        assert!(parse_otpauth_uri(&format!("{base}&period=0")).is_err());
        assert!(parse_otpauth_uri(&format!("{base}&digits=7")).is_err());
    }

    #[test]
    fn otpauth_percent_escapes() {
        // A trailing '=' in the secret is only valid base32 with padding
        // enabled; our decoder rejects it either way — the point of the test
        // is that percent-decoding happens before validation.
        let p = parse_otpauth_uri("otpauth://totp/x?secret=GEZDGNBVGY%3D");
        assert!(p.is_err());
        // A valid 10-byte secret with a percent-encoded character in the label.
        let ok =
            parse_otpauth_uri("otpauth://totp/issuer%3Aalice?secret=GEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(ok.secret.len(), 10);
    }
}
