//! RPv1 header parser/serializer (VAULT_FORMAT.md §3-§4).

use crate::crypto::ciphers::{Algorithm, NONCE_LEN};
use crate::crypto::error::{Error, Result};
use crate::crypto::kdf::{KdfParams, SALT_LEN};

pub const MAGIC: &[u8; 3] = b"RPv";
pub const CURRENT_VERSION: u8 = 0x01;
pub const HEADER_LEN: usize = 117;
pub const FUTURE_PAD_LEN: usize = 18;
pub const WRAPPED_DEK_CIPHER_LEN: usize = 32; // DEK plaintext len; v1 has no KEK padding
pub const WRAP_TAG_LEN: usize = 16;

/// Header, fully parsed. Mirrors VAULT_FORMAT §4.1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedHeader {
    pub version: u8,
    pub kdf_id: u8,
    pub wrap_alg_id: u8,
    pub item_alg_id: u8,
    pub reserved: [u8; 3],
    pub argon2_m_mib: u32,
    pub argon2_t: u32,
    pub argon2_p: u8,
    pub kdf_salt: [u8; SALT_LEN],
    pub enc_counter: u32,
    pub wrap_nonce: [u8; NONCE_LEN],
    pub wrapped_dek: [u8; WRAPPED_DEK_CIPHER_LEN],
    pub wrap_tag: [u8; WRAP_TAG_LEN],
    pub future_pad: [u8; FUTURE_PAD_LEN],
}

impl ParsedHeader {
    pub fn wrap_algorithm(&self) -> Result<Algorithm> {
        Algorithm::from_id(self.wrap_alg_id)
    }
    pub fn item_algorithm(&self) -> Result<Algorithm> {
        Algorithm::from_id(self.item_alg_id)
    }
    pub fn kdf_params(&self) -> KdfParams {
        KdfParams {
            argon2_m_mib: self.argon2_m_mib,
            argon2_t: self.argon2_t,
            argon2_p: self.argon2_p,
        }
    }
}

/// Build the AEAD associated data for the wrapped-DEK record (§4.3):
/// header bytes [offset 4 ..= wrap_nonce end (offset 51)] — i.e. everything
/// the reader parses before attempting the unwrap. Always 47 bytes.
pub fn header_aad(h: &ParsedHeader) -> [u8; 47] {
    let mut a = [0u8; 47];
    a[0] = h.kdf_id;
    a[1] = h.wrap_alg_id;
    a[2] = h.item_alg_id;
    a[3..6].copy_from_slice(&h.reserved);
    a[6..10].copy_from_slice(&h.argon2_m_mib.to_be_bytes());
    a[10..14].copy_from_slice(&h.argon2_t.to_be_bytes());
    a[14] = h.argon2_p;
    a[15..31].copy_from_slice(&h.kdf_salt);
    a[31..35].copy_from_slice(&h.enc_counter.to_be_bytes());
    a[35..47].copy_from_slice(&h.wrap_nonce);
    a
}

pub fn parse_header(data: &[u8]) -> Result<ParsedHeader> {
    if data.len() < HEADER_LEN {
        return Err(Error::Encrypt("file too short for header".into()));
    }
    if &data[0..3] != MAGIC.as_ref() {
        return Err(Error::Encrypt("not a vault file (bad magic)".into()));
    }
    let version = data[3];
    if version != CURRENT_VERSION {
        return Err(Error::Unsupported(version));
    }
    let kdf_salt: [u8; SALT_LEN] = data[19..35].try_into().unwrap();
    let wrap_nonce: [u8; NONCE_LEN] = data[39..51].try_into().unwrap();
    let wrapped_dek: [u8; WRAPPED_DEK_CIPHER_LEN] = data[51..83].try_into().unwrap();
    let wrap_tag: [u8; WRAP_TAG_LEN] = data[83..99].try_into().unwrap();
    let future_pad: [u8; FUTURE_PAD_LEN] = data[99..117].try_into().unwrap();
    // future_pad is unauthenticated in v1 (outside both the header AAD and
    // every AEAD tag). v1 writers must zero it; a non-zero pad means either
    // corruption or a v1.x file with fields this reader doesn't know — both
    // are refuse-to-open, not silently-ignored-tampering.
    if future_pad != [0u8; FUTURE_PAD_LEN] {
        return Err(Error::Encrypt(
            "non-zero future pad — vault written by a newer version or corrupted".into(),
        ));
    }
    Ok(ParsedHeader {
        version,
        kdf_id: data[4],
        wrap_alg_id: data[5],
        item_alg_id: data[6],
        reserved: [data[7], data[8], data[9]],
        argon2_m_mib: u32::from_be_bytes(data[10..14].try_into().unwrap()),
        argon2_t: u32::from_be_bytes(data[14..18].try_into().unwrap()),
        argon2_p: data[18],
        kdf_salt,
        enc_counter: u32::from_be_bytes(data[35..39].try_into().unwrap()),
        wrap_nonce,
        wrapped_dek,
        wrap_tag,
        future_pad,
    })
}

pub fn build_header(h: &ParsedHeader) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..3].copy_from_slice(MAGIC);
    out[3] = h.version;
    out[4] = h.kdf_id;
    out[5] = h.wrap_alg_id;
    out[6] = h.item_alg_id;
    out[7..10].copy_from_slice(&h.reserved);
    out[10..14].copy_from_slice(&h.argon2_m_mib.to_be_bytes());
    out[14..18].copy_from_slice(&h.argon2_t.to_be_bytes());
    out[18] = h.argon2_p;
    out[19..35].copy_from_slice(&h.kdf_salt);
    out[35..39].copy_from_slice(&h.enc_counter.to_be_bytes());
    out[39..51].copy_from_slice(&h.wrap_nonce);
    out[51..83].copy_from_slice(&h.wrapped_dek);
    out[83..99].copy_from_slice(&h.wrap_tag);
    out[99..117].copy_from_slice(&h.future_pad);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_layout() {
        let h = ParsedHeader {
            version: CURRENT_VERSION,
            kdf_id: 0x01,
            wrap_alg_id: 0x01,
            item_alg_id: 0x01,
            reserved: [0, 0, 0],
            argon2_m_mib: 64,
            argon2_t: 2,
            argon2_p: 1,
            kdf_salt: [0x42; SALT_LEN],
            enc_counter: 0,
            wrap_nonce: [0u8; NONCE_LEN],
            wrapped_dek: [0xAA; WRAPPED_DEK_CIPHER_LEN],
            wrap_tag: [0xBB; WRAP_TAG_LEN],
            future_pad: [0u8; FUTURE_PAD_LEN],
        };
        let buf = build_header(&h);
        assert_eq!(buf.len(), HEADER_LEN);
        assert_eq!(&buf[0..4], b"RPv\x01");
        let parsed = parse_header(&buf).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn rejects_short() {
        assert!(parse_header(&[0u8; 10]).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = [0u8; HEADER_LEN];
        buf[0] = 0x00;
        assert!(parse_header(&buf).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..3].copy_from_slice(MAGIC);
        buf[3] = 0x99;
        let err = parse_header(&buf).unwrap_err();
        match err {
            Error::Unsupported(v) => assert_eq!(v, 0x99),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn wrong_version_rpv2_rejected() {
        // "RPv2" = magic bytes correct, version 0x32 (ASCII '2') — should hit the
        // version check, not the magic check.
        let mut buf = [0u8; HEADER_LEN];
        buf[0..3].copy_from_slice(MAGIC);
        buf[3] = b'2';
        assert!(matches!(parse_header(&buf), Err(Error::Unsupported(0x32))));
    }
}
