//! Cross-process clipboard expiry marker (SEC-04).
//!
//! Problem: copy A's expiry restores its pre-copy snapshot, which copy B
//! snapshotted — i.e. A's own secret. Both processes then exit and nothing
//! clears A, which stays on the clipboard indefinitely.
//!
//! Fix: every latchkey copy writes a small marker under a registered
//! clipboard format naming the format's epoch generation and this copy's
//! deadline. At expiry a copy clears the clipboard iff the marker present on
//! the clipboard names the generation that copy set (i.e. no other latchkey
//! copy has superseded it) and its deadline has passed. A genuine user copy
//! removes or replaces the marker and is never overwritten; an overlapping
//! latchkey copy sees the superseded generation and defers to the newer one.
//!
//! This is best-effort defense-in-depth, not a security boundary: another
//! process may claim the format name or strip it. The marker never carries
//! secret material.

pub const MARKER_FORMAT_NAME: &str = "Latchkey.ClipboardExpiryMarker";
// The Win32 side registers this exact literal via `w!` in win32.rs — the two
// definitions must stay in sync (checked by a unit test below, since string
// equality is not const-evaluable for `&str`).

/// Wire format, little-endian: magic u32 `0x4C4B4558` ("LEKX"), version u32 1,
/// generation u64, deadline unix-secs u64.
pub const MARKER_MAGIC: u32 = 0x4C4B_4558;
pub const MARKER_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryMarker {
    pub generation: u64,
    pub deadline_unix: u64,
}

impl ExpiryMarker {
    pub fn encode(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..4].copy_from_slice(&MARKER_MAGIC.to_le_bytes());
        out[4..8].copy_from_slice(&MARKER_VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.generation.to_le_bytes());
        out[16..24].copy_from_slice(&self.deadline_unix.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != 24 {
            return None;
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let version = u32::from_le_bytes(data[4..8].try_into().ok()?);
        if magic != MARKER_MAGIC || version != MARKER_VERSION {
            return None;
        }
        Some(Self {
            generation: u64::from_le_bytes(data[8..16].try_into().ok()?),
            deadline_unix: u64::from_le_bytes(data[16..24].try_into().ok()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn registered_name_matches_wire_name() {
        // win32.rs must register the same literal this module publishes.
        assert_eq!(super::MARKER_FORMAT_NAME, "Latchkey.ClipboardExpiryMarker");
        assert_eq!(
            crate::clip::win32::marker_name_to_string(),
            super::MARKER_FORMAT_NAME
        );
    }

    #[test]
    fn marker_roundtrip() {
        let m = ExpiryMarker {
            generation: 0x1122_3344_5566_7788,
            deadline_unix: 1_800_000_000,
        };
        assert_eq!(ExpiryMarker::decode(&m.encode()), Some(m));
    }

    #[test]
    fn marker_rejects_truncated_and_bad_magic() {
        let m = ExpiryMarker {
            generation: 1,
            deadline_unix: 2,
        };
        let good = m.encode();
        assert_eq!(ExpiryMarker::decode(&good[..20]), None);
        let mut bad = good;
        bad[0] ^= 0xFF;
        assert_eq!(ExpiryMarker::decode(&bad), None);
    }
}
