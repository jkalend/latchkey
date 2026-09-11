//! Non-Windows stub for the win32 module name (compile-time routing aid).
//!
//! On non-Windows builds nothing here is used; `clip/mod.rs` only routes to
//! `win32` under `#[cfg(windows)]`.

use crate::clip::error::{ClipError, Result};

pub fn copy_and_hold(_secret: &[u8], _timeout_secs: u64) -> Result<()> {
    Err(ClipError::Other(
        "win32 backend requires a Windows build".into(),
    ))
}

pub fn copy_now(_secret: &[u8]) -> Result<()> {
    Err(ClipError::Other(
        "win32 backend requires a Windows build".into(),
    ))
}
