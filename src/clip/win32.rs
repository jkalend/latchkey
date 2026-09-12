//! Win32 clipboard primitives: global allocation, snapshot, restore.
//!
//! The copy/hold paths live in `win32_delayed.rs` (delayed rendering —
//! the only path the CLI and TUI route to). This module owns the FFI
//! helpers both it and the clipboard round-trip test need.

use crate::clip::error::{ClipError, Result};

use windows::Win32::Foundation::{HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use windows::Win32::System::Ole::CF_UNICODETEXT;

// windows-rs 0.62 does not expose GlobalFree — its NULL-on-success return
// doesn't map onto its error-wrapper conventions (same reason
// win32_delayed.rs declares SetClipboardData itself). Declare it directly.
#[link(name = "kernel32")]
extern "system" {
    #[link_name = "GlobalFree"]
    fn global_free_raw(hmem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

fn global_free(h: HGLOBAL) {
    unsafe {
        let _ = global_free_raw(h.0);
    }
}

fn last_err(what: &'static str) -> ClipError {
    ClipError::Other(format!(
        "{what} failed: {}",
        std::io::Error::last_os_error()
    ))
}

pub(super) fn to_utf16(s: &[u8]) -> Vec<u16> {
    // Secrets enter the vault as validated UTF-8; lossy only as a defensive fallback.
    String::from_utf8_lossy(s).encode_utf16().collect()
}

/// Render text into a moveable HGLOBAL with NUL terminator (ownership transfers
/// to the clipboard on SetClipboardData success).
pub(super) fn render_into_global(text: &[u16]) -> Result<HGLOBAL> {
    unsafe {
        let bytes = (text.len() + 1) * std::mem::size_of::<u16>();
        let h = GlobalAlloc(GMEM_MOVEABLE, bytes).map_err(|_| last_err("GlobalAlloc"))?;
        let dst = GlobalLock(h) as *mut u16;
        if dst.is_null() {
            // The allocation is ours until handed over — free on every
            // failure path or the HGLOBAL leaks for the process lifetime.
            global_free(h);
            return Err(last_err("GlobalLock"));
        }
        for (i, c) in text.iter().enumerate() {
            *dst.add(i) = *c;
        }
        *dst.add(text.len()) = 0;
        let _ = GlobalUnlock(h);
        Ok(h)
    }
}

/// Hand an HGLOBAL to the clipboard. On SetClipboardData failure the system
/// does NOT take ownership — free it here so callers can't leak it.
pub(super) fn set_clipboard_hglobal(h: HGLOBAL) -> Result<()> {
    unsafe {
        match SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(h.0))) {
            Ok(_) => Ok(()),
            Err(_) => {
                global_free(h);
                Err(last_err("SetClipboardData"))
            }
        }
    }
}

/// Read the current CF_UNICODETEXT, if any (for restore-on-clear).
///
/// The clipboard payload belongs to *another, arbitrary* process: it is
/// not guaranteed NUL-terminated, so the scan is bounded by the actual
/// allocation (GlobalSize) rather than searching for NUL into the void.
pub(super) fn snapshot_clipboard() -> Result<Option<Vec<u16>>> {
    unsafe {
        OpenClipboard(None).map_err(|_| ClipError::Open)?;
        let result = (|| {
            let h = match GetClipboardData(CF_UNICODETEXT.0 as u32) {
                Ok(h) => h,
                Err(_) => return Ok(None), // no text on it — fine
            };
            let h = HGLOBAL(h.0);
            let ptr = GlobalLock(h) as *const u16;
            if ptr.is_null() {
                return Ok(None);
            }
            let alloc_units = GlobalSize(h) / std::mem::size_of::<u16>();
            let mut len = 0usize;
            while len < alloc_units && *ptr.add(len) != 0 {
                len += 1;
            }
            // If no NUL exists inside the allocation, take the whole span.
            let text = std::slice::from_raw_parts(ptr, len).to_vec();
            let _ = GlobalUnlock(h);
            Ok(Some(text))
        })();
        let _ = CloseClipboard();
        result
    }
}

/// Snapshot helper that treats "cannot open" as "nothing to restore" so a busy
/// clipboard never blocks a copy.
pub(super) fn snapshot_best_effort() -> Option<Vec<u16>> {
    snapshot_clipboard().unwrap_or(None)
}

/// Restore the clipboard to a prior snapshot: blank it, then put `prev` back
/// if there was one. Best-effort — a busy clipboard just stays busy.
pub(super) fn restore_clipboard(prev: &Option<Vec<u16>>) {
    unsafe {
        if OpenClipboard(None).is_ok() {
            let _ = EmptyClipboard();
            if let Some(prev) = prev {
                if let Ok(h) = render_into_global(prev) {
                    let _ = set_clipboard_hglobal(h);
                }
            }
            let _ = CloseClipboard();
        }
    }
}

// Note for future design changes: GetClipboardSequenceNumber is NOT usable
// for the restore-ownership check — serving a WM_RENDERFORMAT paste re-runs
// SetClipboardData and bumps the sequence, so it can't distinguish "still
// ours" from "user copied something else". win32_delayed compares content.

#[cfg(test)]
pub(crate) fn copy_now(secret: &[u8]) -> Result<()> {
    let text = to_utf16(secret);
    unsafe {
        OpenClipboard(None).map_err(|_| ClipError::Open)?;
        let result = (|| {
            EmptyClipboard().map_err(|_| last_err("EmptyClipboard"))?;
            let h = render_into_global(&text)?;
            set_clipboard_hglobal(h)
        })();
        let _ = CloseClipboard();
        result
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn utf16_roundtrip() {
        let s = "pässwörd123";
        let v = super::to_utf16(s.as_bytes());
        assert_eq!(String::from_utf16_lossy(&v), s);
    }

    #[cfg(windows)]
    #[test]
    fn copy_now_roundtrips_through_the_real_clipboard() {
        // Only safe to run where we may touch the user's clipboard: it saves
        // and restores whatever was there. Serialized against the
        // delayed-render tests via the same lock (they share the clipboard).
        let _guard = crate::clip::win32_delayed::lock_clipboard();
        let before = super::snapshot_best_effort();
        super::copy_now(b"rpass-test-123").unwrap();
        let got = super::snapshot_best_effort().unwrap();
        assert_eq!(String::from_utf16_lossy(&got), "rpass-test-123");
        // restore
        match before {
            Some(prev) => super::copy_now(&String::from_utf16_lossy(&prev).into_bytes()).unwrap(),
            None => unsafe {
                use windows::Win32::System::DataExchange::{
                    CloseClipboard, EmptyClipboard, OpenClipboard,
                };
                if OpenClipboard(None).is_ok() {
                    let _ = EmptyClipboard();
                    let _ = CloseClipboard();
                }
            },
        }
    }
}
