//! Win32 clipboard backend (ADR-0003 §3): synchronous primitives.
//!
//! `copy_and_hold`/`copy_now` set the data eagerly. The hardened path —
//! delayed rendering via `SetClipboardData(NULL)` plus a message-only
//! window answering `WM_RENDERFORMAT` — lives in `win32_delayed.rs` and
//! is what the CLI routes to; this module keeps the shared primitives
//! (global allocation, snapshot, restore) and the immediate-copy path
//! the TUI uses.

use std::time::{Duration, Instant};

use crate::clip::error::{ClipError, Result};

use windows::Win32::Foundation::{HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;

fn last_err(what: &'static str) -> ClipError {
    ClipError::Other(format!(
        "{what} failed: {}",
        std::io::Error::last_os_error()
    ))
}

fn to_utf16(s: &[u8]) -> Vec<u16> {
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

/// Read the current CF_UNICODETEXT, if any (for restore-on-clear).
pub(super) fn snapshot_clipboard() -> Result<Option<Vec<u16>>> {
    unsafe {
        OpenClipboard(None).map_err(|_| ClipError::Open)?;
        let result = (|| {
            let h = match GetClipboardData(CF_UNICODETEXT.0 as u32) {
                Ok(h) => h,
                Err(_) => return Ok(None), // no text on it — fine
            };
            let ptr = GlobalLock(HGLOBAL(h.0)) as *const u16;
            if ptr.is_null() {
                return Ok(None);
            }
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
                if len > 1 << 20 {
                    break; // paranoid cap: 2 MiB of UTF-16
                }
            }
            let text = std::slice::from_raw_parts(ptr, len).to_vec();
            let _ = GlobalUnlock(HGLOBAL(h.0));
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
                    let _ = SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(h.0)));
                }
            }
            let _ = CloseClipboard();
        }
    }
}

/// Copy `secret`, hold for `timeout_secs`, then restore the pre-copy
/// clipboard (or blank if there was none).
pub fn copy_and_hold(secret: &[u8], timeout_secs: u64) -> Result<()> {
    let text = to_utf16(secret);
    let restore = snapshot_best_effort();

    unsafe {
        OpenClipboard(None).map_err(|_| ClipError::Open)?;
        let result = (|| {
            EmptyClipboard().map_err(|_| last_err("EmptyClipboard"))?;
            let h = render_into_global(&text)?;
            SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(h.0)))
                .map_err(|_| last_err("SetClipboardData"))?;
            Ok(())
        })();
        let _ = CloseClipboard();
        result?;
    }

    // Hold. On expiry, clear and restore.
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100).min(deadline - Instant::now()));
    }

    restore_clipboard(&restore);
    Ok(())
}

/// Immediate copy without holding — for the TUI, which manages its own clear.
pub fn copy_now(secret: &[u8]) -> Result<()> {
    let text = to_utf16(secret);
    unsafe {
        OpenClipboard(None).map_err(|_| ClipError::Open)?;
        let result = (|| {
            EmptyClipboard().map_err(|_| last_err("EmptyClipboard"))?;
            let h = render_into_global(&text)?;
            SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(h.0)))
                .map_err(|_| last_err("SetClipboardData"))?;
            Ok(())
        })();
        let _ = CloseClipboard();
        result.map(|_| ())
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
        let _guard = super::super::win32_delayed::CLIPBOARD_TEST_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner());
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
