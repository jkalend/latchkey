//! Win32 clipboard primitives: global allocation, snapshot, restore.
//!
//! The copy/hold paths live in `win32_delayed.rs` (delayed rendering —
//! the only path the CLI and TUI route to). This module owns the FFI
//! helpers both it and the clipboard round-trip test need.

use crate::clip::error::{ClipError, Result};

#[cfg(test)]
use windows::core::w;
use windows::Win32::Foundation::{HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    SetClipboardData,
};
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use windows::Win32::System::Ole::CF_UNICODETEXT;
#[cfg(test)]
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, HWND_MESSAGE, WINDOW_EX_STYLE, WINDOW_STYLE,
};

/// The lock is always closed, including error/panic paths. Mutations must
/// supply an owner window: EmptyClipboard with a NULL owner prevents a
/// subsequent SetClipboardData from succeeding.
pub(super) struct ClipboardLock;

impl ClipboardLock {
    pub(super) fn try_open(owner: Option<HWND>) -> Result<Self> {
        unsafe { OpenClipboard(owner) }.map_err(|_| ClipError::Open)?;
        Ok(Self)
    }

    pub(super) fn open(owner: Option<HWND>) -> Result<Self> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Ok(lock) = Self::try_open(owner) {
                return Ok(lock);
            }
            if std::time::Instant::now() >= deadline {
                return Err(ClipError::Open);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

impl Drop for ClipboardLock {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

#[cfg(test)]
struct SnapshotWindow(HWND);

#[cfg(test)]
impl SnapshotWindow {
    fn new() -> Result<Self> {
        unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                w!(""),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                None,
                None,
            )
            .map(Self)
            .map_err(|_| last_err("CreateWindowExW"))
        }
    }
}

#[cfg(test)]
impl Drop for SnapshotWindow {
    fn drop(&mut self) {
        unsafe {
            let _ = DestroyWindow(self.0);
        }
    }
}

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
#[cfg(test)]
pub(crate) fn snapshot_clipboard() -> Result<Option<Vec<u16>>> {
    let _lock = ClipboardLock::open(None)?;
    snapshot_open_clipboard()
}

/// Caller must hold ClipboardLock; delayed-render snapshot/restore uses the
/// same lock as ownership checks, so a user copy cannot race the restore.
pub(super) fn snapshot_open_clipboard() -> Result<Option<Vec<u16>>> {
    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT.0 as u32).is_err() {
            return Ok(None);
        }
        let h =
            GetClipboardData(CF_UNICODETEXT.0 as u32).map_err(|_| last_err("GetClipboardData"))?;
        let h = HGLOBAL(h.0);
        let ptr = GlobalLock(h) as *const u16;
        if ptr.is_null() {
            return Err(last_err("GlobalLock"));
        }
        let alloc_units = GlobalSize(h) / std::mem::size_of::<u16>();
        let mut len = 0usize;
        while len < alloc_units && *ptr.add(len) != 0 {
            len += 1;
        }
        let text = std::slice::from_raw_parts(ptr, len).to_vec();
        let _ = GlobalUnlock(h);
        Ok(Some(text))
    }
}

/// Caller must hold ClipboardLock opened with a non-NULL owner window.
pub(super) fn restore_open_clipboard(prev: Option<&[u16]>) -> Result<()> {
    unsafe {
        EmptyClipboard().map_err(|_| last_err("EmptyClipboard"))?;
    }
    if let Some(prev) = prev {
        set_clipboard_hglobal(render_into_global(prev)?)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn restore_clipboard(prev: &Option<Vec<u16>>) -> Result<()> {
    let owner = SnapshotWindow::new()?;
    let _lock = ClipboardLock::open(Some(owner.0))?;
    restore_open_clipboard(prev.as_deref())
}

/// Restore the user's clipboard even if a real-backend regression panics.
#[cfg(test)]
pub(crate) struct PreserveClipboard(Option<Vec<u16>>);

#[cfg(test)]
impl PreserveClipboard {
    pub(crate) fn new() -> Self {
        Self(snapshot_clipboard().expect("read clipboard before test"))
    }
}

#[cfg(test)]
impl Drop for PreserveClipboard {
    fn drop(&mut self) {
        let _ = restore_clipboard(&self.0);
    }
}

#[cfg(test)]
pub(crate) fn copy_now(secret: &[u8]) -> Result<()> {
    let text = zeroize::Zeroizing::new(to_utf16(secret));
    let owner = SnapshotWindow::new()?;
    let _lock = ClipboardLock::open(Some(owner.0))?;
    restore_open_clipboard(Some(&text))
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
        let _restore = super::PreserveClipboard::new();
        super::copy_now(b"latchkey-test-123").unwrap();
        let got = super::snapshot_clipboard().unwrap().unwrap();
        assert_eq!(String::from_utf16_lossy(&got), "latchkey-test-123");
    }
}
