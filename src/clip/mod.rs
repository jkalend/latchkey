//! Clipboard handling (ADR-0003).
//!
//! Three backends, routed by platform (ADR-0008):
//! - **Windows native** — Win32 with **delayed rendering**: we set
//!   `SetClipboardData(CF_UNICODETEXT, NULL)` and render the secret on
//!   WM_RENDERFORMAT. The secret never sits statically in the clipboard, and
//!   process death clears the entry automatically.
//! - **WSL** — spawn `clip.exe` with the secret on stdin (never argv).
//! - **Plain Linux** — best-effort `wl-copy` → `xclip`/`xsel`.
//!
//! Auto-clear: `copy()` blocks for the timeout (default 30 s, max 300), then
//! restores the pre-copy clipboard contents if we captured them, else blanks.
//! Ctrl-C (SIGINT) clears immediately.

pub mod error;
pub mod platform;
mod win_history;

pub use error::{ClipError, Result};
pub use platform::{clipboard_history_enabled, detect, Platform};

/// Default auto-clear timeout in seconds (ADR-0003 §1, amended round 4).
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
pub const MAX_TIMEOUT_SECS: u64 = 300;

/// Validate a timeout argument.
pub fn validate_timeout(secs: u64) -> Result<u64> {
    if secs > MAX_TIMEOUT_SECS {
        Err(ClipError::Timeout(secs))
    } else {
        Ok(secs)
    }
}

/// Copy `secret` to the clipboard and block until the auto-clear timeout.
///
/// When `ClipboardHistory` is enabled (Windows probe), prints a one-line
/// warning to stderr — history defeats auto-clear (ADR-0003 §4).
pub fn copy_and_hold(secret: &[u8], timeout_secs: u64) -> Result<()> {
    let timeout = validate_timeout(timeout_secs)?;
    if let Some(true) = clipboard_history_enabled() {
        eprintln!(
            "warning: Windows Clipboard History is enabled — copied values are captured by Win+V and auto-clear does not remove them"
        );
    }
    match platform::detect() {
        Platform::Windows => crate::clip::win32_delayed::copy_and_hold(secret, timeout),
        Platform::Wsl => crate::clip::wsl::copy_and_hold(secret, timeout),
        Platform::Linux => crate::clip::unix::copy_and_hold(secret, timeout),
    }
}

/// Copy without waiting for the timeout. For TUI use (the TUI holds its own
/// timer); not exposed via the CLI.
pub fn copy_async(secret: &[u8]) -> Result<()> {
    match platform::detect() {
        Platform::Windows => crate::clip::win32::copy_now(secret),
        Platform::Wsl => crate::clip::wsl::copy_now(secret),
        Platform::Linux => crate::clip::unix::copy_now(secret),
    }
}

// Windows backend is a whole module; keep it cfg-gated.
#[cfg(windows)]
pub mod win32;
#[cfg(windows)]
pub mod win32_delayed;
#[cfg(not(windows))]
pub mod win32_fallback;
#[cfg(not(windows))]
pub use win32_fallback as win32;

pub mod unix;
pub mod wsl;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_bounds() {
        assert_eq!(validate_timeout(0).unwrap(), 0);
        assert_eq!(validate_timeout(300).unwrap(), 300);
        assert!(validate_timeout(301).is_err());
    }
}
