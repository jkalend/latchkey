//! Clipboard handling (ADR-0003).
//!
//! Three backends, routed by platform (ADR-0008):
//! - **Windows native** — Win32 with **delayed rendering**: we set
//!   `SetClipboardData(CF_UNICODETEXT, NULL)` and render the secret on
//!   WM_RENDERFORMAT. The secret never sits statically in the clipboard
//!   before the first paste, and process death before that first paste
//!   clears the entry automatically. After a paste has been served the
//!   data lives in a rendered HGLOBAL — clearing then depends on the
//!   timeout restore below.
//! - **WSL** — PowerShell interop (`Set-Clipboard`) with the secret
//!   base64-encoded over stdin, so no console code page can mangle it.
//! - **Plain Linux** — best-effort `wl-copy` → `xclip`/`xsel`. The X11/Wayland
//!   helper owns the selection until the timeout overwrite below.
//!
//! Auto-clear: `copy_and_hold()` blocks for the timeout (default 30 s, max 300),
//! then — but only if the clipboard still holds *our* value (checked via
//! native clipboard ownership or a content compare elsewhere) — restores
//! the pre-copy clipboard contents if we captured them, else blanks it.
//! If the user copied something else in the meantime, their clipboard is
//! left alone.
//!
//! Normal TUI exit cancels and joins the clipboard worker on all platforms.
//! Ctrl-C in the synchronous CLI is handled on native Windows; WSL/Linux
//! have no signal handler, so process death there can leave the secret in
//! the clipboard until another copy. Cancellation cannot make external
//! clipboard-tool reads and writes atomic on WSL/Linux.

pub mod error;
pub mod platform;
mod win_history;

pub use error::{ClipError, Result};
pub use platform::{clipboard_history_enabled, detect, Platform};

#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

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

/// `LATCHKEY_CLIPBOARD_TIMEOUT` (CLI_REFERENCE "Environment variables"):
/// out-of-range or unparsable values fall back to the default rather
/// than failing the prompt path.
pub fn env_timeout_default() -> u64 {
    std::env::var("LATCHKEY_CLIPBOARD_TIMEOUT")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s <= MAX_TIMEOUT_SECS)
        .unwrap_or(DEFAULT_TIMEOUT_SECS)
}

/// Process-wide "Ctrl-C was pressed" flag (native Windows only — on
/// WSL/Linux there is deliberately no signal handler; see module docs).
#[cfg(windows)]
pub(crate) fn ctrlc_flag() -> &'static AtomicBool {
    use windows::core::BOOL;
    use windows::Win32::System::Console::SetConsoleCtrlHandler;

    static FLAG: AtomicBool = AtomicBool::new(false);
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| unsafe {
        unsafe extern "system" fn handler(ctrl_type: u32) -> BOOL {
            const CTRL_C_EVENT: u32 = 0;
            const CTRL_BREAK_EVENT: u32 = 1;
            if matches!(ctrl_type, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
                FLAG.store(true, Ordering::SeqCst);
                // Claim "handled" so the process survives until the hold
                // loop notices and runs the clear-and-exit path.
                return BOOL(1);
            }
            BOOL(0)
        }
        // Best-effort: if installing the handler fails, the timeout
        // restore still bounds exposure.
        let _ = SetConsoleCtrlHandler(Some(handler), true);
    });
    &FLAG
}

/// True once Ctrl-C/Ctrl-Break arrived (native Windows only).
#[cfg(windows)]
pub(crate) fn ctrlc_requested() -> bool {
    ctrlc_flag().load(Ordering::SeqCst)
}

/// Cancellation shared with a synchronous clipboard hold loop.
#[derive(Clone, Default)]
pub struct Cancellation(Arc<(Mutex<bool>, Condvar)>);

impl Cancellation {
    pub fn cancel(&self) {
        let (flag, wake) = &*self.0;
        *flag.lock().unwrap_or_else(|p| p.into_inner()) = true;
        wake.notify_all();
    }

    pub(crate) fn hold(&self, timeout_secs: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let (flag, wake) = &*self.0;
        let mut cancelled = flag.lock().unwrap_or_else(|p| p.into_inner());
        while !*cancelled {
            #[cfg(windows)]
            if ctrlc_requested() {
                break;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            cancelled = wake
                .wait_timeout(
                    cancelled,
                    remaining.min(std::time::Duration::from_millis(100)),
                )
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }
}

/// Owned clipboard worker. Dropping it cancels and joins: cleanup cannot be
/// detached accidentally. Callers should drop vault/terminal state first.
pub struct ClipboardTask {
    cancel: Cancellation,
    handle: Option<std::thread::JoinHandle<Result<()>>>,
}

impl ClipboardTask {
    pub fn start(secret: zeroize::Zeroizing<Vec<u8>>, timeout_secs: u64) -> Result<Self> {
        validate_timeout(timeout_secs)?;
        let cancel = Cancellation::default();
        let worker_cancel = cancel.clone();
        let handle = std::thread::Builder::new()
            .name("latchkey-clipboard".into())
            .spawn(move || copy_and_hold_cancellable(&secret, timeout_secs, true, &worker_cancel))
            .map_err(|e| ClipError::Other(format!("spawn clipboard worker: {e}")))?;
        Ok(Self {
            cancel,
            handle: Some(handle),
        })
    }

    pub fn is_finished(&self) -> bool {
        self.handle
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
    }

    pub fn finish(mut self) -> Result<()> {
        self.join()
    }

    pub fn cancel_and_finish(mut self) -> Result<()> {
        self.cancel.cancel();
        self.join()
    }

    fn join(&mut self) -> Result<()> {
        match self.handle.take() {
            Some(handle) => handle
                .join()
                .map_err(|_| ClipError::Other("clipboard worker panicked".into()))?,
            None => Ok(()),
        }
    }
}

impl Drop for ClipboardTask {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _ = self.join();
    }
}

pub fn copy_and_hold(secret: &[u8], timeout_secs: u64) -> Result<()> {
    copy_and_hold_quiet(secret, timeout_secs, false)
}

pub fn copy_and_hold_quiet(secret: &[u8], timeout_secs: u64, quiet: bool) -> Result<()> {
    let result = copy_and_hold_cancellable(secret, timeout_secs, quiet, &Cancellation::default());
    #[cfg(windows)]
    if result.is_ok() && ctrlc_requested() {
        std::process::exit(130);
    }
    result
}

pub fn copy_and_hold_cancellable(
    secret: &[u8],
    timeout_secs: u64,
    quiet: bool,
    cancel: &Cancellation,
) -> Result<()> {
    let timeout = validate_timeout(timeout_secs)?;
    if !quiet && clipboard_history_enabled() == Some(true) {
        eprintln!(
            "warning: Windows Clipboard History is enabled — copied values are captured by Win+V and auto-clear does not remove them"
        );
    }
    match platform::detect() {
        Platform::Windows => windows_copy_and_hold(secret, timeout, cancel),
        Platform::Wsl => crate::clip::wsl::copy_and_hold_cancellable(secret, timeout, cancel),
        Platform::Linux => crate::clip::unix::copy_and_hold_cancellable(secret, timeout, cancel),
    }
}

#[cfg(windows)]
fn windows_copy_and_hold(secret: &[u8], timeout: u64, cancel: &Cancellation) -> Result<()> {
    crate::clip::win32_delayed::copy_and_hold_cancellable(secret, timeout, cancel)
}

#[cfg(not(windows))]
fn windows_copy_and_hold(_secret: &[u8], _timeout: u64, _cancel: &Cancellation) -> Result<()> {
    // `detect()` only returns Windows on Windows builds; this arm exists so
    // the module tree compiles cross-platform without cfg-sprinkled matches.
    Err(ClipError::Other(
        "internal error: Windows clipboard backend on a non-Windows build".into(),
    ))
}

// Windows backend is a whole module; keep it cfg-gated. Non-Windows builds
// never route here (detect() is cfg-driven), so no fallback stub is needed.
#[cfg(windows)]
pub mod win32;
#[cfg(windows)]
pub mod win32_delayed;

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
