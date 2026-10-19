//! Plain-Linux clipboard backend — best-effort wl-copy → xclip/xsel (ADR-0003 §7).
//!
//! Ownership model (shared with the other backends since the review): the
//! pre-copy clipboard is snapshotted; after the timeout the restore happens
//! ONLY if the clipboard still holds our value (normalized content compare).
//! If the user copied something else in the meantime, their clipboard is
//! left alone.
//!
//! Honest limit, documented in clip/mod.rs and README: on X11/Wayland the
//! helper tool owns the selection as a background process. If latchkey dies
//! before the timeout, that helper keeps serving the secret until the next
//! copy — there is no signal handler on this platform.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::clip::error::{ClipError, Result};
use crate::clip::platform;

enum Tool {
    WlCopy,
    XClip,
    XSel,
}

impl Tool {
    fn name(&self) -> &'static str {
        match self {
            Tool::WlCopy => "wl-copy",
            Tool::XClip => "xclip",
            Tool::XSel => "xsel",
        }
    }

    /// Args to claim the CLIPBOARD selection from stdin.
    fn set_args(&self) -> &'static [&'static str] {
        match self {
            Tool::WlCopy => &[],
            Tool::XClip => &["-selection", "clipboard", "-in"],
            Tool::XSel => &["--clipboard", "--input"],
        }
    }

    /// Binary + args to print the CLIPBOARD selection on stdout.
    fn paste_cmd(&self) -> (&'static str, &'static [&'static str]) {
        match self {
            // --no-newline keeps the byte stream exact for the ownership compare.
            Tool::WlCopy => ("wl-paste", &["--no-newline"]),
            Tool::XClip => ("xclip", &["-selection", "clipboard", "-out"]),
            Tool::XSel => ("xsel", &["--clipboard", "--output"]),
        }
    }
}

fn probe() -> Result<Tool> {
    // wl-copy requires a Wayland session; wl-paste is its read counterpart
    // and the ownership compare depends on it (SEC-05). A session with
    // wl-copy but no wl-paste would silently break expiry verification.
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        let copy = platform::which("wl-copy").is_some();
        let paste = platform::which("wl-paste").is_some();
        match (copy, paste) {
            (true, true) => return Ok(Tool::WlCopy),
            (true, false) => {
                return Err(ClipError::NoBackend(
                    "wl-copy is installed but wl-paste is missing — install wl-clipboard \
                     fully (both binaries) for clipboard support"
                        .into(),
                ))
            }
            _ => {}
        }
    }
    if platform::which("xclip").is_some() {
        return Ok(Tool::XClip);
    }
    if platform::which("xsel").is_some() {
        return Ok(Tool::XSel);
    }
    Err(ClipError::NoBackend(
        "install wl-copy (Wayland) or xclip/xsel (X11) for clipboard support".into(),
    ))
}

/// Tool output differs on whether the selection is echoed with a trailing
/// newline; compare and restore a normalized form (one trailing \n stripped).
fn normalize(bytes: &[u8]) -> Vec<u8> {
    match bytes {
        [rest @ .., b'\n'] => rest.to_vec(),
        _ => bytes.to_vec(),
    }
}

/// Current clipboard text per the selected tool.
///
/// Distinguishes three outcomes (SEC-05): genuinely empty selection
/// (`Ok(None)`), readable contents (`Ok(Some(..))`), and a tool/transport
/// failure (`Err`). The expiry path must never treat "unknown" as "empty".
enum ClipState {
    Empty,
    Value(Vec<u8>),
    ReadError,
}

fn read_clipboard_state(tool: &Tool) -> ClipState {
    let (bin, args) = tool.paste_cmd();
    match Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        Err(_) => ClipState::ReadError,
        Ok(output) if !output.status.success() => ClipState::ReadError,
        Ok(output) if output.stdout.is_empty() => ClipState::Empty,
        Ok(output) => ClipState::Value(normalize(&output.stdout)),
    }
}

/// Legacy presence-only snapshot for callers that don't need the distinction.
#[cfg_attr(not(test), allow(dead_code))]
fn read_clipboard(tool: &Tool) -> Option<Vec<u8>> {
    match read_clipboard_state(tool) {
        ClipState::Value(bytes) => Some(bytes),
        _ => None,
    }
}

/// Write `data` to the clipboard, closing stdin immediately so the helper
/// claims the selection NOW (holding stdin open merely delays ownership —
/// xclip/xsel buffer until EOF, which broke paste during the hold window).
fn write_clipboard(tool: &Tool, data: &[u8]) -> Result<()> {
    let mut child = Command::new(tool.name())
        .args(tool.set_args())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| ClipError::Tool {
            tool: tool.name(),
            detail: e.to_string(),
        })?;
    {
        let mut stdin = child.stdin.take().ok_or_else(|| ClipError::Tool {
            tool: tool.name(),
            detail: "no stdin".into(),
        })?;
        stdin
            .write_all(data)
            .and_then(|_| stdin.flush())
            .map_err(|e| ClipError::Tool {
                tool: tool.name(),
                detail: e.to_string(),
            })?;
    }
    let status = child.wait().map_err(|e| ClipError::Tool {
        tool: tool.name(),
        detail: e.to_string(),
    })?;
    if !status.success() {
        return Err(ClipError::Tool {
            tool: tool.name(),
            detail: format!("exit {status}"),
        });
    }
    Ok(())
}

pub fn copy_and_hold(secret: &[u8], timeout_secs: u64) -> Result<()> {
    copy_and_hold_cancellable(secret, timeout_secs, &crate::clip::Cancellation::default())
}

pub fn copy_and_hold_cancellable(
    secret: &[u8],
    timeout_secs: u64,
    cancel: &crate::clip::Cancellation,
) -> Result<()> {
    crate::clip::validate_timeout(timeout_secs)?;
    let tool = probe()?;
    let prev = read_clipboard(&tool);
    write_clipboard(&tool, secret)?;

    cancel.hold(timeout_secs);

    // Tool protocols cannot make compare-and-restore atomic; never write
    // after an unreadable snapshot, which may belong to another process.
    // (SEC-05) A failed read at expiry must surface as an error, not silent
    // success. Retry briefly (contention is transient), then report
    // uncertainty explicitly.
    let mut attempts = 0;
    loop {
        match read_clipboard_state(&tool) {
            ClipState::ReadError if attempts < 3 => {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(200 * attempts as u64));
            }
            ClipState::ReadError => {
                return Err(ClipError::Other(
                    "could not verify the clipboard was cleared (clipboard read kept failing); \
                     it may still hold the copied secret — clear it manually"
                        .into(),
                ));
            }
            ClipState::Value(bytes) if bytes == normalize(secret) => {
                write_clipboard(&tool, prev.as_deref().unwrap_or(b""))?;
                return Ok(());
            }
            // Empty, or a value that is not ours (user copied something else):
            // nothing latchkey-owned remains.
            _ => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_one_trailing_newline() {
        assert_eq!(normalize(b"abc"), b"abc");
        assert_eq!(normalize(b"abc\n"), b"abc");
        assert_eq!(normalize(b"abc\n\n"), b"abc\n");
        assert_eq!(normalize(b""), b"");
    }
}
