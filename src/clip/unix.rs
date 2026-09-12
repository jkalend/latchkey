//! Plain-Linux clipboard backend — best-effort wl-copy → xclip/xsel (ADR-0003 §7).
//!
//! Ownership model (shared with the other backends since the review): the
//! pre-copy clipboard is snapshotted; after the timeout the restore happens
//! ONLY if the clipboard still holds our value (normalized content compare).
//! If the user copied something else in the meantime, their clipboard is
//! left alone.
//!
//! Honest limit, documented in clip/mod.rs and README: on X11/Wayland the
//! helper tool owns the selection as a background process. If rpass dies
//! before the timeout, that helper keeps serving the secret until the next
//! copy — there is no signal handler on this platform.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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
    // wl-copy requires a Wayland session.
    if std::env::var_os("WAYLAND_DISPLAY").is_some() && platform::which("wl-copy").is_some() {
        return Ok(Tool::WlCopy);
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

/// Current clipboard text per the selected tool, or None when it can't be
/// read (no content, spawn failure — both treated as "unknown; don't touch").
fn read_clipboard(tool: &Tool) -> Option<Vec<u8>> {
    let (bin, args) = tool.paste_cmd();
    let output = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    if output.stdout.is_empty() {
        return None;
    }
    Some(normalize(&output.stdout))
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
        let stdin = child.stdin.as_mut().ok_or_else(|| ClipError::Tool {
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
    let tool = probe()?;
    let prev = read_clipboard(&tool);
    write_clipboard(&tool, secret)?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        std::thread::sleep(
            Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())),
        );
    }

    // Restore only if we still own the clipboard; never clobber whatever
    // the user copied in the meantime. If we can't TELL whether it's ours
    // (snapshot/read failed), clear to empty — the secure default for a
    // secret we put there.
    match read_clipboard(&tool) {
        Some(current) if current != normalize(secret) => {
            // Someone else owns the clipboard now — leave it alone.
        }
        _ => match &prev {
            Some(p) => {
                let _ = write_clipboard(&tool, p);
            }
            None => {
                let _ = write_clipboard(&tool, b"");
            }
        },
    }
    Ok(())
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
