//! WSL clipboard backend — `clip.exe` via stdin (ADR-0003 §2, ADR-0008 §3).
//!
//! `clip.exe` hard-copies into the Windows clipboard and exits, so delayed
//! rendering is unavailable across the WSL boundary. The `rpass copy` process
//! therefore stays alive for the timeout and blanks the clipboard on expiry
//! by piping an empty string (best-effort restore is not possible without
//! interop gymnastics; v1 clears, doesn't restore). Residual risk is
//! documented in ADR-0003 §6.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::clip::error::{ClipError, Result};

const CLIP_EXE: &str = "clip.exe";

fn spawn_clip(secret: &[u8]) -> Result<()> {
    let mut child = Command::new(CLIP_EXE)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| ClipError::Tool {
            tool: CLIP_EXE,
            detail: e.to_string(),
        })?;
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| ClipError::Tool {
            tool: CLIP_EXE,
            detail: "no stdin".into(),
        })?;
        stdin
            .write_all(secret)
            .and_then(|_| stdin.flush())
            .map_err(|e| ClipError::Tool {
                tool: CLIP_EXE,
                detail: e.to_string(),
            })?;
    }
    let status = child.wait().map_err(|e| ClipError::Tool {
        tool: CLIP_EXE,
        detail: e.to_string(),
    })?;
    if !status.success() {
        return Err(ClipError::Tool {
            tool: CLIP_EXE,
            detail: format!("exit {}", status),
        });
    }
    Ok(())
}

/// Blank the Windows clipboard from WSL: pipe an empty line to clip.exe.
fn clear_clipboard() {
    let _ = spawn_clip(b"\r\n");
}

pub fn copy_and_hold(secret: &[u8], timeout_secs: u64) -> Result<()> {
    spawn_clip(secret)?;
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200).min(deadline - Instant::now()));
    }
    clear_clipboard();
    Ok(())
}

pub fn copy_now(secret: &[u8]) -> Result<()> {
    spawn_clip(secret)
}

#[cfg(test)]
mod tests {
    // No WSL-specific unit tests on a Windows host; covered by CI on the
    // WSL runner and the platform::tests routing test.
}
