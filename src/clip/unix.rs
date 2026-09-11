//! Plain-Linux clipboard backend — best-effort wl-copy → xclip/xsel (ADR-0003 §7).

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

fn spawn(tool: &Tool, args: &[&str], secret: &[u8]) -> Result<()> {
    let mut child = Command::new(tool.name())
        .args(args)
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
            .write_all(secret)
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
    match tool {
        Tool::WlCopy => {
            // wl-copy forks a child that owns the selection and exits when
            // cleared; `--forever`-less default also works with our timeout:
            // we copy, sleep, then overwrite the selection with empty.
            spawn(&tool, &[], secret)?;
        }
        Tool::XClip => {
            // -selection clipboard, keep stdin open for the timeout (xclip
            // owns the selection while alive; closing stdin = disown).
            let mut child = Command::new(tool.name())
                .args(["-selection", "clipboard", "-in"])
                .stdin(Stdio::piped())
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
                    .write_all(secret)
                    .and_then(|_| stdin.flush())
                    .map_err(|e| ClipError::Tool {
                        tool: tool.name(),
                        detail: e.to_string(),
                    })?;
                // Hold stdin open for the timeout; xclip exits on EOF.
                let deadline = Instant::now() + Duration::from_secs(timeout_secs);
                while Instant::now() < deadline {
                    std::thread::sleep(
                        Duration::from_millis(200)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
            } // stdin drops → xclip sees EOF → selection disowned → clipboard empty
            let _ = child.wait();
            return Ok(());
        }
        Tool::XSel => {
            let mut child = Command::new(tool.name())
                .args(["--clipboard", "--input"])
                .stdin(Stdio::piped())
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
                    .write_all(secret)
                    .and_then(|_| stdin.flush())
                    .map_err(|e| ClipError::Tool {
                        tool: tool.name(),
                        detail: e.to_string(),
                    })?;
                let deadline = Instant::now() + Duration::from_secs(timeout_secs);
                while Instant::now() < deadline {
                    std::thread::sleep(
                        Duration::from_millis(200)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
            }
            let _ = child.wait();
            return Ok(());
        }
    }
    // wl-copy path: overwrite the selection with empty after the timeout.
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        std::thread::sleep(
            Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    let _ = spawn(&tool, &[], b"");
    Ok(())
}

pub fn copy_now(secret: &[u8]) -> Result<()> {
    let tool = probe()?;
    match tool {
        Tool::WlCopy => spawn(&tool, &[], secret),
        Tool::XClip => spawn(&tool, &["-selection", "clipboard", "-in"], secret),
        Tool::XSel => spawn(&tool, &["--clipboard", "--input"], secret),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_backend_error_is_helpful() {
        // On a CI runner without any clipboard tool, probe must fail with the
        // named-tool error, not a panic. With a tool present it succeeds —
        // either way this must not hang.
        let r = super::probe();
        match r {
            Ok(_) => {}
            Err(e) => assert!(e.to_string().contains("wl-copy") || e.to_string().contains("xclip")),
        }
    }
}
