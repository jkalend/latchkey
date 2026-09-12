//! WSL clipboard backend — PowerShell interop (ADR-0003 §2, ADR-0008 §3).
//!
//! Why not `clip.exe`: it decodes stdin through the console/OEM code page,
//! so any secret with bytes ≥ 0x80 pastes as mojibake. PowerShell's
//! `Set-Clipboard` takes a .NET string; piping it as UTF-16LE-in-base64 is
//! exact (base64 is pure ASCII — no code page can touch it, and no secret
//! appears on a command line).
//!
//! Ownership model matches the other backends: the pre-copy clipboard is
//! snapshotted; after the timeout it is restored ONLY if the clipboard
//! still holds our value. Ctrl-C safety is limited on WSL — see
//! clip/mod.rs for the honest version.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::clip::error::{ClipError, Result};

const PS_NAME: &str = "powershell.exe";
/// Fixed interop locations, tried before PATH (a tampered WSL PATH could
/// otherwise point `powershell.exe` at an arbitrary binary).
const PS_FIXED: &[&str] = &[
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe",
];

fn powershell() -> std::path::PathBuf {
    for cand in PS_FIXED {
        if std::path::Path::new(cand).exists() {
            return cand.into();
        }
    }
    std::path::PathBuf::from(PS_NAME)
}

// ─── base64 (RFC 4648, with padding) ────────────────────────────────────────
// Minimal, dependency-free: ADR-0005's no-dep-creep taste applies. Only what
// the PowerShell bridge needs.

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        out.push(B64_ALPHABET[(b[0] >> 2) as usize] as char);
        out.push(B64_ALPHABET[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(b[2] & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let n_groups = bytes.len() / 4;
    for (gi, g) in bytes.chunks(4).enumerate() {
        let last = gi + 1 == n_groups;
        let v0 = b64_val(g[0])?;
        let v1 = b64_val(g[1])?;
        out.push(((v0 << 2) | (v1 >> 4)) as u8);
        if g[2] == b'=' {
            if !(last && g[3] == b'=') {
                return None;
            }
            break;
        }
        let v2 = b64_val(g[2])?;
        out.push((((v1 & 0x0f) << 4) | (v2 >> 2)) as u8);
        if g[3] == b'=' {
            if !last {
                return None;
            }
            break;
        }
        let v3 = b64_val(g[3])?;
        out.push((((v2 & 0x03) << 6) | v3) as u8);
    }
    Some(out)
}

// ─── PowerShell bridge ─────────────────────────────────────────────────────

fn run_ps_stdin(script: &str, stdin_bytes: &[u8]) -> Result<()> {
    let mut child = Command::new(powershell())
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| ClipError::Tool {
            tool: PS_NAME,
            detail: e.to_string(),
        })?;
    {
        let stdin = child.stdin.as_mut().ok_or_else(|| ClipError::Tool {
            tool: PS_NAME,
            detail: "no stdin".into(),
        })?;
        stdin
            .write_all(stdin_bytes)
            .and_then(|_| stdin.flush())
            .map_err(|e| ClipError::Tool {
                tool: PS_NAME,
                detail: e.to_string(),
            })?;
    }
    let status = child.wait().map_err(|e| ClipError::Tool {
        tool: PS_NAME,
        detail: e.to_string(),
    })?;
    if !status.success() {
        return Err(ClipError::Tool {
            tool: PS_NAME,
            detail: format!("exit {status}"),
        });
    }
    Ok(())
}

fn run_ps_output(script: &str) -> Option<Vec<u8>> {
    let out = Command::new(powershell())
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

/// Secret bytes → base64 of UTF-16LE (matches win32's to_utf16 semantics).
fn encode_utf16_b64(secret: &[u8]) -> Zeroizing<String> {
    let utf16: Zeroizing<Vec<u16>> =
        Zeroizing::new(String::from_utf8_lossy(secret).encode_utf16().collect());
    let bytes: Zeroizing<Vec<u8>> =
        Zeroizing::new(utf16.iter().flat_map(|u| u.to_le_bytes()).collect());
    Zeroizing::new(b64_encode(&bytes))
}

fn set_clipboard_utf16_b64(b64: &str) -> Result<()> {
    run_ps_stdin(
        "$b=[Console]::In.ReadToEnd().Trim(); \
         Set-Clipboard -Value ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b)))",
        b64.as_bytes(),
    )
}

/// Current clipboard text as raw UTF-16LE bytes, or None if empty/unreadable.
fn snapshot_utf16() -> Option<Vec<u8>> {
    let out = run_ps_output(
        "$t = Get-Clipboard -Raw; \
         if ($null -ne $t) { \
           [Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($t))) \
         }",
    )?;
    let decoded = b64_decode(&String::from_utf8_lossy(&out))?;
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

fn set_clipboard_from_utf16(bytes: &[u8]) -> Result<()> {
    set_clipboard_utf16_b64(&b64_encode(bytes))
}

fn clear_clipboard() {
    // Set-Clipboard has no "empty" value in PS 5.1; an empty string is the
    // closest user-visible empty state (and definitely not the old "\r\n").
    // b64 of "" decodes to an empty .NET string.
    let _ = set_clipboard_utf16_b64("");
}

pub fn copy_and_hold(secret: &[u8], timeout_secs: u64) -> Result<()> {
    let ours = encode_utf16_b64(secret);
    let ours_bytes = b64_decode(&ours).unwrap_or_default();
    let prev = snapshot_utf16();
    set_clipboard_utf16_b64(&ours)?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        std::thread::sleep(
            Duration::from_millis(200).min(deadline.saturating_duration_since(Instant::now())),
        );
    }

    // Restore only if we still own the clipboard.
    match snapshot_utf16() {
        Some(cur) if cur != ours_bytes => {
            // Someone else owns the clipboard now — leave it alone.
        }
        _ => match &prev {
            Some(p) => {
                let _ = set_clipboard_from_utf16(p);
            }
            None => clear_clipboard(),
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_roundtrip() {
        for case in [&b""[..], b"a", b"ab", b"abc", b"abcd", b"hello world"] {
            let enc = b64_encode(case);
            assert_eq!(
                b64_decode(&enc).as_deref(),
                Some(case),
                "roundtrip {case:?}"
            );
        }
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"a"), "YQ==");
        assert_eq!(b64_encode(b"ab"), "YWI=");
        assert_eq!(b64_encode(b"abc"), "YWJj");
        assert!(b64_decode("YQ").is_none()); // padding truncated
        assert!(b64_decode("YQ==YQ==").is_none()); // padding mid-string
        assert!(b64_decode("YQ==\n").as_deref() == Some(b"a"));
    }

    #[test]
    fn utf16_b64_roundtrip() {
        let b64 = encode_utf16_b64("pässwörd123".as_bytes());
        let raw = b64_decode(&b64).unwrap();
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        assert_eq!(String::from_utf16_lossy(&units), "pässwörd123");
    }
}
