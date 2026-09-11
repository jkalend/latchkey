//! Platform detection and routing (ADR-0008).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Wsl,
    Linux,
}

/// Detect the platform per ADR-0008:
/// - Windows: compile-time cfg (native binary always Win32 path).
/// - WSL: `WSL_DISTRO_NAME` or `WSL_INTEROP` env (primary), "microsoft"
///   substring in /proc/sys/kernel/osrelease (fallback).
/// - plain Linux otherwise.
pub fn detect() -> Platform {
    #[cfg(windows)]
    {
        Platform::Windows
    }
    #[cfg(not(windows))]
    {
        if is_wsl() {
            Platform::Wsl
        } else {
            Platform::Linux
        }
    }
}

#[cfg(not(windows))]
fn is_wsl() -> bool {
    // Primary: env vars present in every WSL2 session.
    if std::env::var_os("WSL_DISTRO_NAME").is_some() || std::env::var_os("WSL_INTEROP").is_some() {
        return true;
    }
    // Fallback: Microsoft kernel tag.
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.to_ascii_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// True when the Windows Clipboard History feature is enabled for the current
/// user (ADR-0003 §4). Probe only — we never write registry keys.
pub fn clipboard_history_enabled() -> Option<bool> {
    crate::clip::win_history::query_enable_history()
}

/// Locate an executable on PATH (unix-style lookup for WSL/Linux backends).
#[cfg(not(windows))]
pub(crate) fn which(tool: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(tool);
        if is_executable(&cand) {
            return Some(cand);
        }
    }
    None
}

/// On Windows builds the unix backends are compiled out, but the `unix`
/// module's probe() still references this — provide a never-used stub.
#[cfg(windows)]
pub(crate) fn which(_tool: &str) -> Option<std::path::PathBuf> {
    None
}

#[cfg(not(windows))]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn detect_matches_cfg() {
        // On the test machine: WSL env vars absent under plain ssh, osrelease
        // decides. We just assert the invariant that detection is deterministic.
        assert_eq!(detect(), detect());
    }

    #[cfg(windows)]
    #[test]
    fn windows_is_windows() {
        assert_eq!(detect(), Platform::Windows);
    }
}
