//! Vault path resolution (ADR-0002, CLI_REFERENCE "Environment variables").
//!
//! Precedence: `--vault` flag > `LATCHKEY_VAULT` env > platform default.

use std::path::PathBuf;

/// Platform-default vault location (ADR-0002):
/// - Windows: `%LOCALAPPDATA%\latchkey\vault.bin`
/// - Linux/WSL: `${XDG_STATE_HOME:-$HOME/.local/state}/latchkey/vault.bin`
pub fn default_vault_path() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join("latchkey").join("vault.bin");
        }
        // Fall through to a relative fallback if LOCALAPPDATA is somehow unset.
        PathBuf::from("latchkey").join("vault.bin")
    }
    #[cfg(not(windows))]
    {
        let state = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
                    .join(".local")
                    .join("state")
            });
        state.join("latchkey").join("vault.bin")
    }
}

/// Resolve per precedence: explicit flag, then env, then default.
pub fn resolve(flag: Option<&std::path::Path>) -> PathBuf {
    if let Some(p) = flag {
        return p.to_path_buf();
    }
    if let Some(env) = std::env::var_os("LATCHKEY_VAULT") {
        if !env.is_empty() {
            return PathBuf::from(env);
        }
    }
    default_vault_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_wins() {
        let p = resolve(Some(std::path::Path::new("/explicit/vault.bin")));
        assert_eq!(p, PathBuf::from("/explicit/vault.bin"));
    }

    #[test]
    fn default_is_sane() {
        let p = default_vault_path();
        assert!(p.to_string_lossy().contains("vault.bin"));
    }
}
