# ADR-0002: Vault file location

**Status:** Accepted
**Date:** 2026-09-09

## Context

The vault must live somewhere conventional, user-backuppable, and
discoverable on both platforms. Candidates considered:

- Windows: `%APPDATA%`, `%LOCALAPPDATA%`, `%USERPROFILE%`
- Linux/WSL: `$HOME`, XDG data/state dirs

## Decision

| Platform | Path |
|---|---|
| Windows | `%LOCALAPPDATA%\latchkey\vault.bin` |
| Linux/WSL | `${XDG_STATE_HOME:-$HOME/.local/state}/latchkey/vault.bin` |

`--vault <path>` overrides on every command; the default is printed by
`latchkey init`.

## Consequences

- **XDG_STATE_HOME, not XDG_DATA_HOME:** the vault is mutable state, not
  reusable data — and critically, state dirs are *not* expected to be in
  dotfiles repos, reducing accidental-commit risk.
- **LOCALAPPDATA, not APPDATA:** roaming profiles sync `%APPDATA%` to
  domain controllers by default in managed environments — an unrequested
  copy of the (encrypted) vault leaving the machine. `%LOCALAPPDATA%`
  stays local. The file is encrypted, so this is defense-in-depth, not a
  hard requirement.
- **WSL reality check:** the WSL filesystem lives in a VHDX on the
  Windows side; users who want Windows-side backup should copy via
  `\\wsl$\` or place the vault on a Windows drive path with `--vault
  /mnt/c/...`. Documented in the README quick start, not automated — we
  don't guess where the user wants it.
- One vault per location; no multi-vault index in v1 (`--vault` covers
  the use case without config surface).
