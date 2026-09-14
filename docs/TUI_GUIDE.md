# TUI Guide

**Status:** Public-preview implementation (`latchkey` 0.2.0)

## Scope

- Entry: `latchkey tui` — or just `latchkey` with no subcommand, which is the
  same thing (the TUI is the interactive default).
- Fuzzy search over titles/usernames (index-only decryption — secrets
  stay untouched until selection, VAULT_FORMAT §5).
- Single-item detail view with masked secrets; `c` copies the password and
  `t` copies the current TOTP code with the ADR-0003 countdown.
- Add/edit forms cover title, username, password, URL, notes, and TOTP
  without leaving the alternate screen. Delete requires an explicit `y`
  confirmation showing title, username, and `item_id`.

## Keybindings

| Key | Action |
|---|---|
| `/` | Start search |
| `↑`/`↓` | Navigate list |
| `PgUp`/`PgDn` | Scroll list by 10 |
| mouse wheel | Scroll list |
| `Enter` | Open selected item |
| `a` | Add a credential |
| `e` | Edit the selected credential |
| `d` | Delete the selected credential after confirmation |
| `Tab` / `Shift-Tab` | Move through form fields |
| `Ctrl-G` | Generate a password in a form |
| `c` | Copy password in detail view |
| `t` | Copy current TOTP code |
| `r` | Reveal password for 10 seconds |
| `L` | Lock immediately |
| `q` / `Esc` | Back / quit |

## Security behaviors

- Secrets masked by default; explicit reveal (`r` key) with a visible
  "on screen" indicator and auto-re-mask after 10 s of no input.
- **Auto-lock after 10 minutes of inactivity** (configurable,
  `LATCHKEY_TUI_LOCK_MINS`, default 10): the DEK, KEK, and all decrypted
  secrets are zeroized and dropped; the TUI keeps running with a
  password prompt. Re-entry cost is one Argon2 round-trip — same as any
  CLI invocation. This replaces the no-lock alternative (a TUI session
  holding a DEK for hours is the single biggest memory-exposure window
  in the tool; THREAT_MODEL §5.3's mitigations are designed around
  short unlock lifetimes).

- **Pending clipboard operation:** copy runs in a worker and calls the
  platform auto-clear path. Locking drops the vault immediately; the worker
  retains only the copied secret until the bounded 30-second clear completes.
  The status bar reports completion or a clipboard error.
- Explicit `L` keybinding locks immediately; the pending clipboard clear still
  runs to completion.
- No focus-loss lock — cross-platform terminal focus events are
  unreliable on WSL/Windows-Terminal combos; idle-timeout is the
  uniform floor.
- No secret ever rendered in the search box or list rows.
- Form password, notes, and TOTP input is masked. Edit forms never preload
  existing secret values: blank keeps the existing value and `-` clears it.
  Cancelling or locking drops and zeroizes the form. A failed save cannot be
  retried against the same in-memory vault; `Esc` discards the form and locks
  so the vault must be reopened.
- Clipboard countdown shown as a status-bar timer; the process holds the
  timeout exactly as the CLI does (ADR-0003) — no daemon.
- Warns at startup if Windows Clipboard History is detected enabled.

## Library decision

ratatui 0.29 + crossterm 0.28 — maintained, pure Rust, no termbox C
dependency, consistent with ADR-0001's no-C-build principle.
