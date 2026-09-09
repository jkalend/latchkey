# TUI Guide

**Status:** Draft v0.1 — pre-implementation

> Placeholder outline. The TUI is the last deliverable in the authoring
> order (PROPOSAL.md §4); this document gets real content once the
> command surface and vault format are frozen and a `rpass tui` skeleton
> exists.

## Planned scope

- Entry: `rpass tui` (or `rpass` with no subcommand, if the UX feels
  right).
- Fuzzy search over titles/usernames (index-only decryption — secrets
  stay untouched until selection, VAULT_FORMAT §5).
- Single-item detail view with masked secrets, `Enter` to copy with the
  ADR-0003 auto-clear countdown displayed in the UI.

## Keybindings (proposal)

| Key | Action |
|---|---|
| `/` | Focus search |
| `↑`/`↓` | Navigate list |
| `Enter` | Open item / copy secret |
| `e` | Edit item |
| `d` | Delete item (confirmation) |
| `g` | Generate password into item |
| `q` / `Esc` | Back / quit |

## Security behaviors

- Secrets masked by default; explicit reveal (`r` key) with a visible
  "on screen" indicator and auto-re-mask after 10 s of no input.
- **Auto-lock after 10 minutes of inactivity** (configurable,
  `RPASS_TUI_LOCK_MINS`, default 10): the DEK, KEK, and all decrypted
  secrets are zeroized and dropped; the TUI keeps running with a
  password prompt. Re-entry cost is one Argon2 round-trip — same as any
  CLI invocation. This replaces the no-lock alternative (a TUI session
  holding a DEK for hours is the single biggest memory-exposure window
  in the tool; THREAT_MODEL §5.3's mitigations are designed around
  short unlock lifetimes).

- **Grace period for pending clipboard operations (60 s):** when the
  lock point arrives with a `rpass copy` clipboard wait still pending,
  the TUI delays the actual secret-drop by up to 60 s. Three cases:
  - The copy's auto-clear timeout fires during the grace window →
    lock proceeds normally at the end of the copy, secret dropped as
    soon as it's safe.
  - The user pastes during the grace window → clipboard wait
    completes on demand; lock proceeds immediately (no waiting around
    for them to finish typing — the clipboard cleared on paste).
  - Neither happens within 60 s → lock fires anyway, the pending
    clipboard promise becomes dead-on-arrival; the user re-enters a
    master password to continue.
  The grace is bounded (never "hold the copy forever") because an
  unbounded grace would let a forgotten copy hold the vault open
  indefinitely. Bound: 60 s.
- Explicit `L` keybinding locks immediately — bypasses any grace.
- No focus-loss lock — cross-platform terminal focus events are
  unreliable on WSL/Windows-Terminal combos; idle-timeout is the
  uniform floor.
- No secret ever rendered in the search box or list rows.
- Clipboard countdown shown as a status-bar timer; the process holds the
  timeout exactly as the CLI does (ADR-0003) — no daemon.
- Warns at startup if Windows Clipboard History is detected enabled.

## Library decision

TBD — `ratatui` is the leading candidate (maintained fork of
`tui-rs`, pure Rust, no-termbox C dependency — consistent with
ADR-0001's no-C-build principle). Decide in an ADR-0007 when
implementation starts.
