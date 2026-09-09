# ADR-0007: TUI library — ratatui

**Status:** Accepted
**Date:** 2026-09-09

## Context

The TUI needs a maintained, pure-Rust terminal library. Candidates:

- **`ratatui`** — the actively maintained community fork of `tui-rs`;
  pure Rust, immediate-mode drawing, crossterm backend (no C, no
  ncurses).
- **`cursive`** — higher-level retained-mode widgets, but heavier
  dependency tree and a ncurses backend option (C) unless pinned to
  the crossterm backend.

## Decision

`ratatui` with the `crossterm` backend.

## Consequences

- Consistent with ADR-0001's no-C-build principle: the entire toolchain
  is pure Rust, `cargo build` works identically on Windows and WSL.
- Crossterm handles both Win32 console and POSIX terminals — one input
  model across our two platforms.
- We write our own widget composition (search list, detail view) rather
  than getting `cursive`'s prebuilt dialogs — acceptable for a
  single-purpose interface of this size.
- Immediate-mode drawing suits the security posture: the list renders
  from the decrypted index each frame, so masking/re-masking state
  (TUI_GUIDE) is a redraw, not a widget-tree mutation to get right.
