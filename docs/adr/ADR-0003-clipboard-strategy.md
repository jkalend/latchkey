# ADR-0003: Clipboard strategy and auto-clear timeout

**Status:** Accepted
**Date:** 2026-09-09

## Context

Copy-to-clipboard is the primary retrieval path, and the clipboard is the
weakest point of any password manager on our two platforms:

- **Windows:** Clipboard History (Win+V) and cloud clipboard sync capture
  everything copied; auto-clear does not remove entries already captured.
- **WSL:** no native Linux clipboard without WSLg/an X server; the
  pragmatic path is shelling out to `clip.exe` on the Windows side.
- Process-command-line arguments are visible in `ps` output and WSL
  interop logs.

## Decision

1. **Auto-clear timeout: 30 seconds** (default), configurable
   `--timeout <secs>` in `[0, 300]`. On expiry: restore the pre-copy
   clipboard content if the platform API allows, else blank it.
   (Default changed from 15 → 30 s in round 4 of the design
   review — 15 s was tighter than a realistic "alt-tab, walk through
   the browser" paste takes, and Wayland-clear is strong enough
   to justify the extra window.)
2. **Copy via `clip.exe` stdin on WSL** — `printf '%s' "$secret" |
   clip.exe` semantics (from Rust: spawn with piped stdin). **Never**
   pass the secret as a command-line argument.
3. **Windows native:** Win32 clipboard API, **delayed rendering**
   (`SetClipboardData(..., NULL)`): the clipboard holds a promise, and
   our process renders the secret on demand. Two properties fall out for
   free: the secret never sits in the clipboard as a static value while
   the timer runs (paste targets pull it only when they ask); and
   **process death clears the clipboard automatically** — a dead process
   cannot answer a render request, so the OS treats the entry as empty.
   This resolves the terminal-closed / killed / sleep-threshold gap
   the naive implementation leaves: the secret never outlives us by
   more than what's already in flight.
   The auto-clear timer still runs in-process for the pre-copy restore
   and the explicit snatch-back.
4. **History detection:** on Windows (and from WSL via registry probe
   through interop), check
   `HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory`. If
   enabled, print a one-line warning at copy time: Clipboard History
   defeats auto-clear. Probe only — the tool never writes registry keys.
5. Timeout is enforced by the `rpass copy` process staying alive until
   expiry (simple, scriptable `&`-backgroundable), not by a daemon.
   Process death is *not* a failure mode on native Windows given delayed
   rendering (see #3) — the clipboard entry is a dead promise and the OS
   drops it.

6. **WSL residual risk (accepted, documented):** `clip.exe` performs a
   hard copy into the Windows clipboard and exits — the delayed-rendering
   trick is unavailable to us across the WSL boundary. If the `rpass
   copy` process dies on WSL before the timeout fires, the secret stays
   in the clipboard until the timeout hits — bounded at 30 s by default
   (§1), not an unbounded leak as it was at 15 s. Documented in
   TUI_GUIDE (§security behaviors) and THREAT_MODEL §5.2; users on WSL
   for whom this matters should either run `rpass` natively on Windows
   (where delayed rendering applies) or paste-and-clear the clipboard
   manually (`echo. | clip.exe`).

7. **Plain Linux (best-effort, added by decision 2026-09-09 round 3):**
   outside WSL, we attempt clipboard support across the Linux backends
   with a runtime probe in this order:
   1. `wl-copy` (Wayland) — if present and `WAYLAND_DISPLAY` set, with a
      short timer forked to clear the selection after the timeout. The
      Wayland clear is **stronger than the Windows one**: Wayland holds
      a MIME-typed offer in memory, and when we re-offer a blank
      clipboard, prior targets that already received the data are left
      alone — subsequent pastes get the cleared value.
   2. `xclip` / `xsel` (X11) — block with the selection owned and clear
      on timeout (X11's selection model makes process-exit clear the
      clipboard naturally, mirroring delayed-render — a death case
      better than Windows native).
   3. None found → copy fails with a clear error naming the missing
      tool, no crash, no silent no-op.
   Platform probe follows the env-var + osrelease pattern: WSL is
   detected by `WSL_DISTRO_NAME`/`WSL_INTEROP` (primary) with a
   "microsoft" substring check in `/proc/sys/kernel/osrelease`
   (fallback), and only in its absence do we try wl-copy/xclip/xsel.
   Linux clipboard auto-clear parity with Windows is documented in the
   README and THREAT_MODEL §5.2 (the X11 death-clear is a benefit, not
   a regression).

## Consequences

- 15 s is long enough to alt-tab and paste, short enough to bound the
  exposure window against shoulder-surfing (THREAT_MODEL §5.2).
- Restore works by saving the current clipboard content before
  `SetClipboardData` and re-setting it on expiry (Win32); on WSL, by
  best-effort re-set via `powershell.exe Set-Clipboard` only if the old
  content was plain text. Text-only; binary clipboard content is cleared,
  not restored.
- A user with Clipboard History enabled still leaks into history — we
  warn loudly, we don't pretend to prevent. Full mitigation is
  documented in the TUI guide (exclude the app or disable history).
- No daemon: `rpass copy` holds the process open for 15 s; Ctrl-C skips
  the wait and clears immediately.
