# ADR-0008: WSL detection and platform routing

**Status:** Accepted
**Date:** 2026-09-09

## Context

The Linux binary is identical on WSL and bare-metal Linux. The docs
promise WSL-specific behavior (clip.exe routing, registry probe, WSL
residual risks) but say nothing about how the binary knows which world
it's in, or what a plain-Linux user gets. Detection strategy and the
fallback chain matter: a wrong guess clips the secret in the wrong
world or silently no-ops.

## Decision

1. **WSL detection primary:** presence of `WSL_DISTRO_NAME` or
   `WSL_INTEROP` in the environment (set in every WSL2 session, absent
   on plain Linux).

2. **WSL detection fallback:** `microsoft` substring (case-insensitive)
   in `/proc/sys/kernel/osrelease` — the standard Microsoft kernel
   branch tag for WSL2. Used only if both env vars are absent, since
   some distros customize the string.

3. **Platform routing on WSL:** as ADR-0003 specifies — clipboard via
   `clip.exe` stdin, registry probe via interop, no Wayland/X11
   heuristics.

4. **Platform routing on plain Linux:** best-effort clipboard across
   the Linux stack, probed in this order (ADR-0003 §7 for the detail):
   `wl-copy` → `xclip`/`xsel`. If none is available, clipboard
   operations fail with a clear, specific error naming the missing
   tool; the rest of the tool works.

5. **Windows native:** always the Win32 clipboard path — no probing.

## Consequences

- **Deterministic defaults:** WSL gets Windows behavior, plain Linux
  gets Linux behavior, never a crossward guess. The env-var primary is
  the strongest signal; the osrelease fallback catches the rare case
  where the env vars were stripped (e.g., ssh-ing out of WSL).
- **No new clipboard natives:** we probe for tools, we don't link
  against Xlib/Wayland — `clip/` shells out to the discovered binary
  the same way WSL shells out to `clip.exe`.
- **Two shipped platform behaviors, three implemented:** README and
  THREAT_MODEL continue describing Windows + WSL as the targets; the
  plain-Linux path is documented, tested best-effort, and *not*
  advertised as a supported platform — supported means "auto-clear
  parity is engineered and tested," which requires X11/Wayland
  specifics documented in ADR-0003 §7.
- **Update:** the "other Linux out of scope" line in the README is
  amended to "best-effort — see ADR-0008".