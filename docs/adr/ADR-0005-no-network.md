# ADR-0005: No network capability, enforced structurally

**Status:** Accepted
**Date:** 2026-09-09

## Context

"Local-first" is a security claim, and security claims that rest on
developer discipline rot. A tool that *could* phone home eventually
will (telemetry PR, update check, "helpful" feature).

## Decision

**No HTTP/TLS client dependency anywhere in the tree — including
transitive dependencies.** The guarantee is checkable, not promised:

1. `cargo deny` CI rule banning `reqwest`, `hyper`, `ureq`, `isahc`,
   `curl`, `tokio` networking features, and all `http`/`tls` crates (with
   allow-lists only where a tool needs fetching, e.g. `cargo deny`'s own
   advisory database — that runs in CI, not in the shipped binary).
2. No `std::net` / `std::os::windows::win32` socket APIs in `src/` —
   enforced by a grep-based CI check over the source.
3. The README states it as a *checkable* property with the command a
   skeptic can run:
   `cargo tree | grep -iE "reqwest|hyper|ureq|http|tls"` returning
   empty.

## Consequences

- The no-network claim survives contributor turnover because the CI
  enforces it, not the review.
- No update checker, no breach-report lookups (HaveIBeenPwned k-anonymity
  checks are explicitly out of scope; users wanting them can use a
  browser). Documented as a non-feature.
- Clipboard-on-WSL does spawn `clip.exe` / `powershell.exe` — local
  inter-process calls, not network. The ADR concerns sockets, and the
  spawned binaries are named explicitly so the claim stays precise.
- If v2 ever wants optional sync, that's a new binary/package — this
  ADR's constraint stays with the core.
