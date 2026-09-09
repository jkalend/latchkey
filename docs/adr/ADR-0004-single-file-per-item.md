# ADR-0004: Single vault file with per-item encryption

**Status:** Accepted
**Date:** 2026-09-09

## Context

Two viable storage shapes:

1. **Single file, monolithic encryption** — decrypt the whole vault into
   memory to do anything.
2. **Single file, per-item encryption** — one AEAD ciphertext per item
   plus an encrypted index (what VAULT_FORMAT.md specifies).
3. **Directory of per-item files** (the `pass` model) — each secret a
   file, metadata in filenames (leaks!), git-friendly.

## Decision

Option 2: a single file with an encrypted index and per-item AEAD
ciphertexts.

## Consequences

- `list` and TUI browsing decrypt only the index — titles are visible
  without ever touching a secret (title placement decided in
  VAULT_FORMAT §5).
- One item edit rewrites that item's ciphertext only; the write protocol
  (atomic rename, VAULT_FORMAT §8) makes even full rewrites safe under
  naive sync.
- No per-file metadata leakage (unlike `pass`, where filenames are
  account names in cleartext).
- Cost vs. option 1: an index to maintain, tombstones, compaction
  (VAULT_FORMAT §6.3). Accepted — the complexity is bounded and
  specced.
- Cost vs. option 3: no git history of secrets (which is a *feature* —
  `pass`'s history is ciphertext-only anyway) and no per-item
  filesystem permissions.
