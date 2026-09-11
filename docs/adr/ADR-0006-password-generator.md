# ADR-0006: Password generator design

**Status:** Accepted (amended 2026-09-11 — see §3a)
**Date:** 2026-09-09

## Context

`rpass generate` must produce uniformly random passwords over the
requested alphabet with no modulo bias, and the defaults must be
defensible without hand-waving.

## Decision

1. **Randomness:** OS CSPRNG via `getrandom` — no userspace PRNG
   seeding, ever.
2. **Mapping to alphabet:** rejection sampling. Draw bytes, interpret as
   u32, reject values ≥ `floor(2^32 / alphabet_len) * alphabet_len`,
   take `value % alphabet_len`. (A 64-bit draw would reduce waste
   further; u32 keeps it simple and the bound analysis clean.)
3. **Presets:**

   | Preset | Alphabet | Length | Entropy |
   |---|---|---|---|
   | default | A-Za-z0-9 (62) | 20 | ~119 bits |
   | `--symbols` | + 16 common safe symbols (78) | 20 | ~125 bits |
   | `--passphrase` | EFF short list 2.0 (1296 words) | 8 words | ~83 bits |
   | `--hex` | 0-9a-f (16) | 32 | 128 bits |

   All presets target ≥ 78 bits; the default comfortably exceeds 100.

3a. **Amendment (2026-09-11).** The original table said "EFF short list
   2.0 (7776 words), 6 words, ~78 bits". That conflated two EFF lists:
   7776 (6⁵) is the *long* list; short list 2.0 is 6⁴ = **1296**
   words, ~10.34 bits/word. 6 words of short-2.0 is only ~62 bits —
   below the floor. Two options were considered: switch to the long
   list (7-char words, harder to type on phones) or keep short-2.0 and
   raise the default to 8 words (~82.7 bits). Short-2.0 at 8 words was
   chosen; the per-word entropy is lower but words stay ≤ 10 chars and
   the floor is cleared with margin. Implementation:
   `src/gen/mod.rs` (`DEFAULT_WORDS = 8`, embedded wordlist
   `src/gen/eff_short_2.txt`).

   The symbol set was also pinned to exactly 16 chars
   (`!@#$%^&*()-_=+`, no `[]{}<>?,.;:`) so the 78-char alphabet and
   ~125-bit figure are exact rather than approximate.

4. **No ambiguous-character exclusion by default** (`0`/`O`, `l`/`1`) —
   excluding characters *reduces* entropy and the ambiguity problem is
   better solved by `--symbols` selection or the user's font. Offered as
   `--no-ambiguous` opt-in for those who want it.
5. **Output:** to stdout by default (a *generated* password isn't a
   stored secret until stored); `--copy` routes it to the clipboard with
   the ADR-0003 timeout.
6. **Length bounds:** [8, 256]; passphrase words [3, 20].

## Consequences

- Entropy math is per-preset documented, so the README can make the
  "≥ 100 bits default" claim with arithmetic behind it.
- Passphrases use the offline EFF list — a wordlist file shipped in the
  binary (embedded via `include_str!`), not downloaded (ADR-0005).
- `--no-ambiguous` reduces effective entropy slightly; the help text
  states the reduction.
