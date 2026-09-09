# Cryptography Specification

**Status:** Draft v0.1 — pre-implementation
**Covers:** rust_password_manager v1
**Platforms:** Windows 10/11 (native), Linux under WSL2

> This document is written to be reviewable without reading the code.
> Any security-relevant behavior not specified here is a bug in this spec
> and must be fixed here first, then in code.

---

## 1. Overview

```
master password ──Argon2id──▶ KEK (256-bit)
                                   │
vault header ◀─────────────────────┤ (unwrap)
  [salt, KDF params, alg IDs,      ▼
   wrapped DEK, MAC]            DEK (256-bit, random per vault)
                                   │
                                   ▼
                        AEAD (AES-256-GCM or
                        ChaCha20-Poly1305), per item
                                   │
                                   ▼
                        encrypted items + tags
```

Cryptographic libraries: the RustCrypto family — `argon2`, `aes-gcm`,
`chacha20poly1305`, `zeroize`, `secrecy` — pure-Rust, well-audited,
no C build friction on either of our platforms.

## 2. Key hierarchy

**KEK/DEK split.** The master password derives a Key-Encryption-Key; a
random Data-Encryption-Key encrypts the actual items.

- **Why:** changing the master password re-derives the KEK and re-wraps the
  DEK (one small AEAD operation) instead of re-encrypting every item.
  Also allows future key-rotation or multi-credential unlock without a
  format break.
- The DEK is 256 bits, generated from the OS CSPRNG at vault creation.
- The wrapped DEK is stored in the vault header, encrypted with the
  KEK under AEAD, with the header parameters as associated data (§7).

## 3. Key derivation — Argon2id

| Parameter | Value | Rationale |
|---|---|---|
| Variant | Argon2id | Side-channel-resistant hybrid; the standard choice for password managers |
| Memory | 64 MiB | Meaningful GPU/ASIC cost; low enough to stay snappy on WSL (default WSL2 memory is 50–80% of host RAM, but the *tool* runs fine in 64 MiB) |
| Iterations | tuned to ≥ 1 s wall-clock on a mid-range 2026 CPU, measured at init time; stored in header | KDF params live in the vault header so they can be raised without a format change |
| Parallelism | 1 lane | Simpler constant memory behavior; parallelism buys little at 64 MiB |
| Salt | 16 bytes, random per vault | Precludes precomputation and cross-vault amortization |
| Output | 32 bytes (KEK) | Matches all downstream key sizes |

- Parameter values are **stored in the header** (m, t, p, salt), so future
  upgrades re-derive with new params and re-wrap the DEK — no vault
  re-encryption.
- The `rotate` command raises KDF parameters to current policy.
- A minimum-parameter floor is enforced on read: vaults with params below
  the floor still open (with a warning) but cannot be re-saved without
  upgrading.

## 4. AEAD algorithms

Two authenticated modes, both 256-bit keys, both from RustCrypto:

| Algorithm | Use when |
|---|---|
| **AES-256-GCM** | Default. Hardware-accelerated (AES-NI on x86, crypto extensions on ARM) — effectively free on our platforms. |
| **ChaCha20-Poly1305** | Fallback for platforms without AES acceleration; kept as a tested code path. |

- The algorithm is a **vault-wide property recorded in the header**, not a
  per-invocation choice. Algorithm agility exists for migration, not for
  user preference.
- The AEAD algorithm protecting the wrapped DEK and the one protecting
  items are selected independently, each recorded in the header.

## 5. Nonce strategy — critical section

Per-item encryption, 96-bit nonces.

**Policy: random nonces, with a hard cap on encryptions per key.**

- Each item's encryption draws a fresh random 96-bit nonce from the OS
  CSPRNG.
- The birthday bound for GCM: after 2^32 random nonces under the same key,
  collision probability becomes material (~2^-32 per pair scale). With a
  per-vault DEK and per-item nonces, a vault with 2^32 encryptions under
  one DEK is unreachable by a human-scale tool.
- **Backstop — DEK rotation counter:** the header records a monotonically
  increasing encryption counter. Policy limit: rotate the DEK after
  2^24 encryptions under it (comfortable margin — collision probability at
  2^24 stays below 2^-35). **Rotation is a full re-encryption:** exactly
  one DEK is alive at any time; `rotate` decrypts and re-encrypts every
  item under a fresh DEK, re-wraps it with the KEK, and resets the
  counter. Human-scale vaults (hundreds of items) re-encrypt in
  milliseconds, and the write is atomic per VAULT_FORMAT §8. There is no
  multi-DEK or per-version mechanism — the format has exactly one
  `wrapped_dk` record.
- The wrapped-DEK encryption uses a **fixed all-zero nonce**. This is safe
  because the KEK is unique per master password (salted KDF) and the
  wrapped-DEK operation happens exactly once per KEK — the (key, nonce)
  pair is never reused.

### Why not counters?

Deterministic counter nonces require durable shared state (which write
wins on crash?), which is a corruption bug class we refuse to trade a
theoretical collision bound for. Random nonces + rotation cap give the
same safety with stateless crash behavior.

## 5a. Randomness

All randomness — salt, DEK, item nonces, generated passwords — comes from
the OS CSPRNG via the `getrandom` crate (down to `getrandom(2)` on Linux /
`BCryptGenRandom` on Windows). No userspace PRNG seeding, no
time-seeded anything.

## 6. Key memory hygiene

- `zeroize` on every buffer holding a password, key, or plaintext item;
  custom Drop where needed.
- `secrecy` typed wrappers (`SecretVec<u8>`) — no `Debug`/`Display` for
  secrets by construction.
- Passwords are read into `SecretVec<u8>` and never into `String`.
- One item decrypted at a time; the vault body is never fully materialized
  in plaintext (see VAULT_FORMAT §4 — item-level addressing).
- Best-effort page locking: `VirtualLock` (Windows) / `mlock` (Linux/WSL).
  Small limits and OS refusal are expected; logged, not fatal. Never
  claimed as a guarantee.

## 7. Integrity & authenticity — what the AEAD tag covers

- **Authenticated (per item):** the entire plaintext item (title, username,
  password, notes, metadata) + per-item AAD = vault version + item index.
- **Authenticated (header):** the header MAC covers the full header
  fields: version, salt, KDF params, algorithm IDs, and the wrapped-DEK
  record (the wrapped DEK is itself AEAD-encrypted with the header fields
  as its AAD — so tampering with any parameter fails at unwrap time, not
  at item-decrypt time).
- **Not authenticated:** nothing security-relevant. Unauthenticated data
  is limited to the file magic + version byte, which are parsed
  defensively and only select a parser.

**Tampering behavior (normative):** any authentication failure yields the
same generic error — `vault corrupt or wrong password` — and no partial
plaintext. Error messages must not distinguish tag failure in the header
vs. in an item, so an attacker cannot use failures as an oracle.

## 8. Cryptographic operations (normative list)

| Op | Primitive | Key | Nonce |
|---|---|---|---|
| Derive KEK | Argon2id(m=64MiB, t≥1s, p=1, salt) | — | — |
| Wrap DEK | AES-256-GCM (or ChaCha20-Poly1305) | KEK | zero nonce (§5) |
| Encrypt item | AES-256-GCM (or ChaCha20-Poly1305) | DEK | random 96-bit, per encryption |
| Wrap DEK on rotation | same as wrap | new KEK | zero nonce (safe — fresh KEK) |
| Password generation | OS CSPRNG + rejection sampling | — | — |
| TOTP code generation | HMAC-SHA1/256/512 (RFC 6238), time-steped | TOTP secret (stored in ItemRecord) | counter = floor(unix/period) |

## 9. Password generator (crypto-relevant aspects)

- Uniform sampling over the requested alphabet via rejection sampling —
  no modulo bias.
- Presets and entropy math are specified in ADR-0006; defaults target
  ≥ 100 bits (e.g. 20 chars from a 78-char alphabet ≈ 125 bits).
- Generated passwords exist only in memory (and clipboard) unless the
  caller stores them — `generate` never writes to disk.

## 10. Verification plan

- **Round-trip tests:** every (algorithm, params) combination must
  encrypt → decrypt to identity.
- **TOTP:** RFC 6238 test vectors (the appendix SHA1 vectors at minimum,
  plus SHA256/512 sets) pin the implementation; TOTP secrets round-trip
  through the ItemRecord as any other secret, and time is injected as a
  parameter in tests — never read from the wall clock in a test.
- **Tamper tests:** flip a bit in header, wrapped-DEK ciphertext, item
  ciphertext, and tag — each must fail with the generic error.
- **Cross-algorithm tests:** vault created with AES-GCM migrates to
  ChaCha20-Poly1305 via `rotate`, then round-trips.
- **KDF sanity:** NIST-style official Argon2 test vectors for the chosen
  parameter set (from the PHC winner spec) pin the KDF implementation.
- **Fuzzing:** the vault parser and the decrypt path get dedicated fuzz
  targets (corpus: valid vaults + single-bit mutations).
- **Test vectors in-repo:** a `test-vectors/` directory with a small set
  of golden vaults (empty, one item, many items, pre-rotation, post-
  rotation) so an independent implementation can check compatibility.

## 11. Crate choices & pinning

| Crate | Role |
|---|---|
| `argon2` | Argon2id (RustCrypto) |
| `aes-gcm` | AES-256-GCM |
| `chacha20poly1305` | ChaCha20-Poly1305 |
| `totp-rs` (or `hmac`+`sha1/2/5` hand-rolled to spec) | TOTP generation (RFC 6238) |
| `zeroize` | secret memory hygiene |
| `secrecy` | typed secret wrappers |
| `getrandom` | OS CSPRNG |

- Dependencies pinned with `Cargo.lock` committed; releases built with
  `--locked`.
- `cargo audit` + `cargo deny` in CI on every push.
- **No HTTP/TLS client anywhere in the dependency tree** — the
  no-network claim is checkable from `Cargo.toml` (ADR-0005).

## 12. Open items

1. Exact Argon2 iteration count — measure on dev hardware at
   implementation time, record the measured floor here.
2. ~~Header MAC placement~~ — **resolved:** folded into the wrapped-DEK
   AEAD tag, whose AAD covers the full 117-byte header
   (VAULT_FORMAT §4.3).
