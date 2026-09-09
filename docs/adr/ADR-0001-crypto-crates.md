# ADR-0001: Use the RustCrypto crate family

**Status:** Accepted
**Date:** 2026-09-09

## Context

We need Argon2id, AES-256-GCM, ChaCha20-Poly1305, and OS randomness on
Windows (native) and Linux (WSL2). Candidates:

- **RustCrypto** (`argon2`, `aes-gcm`, `chacha20poly1305`): pure Rust,
  trait-unified AEAD interfaces, formally verified core where available,
  no C toolchain needed on Windows.
- **`ring`**: well-regarded, but opinionated API (no Argon2 support, less
  algorithm flexibility), BoringSSL-derived C/asm build.
- **`sodiumoxide`/libsodium**: excellent primitive defaults but C build,
  and Argon2 is the only KDF — fine, but the binding maintenance has
  historically lagged.
- **OS keychains** (Windows DPAPI / Credential Manager, libsecret): not
  encryption we control, platform-divergent semantics, and DPAPI ties
  decryption to the Windows account — hostile to the WSL side of our
  dual-platform story.

## Decision

RustCrypto crates for all cryptography, plus `zeroize` and `secrecy` for
memory hygiene and `getrandom` for OS randomness.

## Consequences

- One ecosystem, shared traits (`Aead`, `KeyInit`), easy to add the
  second AEAD behind the same interface.
- No C compilation anywhere — `cargo build` just works on Windows and in
  WSL.
- We own algorithm parameter choices (a responsibility `ring` would have
  partly shouldered); mitigated by writing them down in
  [CRYPTO_SPEC.md](../CRYPTO_SPEC.md).
