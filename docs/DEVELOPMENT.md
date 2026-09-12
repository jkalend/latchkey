# Development Guide

**Status:** Current pre-release implementation (`rpass` 0.1.0)
**Platforms:** Windows 10/11 (native), Linux under WSL2 — both are
first-class; CI runs both.

## Setup

```console
$ git clone <repo>
$ cd rust_password_manager
$ cargo build
$ cargo test
```

Rust stable. **MSRV: 1.98**, in `rust-version` in `Cargo.toml` and
enforced by a CI job that builds and tests with the pinned toolchain.
Bumping the floor is a deliberate ADR or a release-notes entry — not a
casually broken doc line (PROPOSAL §5.5's point).

## Repository layout

```
docs/           specs and ADRs — read THREAT_MODEL, CRYPTO_SPEC,
                VAULT_FORMAT before writing code that touches crypto
src/            binary + library
  crypto/       KDF, AEAD wrappers, CSPRNG key/salt generation
  vault/        file format reader/writer, index, items
  gen/          password generator (ADR-0006); embeds the EFF wordlist
  clip/         platform clipboard (Win32 delayed render; PowerShell
                interop on WSL; wl-copy/xclip/xsel on plain Linux)
  cli/          command parsing and dispatch
  tui/          interactive interface
tests/          integration tests over real vault files
test-vectors/   golden vaults (CRYPTO_SPEC §10)
fuzz/           fuzz targets: vault parser, decrypt path
```

## Spec-first rule

The docs are the source of truth. If code and a spec disagree, either
the code is wrong or the spec was wrong — fix whichever, in a commit
that says which. **Crypto-relevant behavior changes require updating
CRYPTO_SPEC.md or VAULT_FORMAT.md in the same PR.**

## Testing expectations

- Unit tests colocated; integration tests in `tests/` operate on real
  vault files (round-trip, tamper cases from CRYPTO_SPEC §10).
- Fuzz targets in `fuzz/` (cargo-fuzz) for the parser and decrypt path;
  corpus seeded from `test-vectors/` plus bit-flipped mutations.
- Platform-sensitive tests (clipboard, file locking) are
  `#[cfg(windows)]` / `#[cfg(unix)]` gated and run in CI on both
  runners.

## CI checks

1. `cargo fmt --check`, `cargo clippy -- -D warnings`
2. `cargo test` (both platforms) with **MSRV pinned toolchain** —
   `rust-version` in `Cargo.toml` is the source of truth; CI refuses
   pushes that require a newer Rust
3. `cargo audit` and `cargo deny` (advisories, licenses, and the
   ADR-0005 network-ban rules)
4. Network-ban grep over `src/` (ADR-0005 §2)

## Release checklist

Pushing a `v*` tag runs `.github/workflows/release.yml`, builds locked
Windows and Linux artifacts, writes `SHA256SUMS`, and publishes a GitHub
release with generated notes.

- [ ] `Cargo.lock` committed; build with `--locked`
- [ ] `cargo check --target x86_64-unknown-linux-gnu` passes — the
      `cfg(not(windows))` tree (clipboard backends, platform probe) must
      compile even though day-to-day dev is on Windows; CI's ubuntu job
      gates this, catching it pre-push is cheaper
- [ ] `cargo audit` clean
- [ ] Test vectors regenerated and cross-checked against a second
      implementation of the format (even a quick Python reader) —
      VAULT_FORMAT's "independently implementable" bar
- [ ] Update the measured Argon2 baseline in CRYPTO_SPEC §3 if hardware
      assumptions changed
- [ ] GitHub private vulnerability reporting enabled on the repository
      (SECURITY.md's reporting path depends on it)
- [ ] `Cargo.toml` version matches the tag; review generated release notes
