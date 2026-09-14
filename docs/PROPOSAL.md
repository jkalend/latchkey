# rust_password_manager — Documentation Proposal

**Status:** Historical — initial documentation plan (completed)
**Date:** 2026-09-09
**Current release proposal:** [NEXT_RELEASE.md](NEXT_RELEASE.md)
**Platforms:** Windows 10/11 (native) and Linux under WSL2. macOS is out of scope for v1.

---

## 1. Purpose

This document proposes the documentation structure for the project before implementation
begins. For a security-sensitive tool, documentation is not an afterthought: the threat
model, cryptography choices, and data format must be written down and reviewable
*before* code is written against them. The docs below are ordered roughly in the
sequence they should be authored.

## 2. Proposed document set

| # | Document | Path | Audience | Priority |
|---|----------|------|----------|----------|
| 1 | README | `README.md` | End users, recruiters | P0 |
| 2 | Threat Model | `docs/THREAT_MODEL.md` | Security reviewers, contributors | P0 |
| 3 | Cryptography Specification | `docs/CRYPTO_SPEC.md` | Security reviewers | P0 |
| 4 | Vault File Format | `docs/VAULT_FORMAT.md` | Implementers, future compatibility | P1 |
| 5 | CLI Reference | `docs/CLI_REFERENCE.md` | End users | P1 |
| 6 | TUI Guide | `docs/TUI_GUIDE.md` | End users | P2 |
| 7 | Design Decisions / ADRs | `docs/adr/` | Contributors | P1 |
| 8 | Contributing & Security Policy | `CONTRIBUTING.md`, `SECURITY.md` | Contributors, reporters | P1 |
| 9 | Development Guide | `docs/DEVELOPMENT.md` | Contributors | P2 |

## 3. Document outlines

### 3.1 README.md (P0)

- One-paragraph pitch: local-first, zero-knowledge, no network calls.
- Feature list: encrypted vault, CLI + TUI, clipboard auto-clear timeout,
  password generation, Argon2 KDF, AES-GCM / ChaCha20-Poly1305.
- **Honest scope statement** — explicitly answer: *should you trust this with real
  passwords?* Recommended wording: a "Not audited" banner until an external review
  exists. This is a portfolio project; overclaiming security readiness is the
  fastest way to lose credibility with security-literate readers.
- Install / build instructions (`cargo install`, platform notes for clipboard crates).
- Quick-start walkthrough (init → add → copy → generate).
- Comparison table vs. Bitwarden/KeePassXC/`pass` (positioning, not marketing).
- Screenshot or asciinema of the TUI.

### 3.2 docs/THREAT_MODEL.md (P0)

The most important document in the set. Proposed structure, adapted from STRIDE
plus the standard password-manager threat-model questions:

- **Assets:** master password, vault contents, derived keys in memory.
- **Adversaries:** device thief (locked vs. unlocked machine), local malware,
  shoulder-surfers, backups/sync-tool leakage, *ourselves* (accidental
  network exfiltration).
- **Explicit non-goals:** no protection against a compromised OS, no protection
  while the vault is unlocked, no keylogger resistance, no protection against
  the user pasting secrets into a phishing site.
- **Attack surface inventory:** vault file on disk, clipboard (the classic
  weak point — clipboard managers, X11/Wayland differences, Windows clipboard
  history), process memory, swap/pagefile, crash dumps, temp files.
- **Trust boundaries diagram** (ASCII or Mermaid).
- Per-threat mitigation table: threat → mitigation → residual risk.

### 3.3 docs/CRYPTO_SPEC.md (P0)

Written to be reviewable without reading the code. Proposed sections:

1. **Overview diagram** — master password → Argon2id → file key → AEAD.
2. **Key derivation:** Argon2id parameters (m, t, p), how they're stored in the
   vault header (so they can be upgraded later), rationale for chosen values,
   and the target hash-cracking cost. Note which Argon2 *variant* — Argon2id is
   the standard choice for password managers today.
3. **Encryption:** AEAD choice and the policy for the two algorithms:
   - AES-256-GCM (hardware-accelerated on x86 AES-NI, ARMv8 crypto extensions)
   - ChaCha20-Poly1305 (constant-time in software, better on platforms
     without AES acceleration)
   - Document which is default, how the choice is recorded per-vault, and
     that algorithm agility exists for *migration*, not user choice.
4. **Nonce strategy:** critical section. Random 96-bit nonces with
   AES-GCM have a collision ceiling (~2^32 messages before birthday risk
   becomes meaningful). For a password manager with per-item encryption this
   must be addressed — either a counter-based scheme, or an argument that the
   volume bounds make random nonces safe. This is exactly the kind of detail
   that separates a serious implementation from a demo.
5. **Key hierarchy:** is the master password-derived key used directly, or is
   there an intermediate key (allowing master password change without
   re-encrypting the vault)? Proposed: KEK/DEK split.
6. **Key memory hygiene:** `zeroize` for secrets, ` secrecy` crate for typed
   secret wrappers, no `String` for passwords, no `Debug` derive leaks,
   `mlock`/`sodium_mlock` feasibility on each platform (with honest caveats —
   it is best-effort on Windows).
7. **Integrity & authenticity:** what AEAD tags protect, and what they don't
   (e.g., the unauthenticated header — Argon2 params, algorithm IDs — needs a
   coverage decision: ignore vs. include-in-AAD).
8. **Test vectors & property tests:** how correctness is verified
   (round-trips, tamper detection, tampered-header behavior).
9. **Crates used and why** (`argon2`, `aes-gcm`, `chacha20poly1305`, RustCrypto
   ecosystem) with pinning policy.

### 3.4 docs/VAULT_FORMAT.md (P1)

A byte-level specification so the format could be reimplemented independently:

- Header magic + version, KDF params, algorithm IDs, salt.
- Envelope layout (diagram, offsets, endianness).
- Item encoding (serialization format — recommend a compact explicit format or
  serde with documented schema, not raw `bincode` output which is
  Rust-implementation-defined).
- Versioning & migration policy: forward-compatibility rules, what v1→v2
  upgrades must look like, and a commitment that old vaults remain readable.
- Rationale for monolithic vs. per-item encryption. Recommendation: per-item
  encryption — it enables item-level nonces, partial decryption for TUI
  listings, and safer concurrent writes.

### 3.5 docs/CLI_REFERENCE.md (P1)

- Command tree: `init`, `add`, `list`, `get`, `copy`, `generate`, `edit`,
  `rm`, `export`, `import`, `rotate`, `lock`.
- Exit codes (scriptability is a differentiator for CLI password managers).
- Environment variables and config file.
- `--help` output embedded verbatim for each command.
- Shell completion generation.

### 3.6 docs/TUI_GUIDE.md (P2)

- Keybindings table, theming, fuzzy search, clipboard-clear countdown UI.

### 3.7 docs/adr/ — Architecture Decision Records (P1)

Short numbered records. Seed list:

- `ADR-0001`: RustCrypto vs. `ring`/`sodiumoxide` vs. OS keychains.
- `ADR-0002`: Vault file location and OS conventions
  (`%LOCALAPPDATA%` on Windows, XDG state dir on Linux/WSL).
- `ADR-0003`: Clipboard strategy per platform and the auto-clear timeout
  (recommend 10–20 s default; document that clipboard managers can defeat it).
- `ADR-0004`: Single vault file vs. directory of items.
- `ADR-0005`: No-network guarantee — how it's enforced and communicated
  (e.g., no HTTP client dependency at all, so the guarantee is
  checkable from `Cargo.toml`).
- `ADR-0006`: Password generator alphabet/entropy options and defaults.

### 3.8 SECURITY.md (P1)

- Supported versions, how to report vulnerabilities (private disclosure),
  expectations (this is unaudited hobby software — say so), and safe-harbor
  language for researchers.

### 3.9 docs/DEVELOPMENT.md (P2)

- Dev setup, `cargo test` layout, how to add fuzz targets for the parser/
  decryption path, release checklist (reproducible builds, `--locked`,
  dependency audit via `cargo audit` / `cargo deny`).

## 4. Suggested authoring order

1. **Threat Model** — everything else is downstream of it.
2. **Crypto Spec** — forces the nonce and key-hierarchy decisions early.
3. **Vault Format** — locks the on-disk contract before code exists.
4. README (can be written in parallel; refine after the above stabilize).
5. ADRs as decisions come up during implementation; CLI reference once the
   command surface stabilizes.

## 5. Open questions — resolution status

1. ~~TOTP in v1?~~ — **Yes**, included in v1 (VAULT_FORMAT §6.2,
   CRYPTO_SPEC §8, THREAT_MODEL §5.8a).
2. Unlock model: **per-process for v1** (THREAT_MODEL §7); an agent
   daemon is a post-v1 candidate ADR.
3. Sync: **bring-your-own** — the format is designed to be safe as an
   opaque file under naive sync (atomic writes, VAULT_FORMAT §8).
4. ~~Import from other managers?~~ — **Post-v1** at the time of writing
   (superseded: Bitwarden/KeePassXC import shipped in 0.2.0 —
   NEXT_RELEASE §4.3; JSON self-export/import is in the CLI reference).
5. ~~MSRV~~ — **Resolved: 1.98**, enforced via `rust-version` in
   `Cargo.toml` + a pinned-toolchain CI job (DEVELOPMENT.md).

## 6. What success looks like

A security engineer reading only `THREAT_MODEL.md` + `CRYPTO_SPEC.md` +
`VAULT_FORMAT.md` could implement a compatible reader/writer and would not
find any unspecified security-relevant behavior. That is the bar.
