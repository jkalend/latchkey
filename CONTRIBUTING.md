# Contributing

Thanks for considering it. This project is spec-first: the documents in
`docs/` describe intended behavior before code exists, and they remain
the source of truth after it does.

## Before you start

Read, in order:

1. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — especially §4
   (explicit non-goals) so you know what the project does not claim.
2. [docs/CRYPTO_SPEC.md](docs/CRYPTO_SPEC.md) and
   [docs/VAULT_FORMAT.md](docs/VAULT_FORMAT.md) — the crypto and
   on-disk contracts.
3. [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — setup, layout, CI.

## Ground rules

- **Spec-first:** crypto- or format-relevant changes update the relevant
  spec in the same PR. Code/spec disagreement is a bug in one of them.
- **No secrets in CLI arguments, logs, or debug output** — ever
  (THREAT_MODEL §5.6–5.7). This is enforced in review, not just by
  convention.
- **No network dependencies** (ADR-0005) — CI will reject them; don't
  fight the CI on this.
- **ADRs for decisions, not PR descriptions.** Anything that changes the
  threat model, crypto, or format gets a numbered ADR under `docs/adr/`.
- Platform parity: features must work on Windows (native) and Linux
  (WSL2). Platform-specific code is fine; platform-specific *features*
  need an ADR explaining why.

## Process

1. Open an issue describing the change (or claim an existing one).
2. Small PRs against `main`; conventional commits.
3. CI must pass: fmt, clippy, tests on both platforms, `cargo audit` /
   `cargo deny`, network-ban grep.
4. Crypto-relevant PRs get extra review time by design. Slow is fine.

## Security issues

See [SECURITY.md](SECURITY.md) — do **not** open public issues for
security problems.
