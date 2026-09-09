# Security Policy

## Supported versions

Only the latest release line receives security fixes. This project has
not yet made a stable release — until a `v1.0` tag exists, only the
`main` branch is supported.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Use [GitHub's private vulnerability
reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository — the **"Report a vulnerability"** button on the
Security tab. Reports come to the maintainers privately, and GitHub
manages advisory drafting and coordinated disclosure for us.

Include what you found, reproduction steps, and impact assessment. You
will get an acknowledgment within 72 hours. Please avoid automated
scanners' noise (dependency CVEs are tracked via `cargo audit` in CI
already — check existing advisories first).

## Disclosure expectations

- Coordinated disclosure: we'll work with you on a fix and timeline,
  credit you in the release notes if you wish.
- Safe harbor: good-faith research on your own vaults and local builds
  is welcomed. No charges sought for research that respects user
  privacy.

## Honest status

This software is **unaudited hobby software**. It has not undergone a
third-party security review. The cryptography is built on audited
RustCrypto primitives, but the construction around them — key
hierarchy, nonce handling, file format — is specified in
[docs/CRYPTO_SPEC.md](docs/CRYPTO_SPEC.md) precisely so it can be
publicly scrutinized. Findings from that scrutiny are exactly what the
process above is for.

Do not store real credentials in this tool until it has been reviewed.
