# rust_password_manager

A local-first password manager for **Windows 10/11 (native)** and
**Linux under WSL2**. No accounts, no servers, no network calls — your
vault is a single encrypted file on your own disk.

> [!WARNING]
> **This is unaudited hobby software.** Do not store real credentials in it
> until it has been externally reviewed. It is a portfolio project
> exploring practical applied cryptography in Rust. See
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for exactly what it does
> and does not defend against.

## Features

- 🔒 **Encrypted vault** — a single file, protected with Argon2id key
  derivation and authenticated encryption (AES-256-GCM default,
  ChaCha20-Poly1305 fallback).
- 🖥️ **CLI and TUI** — scriptable commands and an interactive fuzzy-search
  interface over the same vault. Bare `rpass` opens the TUI.
- 📋 **Clipboard with auto-clear** — secrets copy to the clipboard and
  clear themselves after 30 seconds; on native Windows the pre-copy
  clipboard contents are restored rather than left empty (delayed
  rendering is tracked for v1.x — see
  [docs/adr/ADR-0003-clipboard-strategy.md](docs/adr/ADR-0003-clipboard-strategy.md)).
- 🎲 **Password generation** — cryptographically secure, rejection-sampled
  from the OS CSPRNG, entropy-documented presets.
- ⏱️ **TOTP authenticator** — store TOTP secrets alongside credentials
  and generate codes locally (RFC 6238; `otpauth://` URIs accepted on
  add/edit).
- 🔁 **Key rotation & master-password change** — re-key the DEK under
  current-policy KDF parameters, or change the master password, without
  re-encrypting item contents you haven't opened.
- 🚫 **Zero network** — no HTTP client exists in the dependency tree at
  all, so the no-phoning-home guarantee is checkable, not a promise
  (CI-enforced).

## Quick start

```console
$ # create a vault (prompts for a master password)
$ rpass init

$ # add a credential
$ rpass add github.com --username me@example.com

$ # list what's in the vault (titles + usernames — no secrets)
$ rpass list

$ # copy a secret to the clipboard, auto-clears in 30s
$ rpass copy github.com

$ # generate a strong password without storing it
$ rpass generate --length 20

$ # back up the encrypted vault (just a file copy — restore is copying it back)
$ rpass backup --out /mnt/c/Backups/vault-backup.bin
```

## Command status

| Command | Status |
|---|---|
| `rpass init` | ✅ implemented |
| `rpass add <title>` | ✅ implemented — `--username --url --notes --generate --totp --totp-uri` |
| `rpass list` | ✅ implemented |
| `rpass get <title>` | ✅ implemented — `--reveal` to print, `--copy`, `--id` |
| `rpass copy <title>` | ✅ implemented — `--timeout`, auto-clear |
| `rpass generate` | ✅ implemented — ADR-0006 presets, `--copy` |
| `rpass totp <title>` | ✅ implemented — `--copy` |
| `rpass edit <title>` | ✅ implemented — single atomic write for index + secrets |
| `rpass rm <title>` | ✅ implemented — `--purge` skips confirm |
| `rpass rotate` | ✅ implemented — DEK + KDF policy; `--new-password` |
| `rpass export` | ✅ implemented — `--format json --yes-i-mean-it --out <file>` |
| `rpass backup` | ✅ implemented — `--out` |
| `rpass tui` (or bare `rpass`) | ✅ implemented — fuzzy search, detail view, idle lock |
| `rpass import` | ✅ implemented — `--format json <file>`, preview + confirm, `--dry-run`, `--yes` |

Full contract per command: [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md).

## Building

Rust 1.98+ (stable, MSRV CI-enforced — DEVELOPMENT.md). From the repo root:

```console
$ cargo build --release
```

**Platform notes**

| Platform | Notes |
|---|---|
| Windows | Works natively; synchronous set-and-hold clipboard (delayed rendering tracked for v1.x, ADR-0003). Warns if Windows Clipboard History is enabled, since it defeats auto-clear. |
| Linux (WSL2) | Clipboard goes through `clip.exe` stdin; secret never appears in process listings or interop logs. Auto-clear works while `rpass copy` lives; process death strands the secret (mitigation: run natively on Windows, or `echo. \| clip.exe`). See ADR-0008 for detection details. |
| Plain Linux | **Best-effort** — clipboard via `wl-copy` (Wayland) or `xclip`/`xsel` (X11), probed at runtime. Auto-clear parity: X11's selection model clears the clipboard when the process exits; Wayland clears on timeout. Not a supported platform in the strict sense; X11/Wayland behavior is engineered but not release-tested. |
| macOS | Out of scope for v1. |

## Vault location

| Platform | Path |
|---|---|
| Windows | `%LOCALAPPDATA%\rpass\vault.bin` |
| Linux/WSL | `${XDG_STATE_HOME:-$HOME/.local/state}/rpass/vault.bin` |

## Security documentation

Before trusting this tool with anything, read:

- [Threat model](docs/THREAT_MODEL.md) — assets, adversaries, explicit
  non-goals (what this tool *cannot* protect you from).
- [Cryptography spec](docs/CRYPTO_SPEC.md) — key hierarchy, Argon2
  parameters, nonce strategy, tamper behavior.
- [Vault format](docs/VAULT_FORMAT.md) — byte-level file format, written
  to be independently implementable.

## Comparison

| | rpass | Bitwarden | KeePassXC | `pass` |
|---|---|---|---|---|
| Local-first, single file | ✅ | ❌ (cloud) | ✅ | ✅ (git) |
| No accounts | ✅ | ❌ | ✅ | ✅ |
| No network code at all | ✅ | ❌ | ✅ | ✅ |
| Rust | ✅ | ❌ | ❌ | ❌ |
| TOTP authenticator | ✅ | ✅ | ✅ | plugin |
| Browser integration | ❌ | ✅ | ✅ | plugin |
| Audited | ❌ | ✅ | ✅ | ✅ |

Positioning: this is not trying to replace your password manager. It's a
from-scratch, spec-first implementation of one, with the security
decisions written down before the code.

## License

TBD
