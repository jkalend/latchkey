# Latchkey

A local-first password manager for **Windows 10/11 (native)** and
**Linux under WSL2**. No accounts, no servers, no network calls — your
vault is a single encrypted file on your own disk.

> [!WARNING]
> **This is unaudited hobby software.** Do not store real credentials in it
> until it has been externally reviewed. It is a portfolio project
> exploring practical applied cryptography in Rust. See
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for exactly what it does
> and does not defend against.

## Project status

The package is `0.2.0`, the first public-preview release candidate. The vault
format and native export schema remain version 1; package, vault, and export
versions are tracked independently.

## Features

- 🔒 **Encrypted vault** — a single file, protected with Argon2id key
  derivation and authenticated encryption (AES-256-GCM default,
  ChaCha20-Poly1305 fallback).
- 🖥️ **CLI and TUI** — scriptable commands and an interactive fuzzy-search
  interface over the same vault. Bare `latchkey` opens the TUI.
- 📋 **Clipboard with auto-clear** — secrets copy to the clipboard and
  clear themselves after 30 seconds. On native Windows the copy uses
  **delayed rendering**: the secret is only handed to a paste target on
  request (process death *before the first paste* clears the entry
  automatically). After the timeout, the pre-copy clipboard contents are
  restored — but only if the clipboard still holds our value, so anything
  you copied in the meantime is never clobbered. Ctrl-C (native Windows)
  clears and exits
  ([docs/adr/ADR-0003-clipboard-strategy.md](docs/adr/ADR-0003-clipboard-strategy.md)).
- 🎲 **Password generation** — cryptographically secure, rejection-sampled
  from the OS CSPRNG, entropy-documented presets.
- ⏱️ **TOTP authenticator** — store TOTP secrets alongside credentials
  and generate codes locally (RFC 6238; `otpauth://` URIs accepted on
  add/edit).
- 🔁 **Key rotation & master-password change** — change the master
  password without re-encrypting any item, or rotate to a fresh DEK
  under current-policy KDF parameters (which re-encrypts the vault
  atomically).
- 🚫 **Zero network** — no HTTP client exists in the dependency tree at
  all, so the no-phoning-home guarantee is checkable, not a promise
  (CI-enforced).

## Quick start

```console
$ # create a vault (prompts for a master password)
$ latchkey init

$ # add a credential
$ latchkey add github.com --username me@example.com

$ # list what's in the vault (titles + usernames — no secrets)
$ latchkey list

$ # copy a secret to the clipboard, auto-clears in 30s
$ latchkey copy github.com

$ # generate a strong password without storing it
$ latchkey generate --length 20

$ # back up the encrypted vault (just a file copy — restore is copying it back)
$ latchkey backup --out /mnt/c/Backups/vault-backup.bin
```

## Command status

| Command | Status |
|---|---|
| `latchkey init` | ✅ implemented |
| `latchkey add <title>` | ✅ implemented — `--username --url --notes --generate --totp --totp-uri` |
| `latchkey list` | ✅ implemented |
| `latchkey get <title>` | ✅ implemented — `--reveal` to print, `--copy`, `--id` |
| `latchkey copy <title>` | ✅ implemented — `--timeout`, auto-clear |
| `latchkey generate` | ✅ implemented — ADR-0006 presets, `--copy` |
| `latchkey totp <title>` | ✅ implemented — `--copy` |
| `latchkey edit <title>` | ✅ implemented — single atomic write for index + secrets |
| `latchkey rm <title>` | ✅ implemented — `--purge` skips confirm |
| `latchkey rotate` | ✅ implemented — DEK + KDF policy; `--new-password` |
| `latchkey export` | ✅ implemented — `--format json --yes-i-mean-it --out <file>` |
| `latchkey backup` | ✅ implemented — `--out` |
| `latchkey check` | ✅ implemented — authenticates every vault record without writing |
| `latchkey tui` (or bare `latchkey`) | ✅ implemented — search, add/edit/delete, detail view, idle lock |
| `latchkey import` | ✅ implemented — native JSON, Bitwarden JSON, KeePassXC CSV; preview + confirm |
| `latchkey completions <shell>` | ✅ implemented — Bash, Zsh, Fish, PowerShell |

Full contract per command: [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md).

## Installation

From crates.io (once the crate is published):

```console
$ cargo install --locked latchkey --version 0.2.0
```

Or download the archive for your platform from the repository's GitHub
Releases page:

- Windows: `latchkey-v0.2.0-x86_64-pc-windows-msvc.zip`
- Linux/WSL2: `latchkey-v0.2.0-x86_64-unknown-linux-gnu.tar.gz`

Download `SHA256SUMS` from the same release and verify the archive before
unpacking (`sha256sum -c SHA256SUMS` on Linux/WSL2, or compare
`Get-FileHash -Algorithm SHA256 <archive>` on Windows). Each archive contains
only the binary, README, and MIT/Apache-2.0 license files. Put `latchkey` or
`latchkey.exe` on `PATH`, then run `latchkey --version`.

Generate completions for the active shell with
`latchkey completions <bash|zsh|fish|powershell>`.

## Building

Rust 1.98+ (stable, MSRV CI-enforced — DEVELOPMENT.md). From the repo root:

```console
$ cargo build --release
```

**Platform notes**

| Platform | Notes |
|---|---|
| Windows | Works natively; clipboard uses Win32 delayed rendering (the secret is served on WM_RENDERFORMAT, so process death *before the first paste* clears it automatically). After the timeout the pre-copy clipboard is restored — only if the clipboard still holds our value (interim copies are left alone). Ctrl-C clears and exits. Warns if Windows Clipboard History is enabled, since it defeats auto-clear. |
| Linux (WSL2) | Clipboard goes through PowerShell `Set-Clipboard` with the secret piped as UTF-16-in-base64 over stdin — Unicode-exact and never visible in process listings. Auto-clear restores prior text only if the clipboard still holds our value. Interrupting latchkey mid-hold leaves the clipboard set until the next copy; prefer a shorter `--timeout` if that concerns you. |
| Plain Linux | **Best-effort** — clipboard via `wl-copy` (Wayland) or `xclip`/`xsel` (X11), probed at runtime. Auto-clear overwrites the selection after the timeout, again only if it still holds our value. If latchkey dies before the timeout, the helper tool keeps serving the secret until the next copy — clearing requires latchkey to stay alive. Not a supported platform in the strict sense; X11/Wayland behavior is engineered but not release-tested. |
| macOS | Out of scope for v1. |

## Vault location

| Platform | Path |
|---|---|
| Windows | `%LOCALAPPDATA%\latchkey\vault.bin` |
| Linux/WSL | `${XDG_STATE_HOME:-$HOME/.local/state}/latchkey/vault.bin` |

## Security documentation

Before trusting this tool with anything, read:

- [Threat model](docs/THREAT_MODEL.md) — assets, adversaries, explicit
  non-goals (what this tool *cannot* protect you from).
- [Cryptography spec](docs/CRYPTO_SPEC.md) — key hierarchy, Argon2
  parameters, nonce strategy, tamper behavior.
- [Vault format](docs/VAULT_FORMAT.md) — byte-level file format, written
  to be independently implementable.

## Comparison

| | latchkey | Bitwarden | KeePassXC | `pass` |
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

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option (matching `Cargo.toml`'s `license = "MIT OR Apache-2.0"`).
