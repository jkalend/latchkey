# Threat Model

**Status:** Draft v0.1 — pre-implementation
**Covers:** rust_password_manager v1
**Platforms:** Windows 10/11 (native), Linux under WSL2

---

## 1. System description

A local-first password manager. All sensitive state lives in a single
encrypted vault file on the local filesystem. The tool never makes network
connections. The user unlocks the vault with a master password, which is run
through Argon2id to derive an encryption key.

```
┌─────────────┐   master password (typed)
│   Human     │──────────────┐
└─────────────┘              ▼
                   ┌──────────────────┐
                   │  Argon2id (KDF)  │
                   └────────┬─────────┘
                            ▼ KEK
                   ┌──────────────────┐        ┌──────────────┐
                   │  unwrap DEK      │◀──────▶│  vault file  │
                   └────────┬─────────┘        │ (on disk)    │
                            ▼ DEK               └──────────────┘
                   ┌──────────────────┐
                   │  AEAD decrypt    │──▶ plaintext item ──▶ clipboard
                   └──────────────────┘
```

Trust boundaries:

1. **User → process** — master password input (terminal, TTY-raw).
2. **Process ↔ disk** — the vault file and any temp files.
3. **Process → clipboard** — secrets copied for pasting.
4. **Process ↔ OS** — memory, swap, crash dumps, environment.

Everything inside the process is trusted while the vault is unlocked; the
boundaries above are where threats live.

## 2. Assets

| Asset | Where | Damage if leaked |
|---|---|---|
| Master password | Terminal input, process memory | Total — unlocks the vault |
| Derived keys (KEK/DEK) | Process memory | Total |
| Vault plaintext | Process memory during unlock | Total |
| Individual secrets | Process memory, clipboard | Per-account compromise |
| Vault file | Disk (and any backups/sync copies) | Safe while KDF holds |
| Metadata (item titles, usernames, timestamps) | Vault file — see §5.4 | Partial — reveals accounts |

## 3. Adversaries

1. **Device thief, machine locked/off.** Vault file on disk; KDF is the only
   defense. Realistic and primary.
2. **Device thief, machine unlocked.** Out of scope (§4) — but clipboard
   contents and memory-resident secrets are exposed moments, so we minimize
   their lifetime.
3. **Local malware / infostealer.** Out of scope while running as the user
   (§4), but the vault file must not be trivially crackable offline —
   Argon2id parameters target this (CRYPTO_SPEC §3).
4. **Shoulder-surfer.** Mitigated: never echo secrets to the terminal by
   default; TUI masks them; `get` prints to clipboard or with a
   `--reveal` flag only.
5. **Naive backup/sync tooling.** The user may place the vault in a synced
   or backed-up folder. The vault file must be safe to leak *as a file*
   (it is — AEAD-encrypted), and concurrent-write corruption must be
   prevented (atomic replace, §6.4).
6. **Ourselves.** Accidental plaintext-to-disk (logs, temp files, debug
   prints) is the most likely real-world failure. Mitigations in §6.5.

## 4. Explicit non-goals

These are **not defended against**, stated plainly so nobody relies on them:

- A compromised OS, keyloggers, or info-stealer malware running as the user.
- An unlocked, unattended machine.
- Cold-boot / DMA attacks.
- Side channels on the crypto (timing, power).
- Phishing — the user pasting a secret into the wrong site.
- Multi-user/multi-process isolation on the same account: any process the
  user runs can read the vault file and attempt offline guessing. We raise
  the cost of that (strong KDF), we do not prevent it.
- Malicious/compromised dependencies — mitigated only in the usual
  ecosystem sense (pinned, audited deps), not cryptographically.

## 5. Threat inventory

### 5.1 Offline attack on a stolen vault file — **primary threat**

- **Threat:** attacker obtains `vault.bin` (theft, backup leak, sync
  provider breach, cloud folder).
- **Mitigation:** Argon2id with parameters chosen for ≥ ~1s on a modern
  CPU (CRYPTO_SPEC §3); random 128-bit salt per vault so no precomputation
  or cross-vault amortization is possible.
- **Residual risk:** a weak master password falls to brute force. Document
  minimum-entropy guidance; enforce length and run a basic common-password
  check against a small embedded deny-list (not a network API).
- **Priority:** P0 for the KDF parameter decision.

### 5.2 Clipboard leakage

- **Threat:** secrets copied to the clipboard persist after paste; clipboard
  history features capture them.
- **Windows specifics:** Clipboard History (Win+V) and cloud clipboard sync
  capture *anything* copied, including from WSL via `clip.exe` interop.
  This is enabled by default on some setups. Auto-clear after timeout does
  **not** remove entries already captured by history.
- **WSL specifics:** there is no native Linux clipboard under WSL2 without
  WSLg/an X server. Copying means shelling out to `clip.exe` (or
  `powershell.exe Set-Clipboard`), which puts plaintext on the Windows side
  and into a process argument observed by WSL interop logging.
- **Mitigations:**
  - Auto-clear timeout (default **30 s**, CLI-configurable) restores
    the pre-copy clipboard content where the platform API allows, else
    clears.
  - **Native Windows: delayed rendering** (`SetClipboardData` with NULL)
    — the clipboard holds only a promise to render. Two consequences: the
    secret isn't a static clipboard value while the timer runs (a paste
    target pulls it on demand), and **process death clears the entry
    automatically** — a dead process can't render, so the OS treats the
    clipboard as empty. Terminal close, kill, or sleep does not strand
    the secret.
  - **WSL: hard copy via `clip.exe`** — delayed rendering is not
    available across the WSL boundary. If the `rpass copy` process dies
    on WSL before the timeout fires, the secret stays in the clipboard
    until the 30 s auto-clear fires — bounded by design, not an
    unbounded leak as the 15 s-default version of this risk was.
    Accepted and documented; the mitigation advice is to run rpass
    natively on Windows or manually clear (`echo. | clip.exe`).
  - **Plain Linux: best-effort.** Detected by the absence of WSL env
    vars (ADR-0008), then clipboard via `wl-copy` (Wayland) or
    `xclip`/`xsel` (X11), probed at runtime. Auto-clear parity:
    the X11 selection model means process-exit clears the clipboard
    — *better* than Windows native, not a regression; Wayland's
    clear-blank-on-timeout also applies. If no Linux clipboard tool is
    found, `copy`/`totp --copy` fails with a clear error. Linux
    clipboard parity is documented in the README; we do not claim it as
    a supported platform.
  - Print a warning at copy time if Windows Clipboard History appears
    enabled (detectable via registry
    `HKCU\Software\Microsoft\Clipboard` — probe only, never write).
  - WSL copy goes through `clip.exe` stdin (never a command-line argument),
    so the secret does not appear in process listings or WSL interop logs.
  - Document, don't hide: the TUI guide tells users Clipboard History
    defeats auto-clear and how to exclude the app or disable history.
- **Residual risk:** Clipboard History users; WSL users whose process
  dies mid-timeout; plain-Linux users with no installed clipboard tool
  (failure is loud, not silent). Accepted and documented.

### 5.3 Memory exposure

- **Threat:** secrets in process memory leak via swap, crash dumps,
  hibernation files, or `/proc/<pid>/mem` access by same-user processes.
- **Mitigations:**
  - Zeroize all key and plaintext buffers on drop (`zeroize` crate); typed
    secret wrappers (`secrecy`) so no accidental `Debug`/`Display` leaks.
  - Decrypt one item at a time; never hold the whole vault plaintext.
  - Windows: attempt to opt out of crash reporting for the process;
    best-effort.
  - `mlock` equivalent: best-effort (`VirtualLock` on Windows, `mlock` on
    Linux) with honest caveats — limits are small and the OS may refuse.
    Not a guarantee; documented as such.
- **WSL-specific:**
  - Linux swap under WSL2 lives in a swap file the Windows host controls
    (`%USERPROFILE%\AppData\Local\Temp\swap.vhdx` on the Windows side —
    disk-resident).
  - **Hibernation / Windows Fast Startup writes full RAM (including the
    WSL2 VM's) to `hiberfil.sys`.** Out of our control; documented.
  - `/proc/<pid>/mem` readable by same-user processes inside the distro —
    covered by the same-user malware non-goal.
- **Residual risk:** high against a funded local attacker; acceptable for
  the threat model's target user.

### 5.4 Metadata leakage

- **Threat:** the vault file's unencrypted header reveals item count, and —
  if item titles/usernames are only body-encrypted but length-ordered — an
  observer of the *file* learns little, but an observer of *synchronized
  copies over time* could correlate sizes/counts.
- **Mitigation:** header contains only crypto parameters, salt, and a
  MAC. Item count and all item metadata are inside the encrypted body.
  Per-item ciphertext lengths leak plaintext length bounds — accepted,
  standard (same as TLS records).
- **Residual:** length-based correlation against sync history. Accepted.

### 5.5 Vault file corruption / torn writes

- **Threat:** crash mid-write, or two invocations writing concurrently
  (including a Windows-side process touching the file via `\\wsl$`).
- **Mitigation:** write-to-temp + fsync + atomic rename; a lock is
  *advisory only* (fcntl on Linux; on Windows, opened with share modes
  that conflict — noting the WSL boundary means the Windows side can still
  bypass it). AEAD tags make silent corruption detectable — a torn write
  fails authentication rather than yielding garbage plaintext.
- **Residual:** last-write-wins between concurrent invocations (no merge);
  documented, single-user tool.

### 5.6 Accidental plaintext on disk

- **Threat:** logs, debug output, temp files containing secrets.
- **Mitigation:** no logging of secret values anywhere (structured log
  fields are typed and secrets never enter them); temp file for atomic
  writes contains only ciphertext; deny-by-default approach to printing
  secrets in CLI output.

### 5.7 Command-line leakage

- **Threat:** secrets passed as CLI arguments appear in shell history and
  `ps` output (both platforms).
- **Mitigation:** never accept secrets as arguments. Interactive prompt or
  `--from-stdin` only. The password *generator* takes only length/charset
  flags — safe. Note: on WSL, Windows-side process monitoring can see
  WSL process args; same rule applies.

### 5.8a TOTP secret handling (v1 scope)

- **Threat:** the TOTP shared secret is a full second-factor bypass —
  possession of it defeats the 2FA entirely.
- **Mitigations:** stored inside the ItemRecord, same AEAD and
  memory-hygiene rules as passwords (`secrecy`/`zeroize`, never in CLI
  args, never logged). The `otpauth://` URI paste path zeroizes the URI
  after parsing. Codes generated on demand and printed/copied only with
  the same reveal discipline as passwords.
- **Clipboard nuance:** a 6-digit code is short-lived (30 s window), so
  the ADR-0003 15 s auto-clear is more than sufficient — the code is
  typically expired by the time the clipboard clears. Residual risk:
  negligible.
- **Clock:** TOTP validity depends on local clock accuracy; skewed
  clocks generate rejected codes (an availability nuisance, not a
  confidentiality threat). No network time sync by design
  (ADR-0005).

### 5.8 Weak password generation

- **Threat:** biased or low-entropy generated passwords.
- **Mitigation:** generation from the OS CSPRNG (`getrandom` crate /
  `BCryptGenRandom` / `getrandom(2)`), rejection sampling for charset
  mapping (no modulo bias), documented entropy math per preset
  (ADR-0006).

## 6. Mitigation summary

| # | Threat | Mitigation | Residual |
|---|--------|------------|----------|
| 5.1 | Stolen vault file | Argon2id ≥1s, 128-bit salt | Weak master password |
| 5.2 | Clipboard persistence | 15 s auto-clear, history detection warning, stdin-based WSL copy | Clipboard History users |
| 5.3 | Memory/swap/dumps | zeroize, secrecy, one-item-at-a-time, best-effort locking | Funded local attacker |
| 5.4 | Metadata | All item data inside encrypted body; header is params only | Ciphertext lengths |
| 5.5 | Torn writes | Atomic replace + fsync; AEAD integrity | Concurrent last-write-wins |
| 5.6 | Plaintext to disk | No secret logging; ciphertext-only temp files | — |
| 5.7 | CLI arg leakage | No secret arguments, ever | — |
| 5.8 | Generator bias | OS CSPRNG + rejection sampling | — |

## 7. Out-of-scope decisions deferred to ADRs

- Unlock model: per-process vs. agent daemon (leaning **per-process** for
  v1 — smallest attack surface; revisit if UX demands).
- Sync: explicitly *bring-your-own*; the format is designed to be safe as
  an opaque file under naive sync (atomic writes, no partial states).
- Import from other managers: desired for v1.x, post-v1.
