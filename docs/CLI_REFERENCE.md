# CLI Reference

**Status:** Public preview (`latchkey` 0.2.0)
**Binary name:** `latchkey`

---

## Global flags (all commands)

| Flag | Effect |
|---|---|
| `--vault <path>` | Override the vault location (ADR-0002) for this invocation |
| `-q` / `--quiet` | Suppress **security warnings** (see §warning policy) — never suppresses errors or usability warnings |
| `--from-stdin` | Read master-password prompts from stdin, one line per prompt; intended for controlled automation |

`--from-stdin` never accepts a secret as a process argument or environment
variable. For `init`, provide the new master password twice. Other vault
commands consume one line. The TUI rejects this flag because it is interactive.
Treat the producing pipe or input file as secret material.

### Warning policy

Three tiers:

- **Errors** — never suppressible, always printed to stderr, exit code 1+.
- **Security warnings** (Clipboard History active, `--reveal` to stdout,
  Vault History Cloud enabled, etc.) — printed to stderr by default;
  the only tier `-q` hides. TUI: printed once to stderr before the
  interface starts (a one-shot startup warning, not a banner).
- **Usability warnings** (empty vault, vault not found, backup path
  collided with existing file) — printed once per invocation to stderr;
  `-q` doesn't silence them (they're one line, and the user *must* see
  them to know nothing happened).

Never mix tiers in one message. The security-warning mechanism exists
so a scripted `latchkey copy x.service | clipboard-tool` can't spam
copy-history warnings every time; errors must still reach a human.

## Command tree

| Command | Purpose |
|---|---|
| `latchkey init` | Create a new vault; prompts for master password (twice) |
| `latchkey add <title>` | Add a credential; prompts for username/password |
| `latchkey totp <title>` | Show + copy the current TOTP code for an item |
| `latchkey list` | List titles + usernames; never decrypts secrets |
| `latchkey get <title>` | Print a secret to stdout; requires `--reveal` unless `--copy` |
| `latchkey copy <title>` | Copy a secret to clipboard; auto-clears (ADR-0003) |
| `latchkey generate` | Generate a password (ADR-0006 presets) |
| `latchkey edit <title>` | Change username/password/notes (fuzzy-selects on collision) |
| `latchkey rm <title>` | Delete an item; `--purge` skips confirmation (fuzzy-selects on collision) |
| `latchkey rotate` | Raise KDF params to current policy; rotate DEK if `enc_counter` near cap |
| `latchkey backup` | Atomic copy of the vault file for safekeeping |
| `latchkey check` | Authenticate every record without modifying the vault |
| `latchkey export` | Plaintext export; requires `--format json` + explicit `--yes-i-mean-it` |
| `latchkey import` | Import from JSON export / other managers |
| `latchkey completions <shell>` | Generate Bash, Zsh, Fish, or PowerShell completions |
| `latchkey tui` | Interactive interface (docs/TUI_GUIDE.md) |

## Details

### `latchkey init`

- Prompts for the master password twice; refuses empty passwords and a
  small embedded deny-list of common passwords (THREAT_MODEL §5.1).
- Refuses to overwrite an existing vault without `--force` (which
  renames the old vault to `vault.bin.bak.<n>` first).
- Prints the vault path and the measured Argon2 wall-clock time, so the
  user sees what "≥ 1 s" means on their machine.

### `latchkey add <title> [--username <u>] [--url <u>] [--notes <n>] [--generate]`

- No duplicate-title rejection — it's valid to have several items with
  the same title ("github.com" / personal + work). Collisions are
  handled at read by interactive fuzzy select (`get`/`copy`).
- Password is prompted hidden (`--generate` fills it per ADR-0006 and
  re-displays it for the user to save elsewhere if they want).
- Never accepts a password as a CLI argument (THREAT_MODEL §5.7).
- `--notes` reads interactively in `$EDITOR` when the flag is given
  without a value; a value on the command line is allowed since notes
  are not classified as secrets (documented trade-off — `get`/`edit`
  treat notes as secret on *output*).

### `latchkey get <title>`

- Default behavior: copies to clipboard (same as `copy`) — printing to
  stdout requires `--reveal`, which also prints a warning that the
  terminal scrollback now contains the secret. `--copy` and `--reveal`
  are mutually exclusive. Copying is byte-exact even for secrets that
  are not valid UTF-8; `--reveal` refuses those (use `copy` instead).
- `<title>` resolves to **all** live entries with that title (VAULT_FORMAT
  §5: titles are not unique). One match → direct; several → an
  interactive fuzzy chooser lists each with username + `item_id` suffix
  for disambiguation; none → `No matching entry; similar: <titles>``(up
  to 3, ranked). Non-interactive scripts use `--id <item_id>` which
  bypasses title matching entirely.

### `latchkey copy <title> [--timeout <secs>]`

- Default 30 s auto-clear, max 300 (ADR-0003). Ctrl-C clears
  immediately.
- Warns (once per invocation) if Windows Clipboard History is detected
  as enabled; `-q` suppresses.

### `latchkey generate [--length <n>] [--symbols] [--passphrase] [--words <n>] [--hex] [--no-ambiguous] [--copy]`

- Defaults: 20 chars, 62-char alphabet, ~119 bits (ADR-0006).
- Prints the entropy estimate alongside the password.

### `latchkey edit <title>`

- Changes to any of username (index) or password/notes/TOTP
  (ItemRecord) are written as **a single atomic vault write** under
  VAULT_FORMAT §8's write protocol. The index and item ciphertext are
  parts of one serialized file — there is no partial-edit failure mode
  where one lands and the other doesn't. This is explicit because
  split-brain on metadata-vs-secret would appear as a corrupted entry
  (username says A, password belongs to B), and the format is designed
  to prevent it.
- Title collision (Q7): enters interactive fuzzy select before any
  edit is staged.

### `latchkey totp <title>`

- Prints the current code and remaining validity in seconds; `--copy`
  routes it to the clipboard instead (same ADR-0003 timeout).
- `latchkey add` / `latchkey edit` accept a TOTP secret via `--totp`
  (base32, prompted hidden — never a CLI argument; defaults to
  SHA1/30 s/6 digits, select the algorithm with
  `--totp-alg <sha1|sha256|sha512>`) or `--totp-uri` for
  pasting an `otpauth://` URI (parsed, parameters extracted, URI
  zeroized).
  **Validated at write-time:** base32 must decode cleanly, and the
  decoded length must fit the selected algorithm (SHA1 ≥ 10 bytes,
  SHA256 ≥ 16, SHA512 ≥ 32 — RFC 6238's interoperability floor).
  Rejects on garbage input with a message showing which validation
  failed (e.g. "base32 decodes to 12 bytes, need ≥16 for SHA256")
  — the service's "this doesn't work" wild-goose chase is much worse
  than `latchkey` rejecting a typo'd secret at save time.
- Time comes from the system clock; clock skew shows up as invalid
  codes at the service, which we surface as a hint (we do not
  auto-resync — no network, ADR-0005).

### `latchkey export --format json --yes-i-mean-it`

- Writes the entire vault **in plaintext** to stdout (or `--out
  <file>`). The double opt-in (flag + explicit format) is deliberate —
  this is the one command that violates the no-plaintext-to-disk
  principle by design, so it must be unmistakably intentional.
- Warns and requires a TTY confirmation unless `--yes-i-mean-it`.
- **Crypto hygiene on export:** plaintext touches memory only in the
  process boundary — ItemRecord fields are decrypted into `SecretVec`s,
  serialized to JSON in-memory, and written to `--out` (or stdout) in
  a single `write_all`, then every plaintext buffer is zeroized before
  process exit. Never landed to a temp file, never piped through a
  shell redirect that could end up in scrollback (the command refuses
  to write to stdout unless the user explicitly passes `--out -`).
- **Schema (v1)** — keyed by `item_id` (stable, never reused — see
  VAULT_FORMAT §5), with titles duplicated for human readability but
  not authoritative on import:

  ```json
  {
    "format_version": 1,
    "exported_at": "<unix seconds>",
    "items": {
      "<item_id>": {
        "title": "<title>",
        "username": "<username>",
        "password": "<password>",
        "url": "<url or ''>",
        "notes": "<notes or ''>",
        "totp": {
          "secret": "<base32>",
          "period": 30,
          "digits": 6,
          "algorithm": "SHA1"
        } | null,
        "created_unix": 0,
        "modified_unix": 0
      },
      ...
    }
  }
  ```

### `latchkey import --format <format> <file>`

- Formats: `json` for native schema 1, `bitwarden-json` for an unencrypted
  Bitwarden JSON export, and `keepassxc-csv` for a KeePassXC CSV export.
- **Preview-and-confirm UX:** the complete file is parsed and validated first,
  then the command prints `{ adds, updates, title-collisions,
  unsupported/skipped fields }` without secrets and asks interactively to
  proceed.
- `--yes` skips confirmation only for a validated pure-add plan with zero
  title collisions. `--dry-run` validates and previews without writing.
- Native `<item_id>` keys with a `title` matching exactly one live entry update
  that entry's secrets while preserving its `item_id`. Non-matches create a
  generated latchkey `item_id`; imported IDs never allocate identity.
- Bitwarden and KeePassXC records are always additions, even when their IDs or
  titles match. Unsupported attachments, passkeys, cards, identity records,
  custom fields, extra URLs, and nonempty unsupported CSV columns contribute
  to the skipped count.
- Supported source fields preserve title, username, password, URL, notes, and
  TOTP. Bitwarden secure notes are imported as credentials without a password.
  Malformed records identify their source position and abort the whole import
  before any vault mutation.
- Imports are limited to 64 MiB and 10,000 records. JSON retains the 10,000
  values-per-collection and 128-level depth limits; individual CSV fields are
  limited to 1 MiB.
- The source file is plaintext. The command warns to secure or remove it after
  import.
- Exit code 1 on malformed input, 0 on success, and 4 on cancellation.

### `latchkey rotate`

- Re-derives with current-policy KDF params, re-wraps the DEK, bumps
  `enc_counter` handling per VAULT_FORMAT §5.
- Can also change the master password (`--new-password` prompts).

### `latchkey backup [--out <file>]`

- Copies the vault file to a backup path (or prints one if `--out` is
  omitted: `<vault-dir>/vault-backup-<unix-timestamp>.bin`, e.g.
  `%LOCALAPPDATA%\latchkey\vault-backup-1725800000.bin` on Windows).
- The backup is **just a copy of the encrypted file** — nothing
  decrypted, nothing transformed. It's safe to move, sync, or back up
  anywhere the file itself is safe.
- Atomic per VAULT_FORMAT §8's write protocol: writes to a temp in the
  same directory and atomically renames, so sync tools never see a
  half-written backup.
- `--out` may point at another drive (e.g. a synced folder
  "/mnt/c/Users/.../CloudDrive/vault-backup.bin" from WSL), which is
  the point of the command — the source vault stays on the local
  filesystem while backups can live elsewhere.
- To restore: copy the backup file over `vault.bin` at the location
  latchkey expects (or use `--vault <path>` to point latchkey at the backup).
  No restore subcommand — restore is just a file copy in reverse.

### `latchkey check`

- Prompts for the master password and authenticates the wrapped DEK, encrypted
  index, every live item, every tombstone frame, and the trailer CRC.
- Reports format version, algorithms, KDF parameters, and live/tombstone
  counts. It never prints titles, usernames, field lengths, or plaintext
  record data.
- Read-only: a successful or failed check never writes the vault. Validate an
  encrypted backup before relying on it with
  `latchkey --vault <backup-path> check`.

### `latchkey completions <bash|zsh|fish|powershell>`

- Generates completion definitions directly from clap's live command tree, so
  every subcommand and global option matches the installed binary.
- Writes to stdout. Load it for the current session, for example:
  `source <(latchkey completions bash)` or
  `latchkey completions powershell | Out-String | Invoke-Expression`.
- For persistent installation, redirect the output to the completion directory
  used by the selected shell.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic failure (I/O, vault corrupt or wrong password — indistinguishable by design, CRYPTO_SPEC §7) |
| 2 | Usage error (bad flags, unknown command) |
| 3 | Vault not found / not initialized |
| 4 | Cancelled by user (Ctrl-C, declined confirmation) |

Stable exit codes make the tool scriptable; never reuse 1's meaning for
an authentication-specific condition.

## Environment variables

| Variable | Effect |
|---|---|
| `LATCHKEY_VAULT` | Default vault path (lowest precedence: flag > env > platform default) |
| `LATCHKEY_CLIPBOARD_TIMEOUT` | Default clipboard timeout in seconds (default 30, max 300 as documented under `copy`) |
| `LATCHKEY_TUI_LOCK_MINS` | TUI idle-lock timeout in minutes (default 10; 0 disables) |

## Configuration file

A configuration file is explicitly out of scope for 0.2.0: the three
environment variables above do not justify another precedence layer or
persisted plaintext settings. Revisit only when real settings outgrow them
([next-release proposal](NEXT_RELEASE.md#5-explicit-non-goals-for-020)).
