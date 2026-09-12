# CLI Reference

**Status:** Current pre-release implementation (`rpass` 0.1.0)
**Binary name:** `rpass`

---

## Global flags (all commands)

| Flag | Effect |
|---|---|
| `--vault <path>` | Override the vault location (ADR-0002) for this invocation |
| `-q` / `--quiet` | Suppress **security warnings** (see §warning policy) — never suppresses errors or usability warnings |

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
so a scripted `rpass copy x.service | clipboard-tool` can't spam
copy-history warnings every time; errors must still reach a human.

## Command tree

| Command | Purpose |
|---|---|
| `rpass init` | Create a new vault; prompts for master password (twice) |
| `rpass add <title>` | Add a credential; prompts for username/password |
| `rpass totp <title>` | Show + copy the current TOTP code for an item |
| `rpass list` | List titles + usernames; never decrypts secrets |
| `rpass get <title>` | Print a secret to stdout; requires `--reveal` unless `--copy` |
| `rpass copy <title>` | Copy a secret to clipboard; auto-clears (ADR-0003) |
| `rpass generate` | Generate a password (ADR-0006 presets) |
| `rpass edit <title>` | Change username/password/notes (fuzzy-selects on collision) |
| `rpass rm <title>` | Delete an item; `--purge` skips confirmation (fuzzy-selects on collision) |
| `rpass rotate` | Raise KDF params to current policy; rotate DEK if `enc_counter` near cap |
| `rpass backup` | Atomic copy of the vault file for safekeeping |
| `rpass export` | Plaintext export; requires `--format json` + explicit `--yes-i-mean-it` |
| `rpass import` | Import from JSON export / other managers |
| `rpass tui` | Interactive interface (docs/TUI_GUIDE.md) |

## Details

### `rpass init`

- Prompts for the master password twice; refuses empty passwords and a
  small embedded deny-list of common passwords (THREAT_MODEL §5.1).
- Refuses to overwrite an existing vault without `--force` (which
  renames the old vault to `vault.bin.bak.<n>` first).
- Prints the vault path and the measured Argon2 wall-clock time, so the
  user sees what "≥ 1 s" means on their machine.

### `rpass add <title> [--username <u>] [--url <u>] [--notes <n>] [--generate]`

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

### `rpass get <title>`

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

### `rpass copy <title> [--timeout <secs>]`

- Default 30 s auto-clear, max 300 (ADR-0003). Ctrl-C clears
  immediately.
- Warns (once per invocation) if Windows Clipboard History is detected
  as enabled; `-q` suppresses.

### `rpass generate [--length <n>] [--symbols] [--passphrase] [--words <n>] [--hex] [--no-ambiguous] [--copy]`

- Defaults: 20 chars, 62-char alphabet, ~119 bits (ADR-0006).
- Prints the entropy estimate alongside the password.

### `rpass edit <title>`

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

### `rpass totp <title>`

- Prints the current code and remaining validity in seconds; `--copy`
  routes it to the clipboard instead (same ADR-0003 timeout).
- `rpass add` / `rpass edit` accept a TOTP secret via `--totp`
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
  than `rpass` rejecting a typo'd secret at save time.
- Time comes from the system clock; clock skew shows up as invalid
  codes at the service, which we surface as a hint (we do not
  auto-resync — no network, ADR-0005).

### `rpass export --format json --yes-i-mean-it`

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

### `rpass import --format json <file>`

- **Preview-and-confirm UX:** reads the file, computes `{ adds,
  updates, title-collisions }`, prints them, and asks interactively to
  proceed. No `--yes-i-mean-it` — scripts that need to know what an
  import will do must run the command interactively or use
  `--dry-run` for inspection only.
- Interactive confirmation is skipped only when the import adds
  nothing (pure adds, zero collisions) and the user passed `--yes`.
- `<item_id>` keys with a matching `title` **update** the existing
  entry's secrets, preserving its `item_id`; non-matching `<item_id>`
  keys **create** a new entry with a generated `item_id` (never reusing
  one from the import file — the file doesn't own identity allocation).
- Existing title collisions require interactive confirmation; `--yes` is
  accepted only for a pure add with no collisions. Duplicate titles in the
  import file are allowed and create separate items.
- `null` TOTP = no authenticator; missing optional fields = empty
  string. Unrecognized top-level keys = ignored (forward-compat).
- `format_version` is required and must be exactly `1`. Imports are
  limited to 64 MiB, 10,000 items, 10,000 values per JSON collection,
  and 128 nesting levels; larger inputs fail before mutating the vault.
- Exit code 1 on malformed JSON, 0 on success, 4 on user-cancel at the
  confirm prompt.

### `rpass rotate`

- Re-derives with current-policy KDF params, re-wraps the DEK, bumps
  `enc_counter` handling per VAULT_FORMAT §5.
- Can also change the master password (`--new-password` prompts).

### `rpass backup [--out <file>]`

- Copies the vault file to a backup path (or prints one if `--out` is
  omitted: `<vault-dir>/vault-backup-<unix-timestamp>.bin`, e.g.
  `%LOCALAPPDATA%\rpass\vault-backup-1725800000.bin` on Windows).
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
  rpass expects (or use `--vault <path>` to point rpass at the backup).
  No restore subcommand — restore is just a file copy in reverse.

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
| `RPASS_VAULT` | Default vault path (lowest precedence: flag > env > platform default) |
| `RPASS_CLIPBOARD_TIMEOUT` | Default clipboard timeout in seconds (default 30, max 300 as documented under `copy`) |
| `RPASS_TUI_LOCK_MINS` | TUI idle-lock timeout in minutes (default 10; 0 disables) |

## Configuration file

A configuration file is explicitly out of scope for 0.2.0: the three
environment variables above do not justify another precedence layer or
persisted plaintext settings. Revisit only when real settings outgrow them
([next-release proposal](NEXT_RELEASE.md#5-explicit-non-goals-for-020)).
