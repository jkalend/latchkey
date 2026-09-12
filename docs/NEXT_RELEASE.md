# Next Release Proposal: rpass 0.2.0

**Status:** Proposed
**Date:** 2026-09-12
**Target:** First public preview
**Package version:** `0.2.0`
**Vault format:** version 1 (`RPv1`), unchanged
**Export schema:** version 1, unchanged

## 1. Decision

The next release should be **rpass 0.2.0**, not 1.5 or 2.0.

The crate is currently `0.1.0`, no public release has shipped, and the project
still identifies itself as unaudited hobby software. A 1.5 or 2.0 tag would
imply a release history and compatibility record that do not exist. Version
0.2.0 honestly communicates a usable preview while leaving room to adjust the
command interface before 1.0.

This proposal does not bump `Cargo.toml`. The version changes only when the
release criteria in §8 are met.

Three version numbers are independent:

- **Package version** follows SemVer and describes the application release.
- **Vault format version** selects the on-disk parser. rpass 0.2.0 continues to
  read and write format 1.
- **Export schema version** selects the portable plaintext import/export
  schema. rpass 0.2.0 continues to use schema 1.

Once 0.2.0 ships, every later release must continue reading vaults and native
exports created by 0.2.0. A future writer-format change requires an explicit
migration, a pre-migration encrypted backup, and a separately specified format
version. Package-version changes alone must never rewrite a vault.

## 2. Release outcome

0.2.0 turns the current security-focused implementation into a complete
offline daily-driver preview:

1. CLI and TUI use one application-operations module for mutations.
2. The TUI can add, edit, and delete credentials instead of acting as a
   read/copy-only viewer.
3. Users can import Bitwarden JSON and KeePassXC CSV through the existing
   preview-and-confirm workflow.
4. Users can authenticate every record in a vault with `rpass check`.
5. Published artifacts are exercised before GitHub Release publishes them.

The release remains local-only, single-user, and per-process. It does not add a
daemon, browser integration, or built-in sync.

## 3. Non-negotiable constraints

All 0.2.0 work must preserve these existing decisions:

- No network capability in the shipped binary (ADR-0005).
- No secrets in command arguments, logs, panic messages, or debug formatting.
- Windows 10/11 native and WSL2 remain the supported platforms. Plain Linux
  clipboard support remains best-effort.
- One encrypted vault file with encrypted index and per-item AEAD records
  (ADR-0004).
- Argon2id KEK plus random DEK; AES-256-GCM and ChaCha20-Poly1305 remain the
  only algorithms.
- Mutations use the existing write lock, stale-session check, fsync, and atomic
  replacement protocol.
- Clipboard restore and timeout behavior remain governed by ADR-0003.
- Existing 64 MiB file limits, 10,000-item import limit, parser-depth limit,
  KDF resource ceilings, and field-size limits remain enforced.

## 4. Scope

### 4.1 Shared application operations

**Problem:** CLI command handlers currently own application rules such as
identity resolution, timestamps, field updates, delete transitions, import
planning, and save timing. A writable TUI would either duplicate those rules
or call CLI-shaped code that prints and prompts.

**Decision:** Add one application-operations module between the CLI/TUI
adapters and the vault implementation.

The interface accepts structured user intent and stable `item_id` values. The
implementation owns validation, timestamp policy, add/edit/delete state
transitions, import planning, verification, and the rule that one logical
mutation produces one vault save. It returns structured outcomes and errors;
it never prompts, prints, reads terminal state, or copies to the clipboard.

The adapters retain interaction policy:

- CLI: argument parsing, hidden prompts, confirmation, stdout/stderr, and exit
  codes.
- TUI: forms, selection, rendering, confirmation modals, and status messages.
- Vault: format parsing, cryptography, lazy item decryption, locks, stale-write
  detection, and atomic persistence.

This is a real seam because two adapters use it. It must replace duplicated
rules rather than layer wrappers over existing CLI handlers.

**Acceptance criteria**

- Existing CLI behavior and exit codes remain unchanged unless this proposal
  explicitly changes them.
- CLI and TUI mutations pass through the same operations interface.
- UI modules do not directly edit `Vault.entries` or `Vault.open_items`.
- A successful add, edit, delete, or import performs exactly one atomic save.
- Confirmation and cancellation happen before the operation; cancelled work
  performs no save.
- Stale-session errors remain distinguishable from validation and I/O errors
  so the TUI can offer reload rather than overwrite.

### 4.2 Full credential lifecycle in the TUI

Add these list/detail actions:

| Key | Action |
|---|---|
| `a` | Add a credential |
| `e` | Edit the selected credential |
| `d` | Delete the selected credential after confirmation |
| `g` | Generate or regenerate a password inside add/edit |

Add/edit forms cover every existing credential field: title, username,
password, URL, notes, and optional TOTP configuration. Passwords and TOTP
secrets are masked while entered. Existing secrets are not pre-rendered into a
form; unchanged secret fields stay unchanged.

Rare or high-risk vault-wide operations remain CLI-only: `init`, `rotate`,
`backup`, `import`, and plaintext `export`.

**Acceptance criteria**

- Add, edit, and delete persist after quitting and reopening the real TUI.
- Cancel from any form or confirmation returns without changing the vault.
- Generated passwords use the existing ADR-0006 generator; the TUI does not
  implement a second generator.
- TOTP accepts the same base32 and `otpauth://` inputs and validation rules as
  the CLI.
- Delete displays title, username, and `item_id`; the default choice is cancel.
- Idle lock while a form is open drops the vault and zeroizes all entered
  secret buffers. Unlock returns to the list, not to an abandoned secret form.
- Explicit lock behaves the same way.
- If another process changes the vault before a TUI save, the save is refused,
  the form remains available for review, and the user may discard it and
  reload. The TUI never retries an overwrite automatically.
- Terminal restoration still runs on normal exit, input/output errors, and
  panic unwinding.

### 4.3 Imports from established managers

Extend `rpass import --format <format> <file>` with:

| Format value | Source |
|---|---|
| `json` | Native rpass export schema 1; existing behavior |
| `bitwarden-json` | Unencrypted Bitwarden JSON export |
| `keepassxc-csv` | KeePassXC CSV export |

Each source adapter parses into one canonical import record. The existing
planner then applies title-collision reporting, full validation, confirmation,
and one atomic save. Source-specific parsing must not leak into mutation code.

External source identifiers are not rpass identities. Bitwarden and KeePassXC
records are additions even if an external ID or title matches. Only native
rpass schema-1 imports may update by the existing identity rules.

**Acceptance criteria**

- The complete file is parsed and every supported field is validated before
  the vault is mutated.
- A malformed record rejects the whole import; no partial import is possible.
- Preview reports add count, title collisions, and unsupported/skipped field
  count without printing secrets. Validation errors identify the source record
  and abort before the preview can be confirmed.
- `--dry-run` never writes. `--yes` bypasses confirmation only for a validated
  pure-add plan, matching the current safety rule.
- Password, URL, notes, username, title, and TOTP are preserved where the
  source format represents them. Unsupported attachments, passkeys, payment
  cards, and identity-only fields are reported as skipped, not silently
  discarded.
- Source files retain the current 64 MiB and 10,000-item limits. JSON retains
  collection/depth limits; CSV receives equivalent record and field limits.
- Import buffers and canonical records zeroize on drop where their types
  permit it.
- The command warns that the source export is plaintext and should be removed
  or secured after a successful import.
- Checked-in non-secret fixtures cover each supported source version and the
  all-or-nothing failure path.

### 4.4 Full-vault authentication check

Add `rpass check` as a read-only command.

It prompts for the master password, validates framing and policy bounds,
authenticates the wrapped DEK and index, and authenticates every live and
tombstone item frame. It reports format version, algorithms, KDF parameters,
live count, tombstone count, and success without rendering credential data.

**Acceptance criteria**

- A valid vault returns exit code 0 and does not modify the file.
- Corrupt header, index, live item, tombstone item, or trailer returns nonzero.
- Authentication failures preserve the existing generic wrong-password-or-
  corruption user-facing policy.
- Output never includes titles, usernames, field lengths, secret values, or
  decrypted record data.
- A before/after file checksum proves the command is read-only.
- Backup documentation recommends running `rpass --vault <backup> check`
  before relying on a copied backup.

### 4.5 Release and installation polish

- Add `rpass completions <bash|zsh|fish|powershell>` using clap's command
  definition as the single source of truth.
- Document installation from GitHub artifacts and `cargo install --locked`.
- In the release workflow, run each packaged binary's `--version` and a
  temporary-vault init/add/list/check scenario before publishing it.
- Keep release archives limited to the binary, README, and license files.
- Publish SHA-256 checksums as already configured.

**Acceptance criteria**

- Generated completions contain every command and global option in the
  release binary.
- Windows and Linux packaged binaries complete the artifact smoke scenario,
  not merely `cargo build`.
- The binary reports `rpass 0.2.0`; the tag is `v0.2.0`; `Cargo.toml` and
  archive names agree.
- CI still proves the ADR-0005 dependency and socket bans.

## 5. Explicit non-goals for 0.2.0

- Vault format 2, new encrypted fields, custom fields, tags, folders, file
  attachments, passkeys, or SSH keys.
- Keyfiles or hardware-backed second factors for vault unlock.
- A resident unlock agent, daemon, background clipboard process, or OS-keychain
  integration.
- Browser extension, network sync, sharing, accounts, telemetry, update checks,
  or breach lookups. Any future sync work belongs in a separate package under
  ADR-0005.
- macOS support.
- A configuration file. The existing environment variables do not yet justify
  another precedence layer or persisted plaintext settings.
- Tombstone compaction. Current limits and target vault size do not justify a
  format-sensitive maintenance operation before the first preview.

These are deferred because they change the threat model, on-disk format, or
platform matrix. None is required to test the current product thesis.

## 6. Delivery sequence

1. **Operations seam:** move current CLI mutation/import rules behind the
   shared interface without changing observable behavior.
2. **Check command:** add whole-vault verification through that interface.
3. **TUI add:** ship one complete writable path, including cancellation,
   stale-write handling, idle lock, and restart persistence.
4. **TUI edit/delete:** reuse the same form and mutation rules; no parallel
   implementation.
5. **Import adapters:** add Bitwarden JSON and KeePassXC CSV ahead of the same
   canonical planner.
6. **Distribution:** completions, artifact smoke scenarios, installation docs,
   and the version bump.

Every step must leave CLI behavior usable. No step may introduce a second
vault writer or an alternate validation path.

## 7. Compatibility policy

- 0.2.x patch releases may fix defects but may not remove commands, flags,
  exit-code meanings, vault-format support, or export-schema support.
- Before 1.0, a breaking CLI change is allowed only in a minor release and
  must be called out in release notes.
- Vault and export compatibility are stricter than package SemVer: public data
  must remain readable even across a package major version.
- New writers must never perform an irreversible migration during ordinary
  open/list/copy operations.
- No compatibility promise applies to undocumented development-only vaults
  created before the first public release, though the existing legacy-frame
  reader should remain while it has negligible cost.

## 8. Release criteria

Tag `v0.2.0` only when all of these are true:

- CLI and TUI exercise the shared operations interface for every mutation.
- Real TUI smoke runs demonstrate add, edit, delete, lock, unlock, copy, and
  clean exit on Windows and WSL2.
- Import fixtures for native JSON, Bitwarden JSON, and KeePassXC CSV pass,
  including malformed and collision cases.
- `rpass check` detects independent bit flips in the index, a live item, a
  tombstone, and the trailer while leaving a valid vault byte-identical.
- `cargo fmt --check`, clippy with warnings denied, all tests, locked release
  builds, `cargo audit`, `cargo deny`, network-ban checks, and the independent
  vault-format cross-check pass.
- Packaged Windows and Linux artifacts pass their post-package smoke scenario.
- README, CLI reference, TUI guide, threat model, development guide, and
  release notes match shipped behavior.
- GitHub private vulnerability reporting is enabled.

## 9. Path to 1.0

0.2.0 is evidence gathering, not a disguised stable release. The 1.0 gate is:

1. At least one public preview has exercised vault compatibility and upgrade
   behavior outside the development machine.
2. The crypto construction, vault parser, import parsers, and clipboard paths
   receive independent security review, with all high-severity findings fixed.
3. The supported Windows and WSL2 flows have reproducible release smoke
   evidence.
4. CLI, vault-format, export-schema, and supported-version policies are frozen
   and documented.

If those conditions are met, the next stable tag is `v1.0.0`; there is no
reason to manufacture 1.5 or 2.0 first.
