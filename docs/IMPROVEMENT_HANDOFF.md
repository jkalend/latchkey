# Password-manager improvement handoff

## Assignment and scope

Implement the six application improvements below for the latchkey side project. Commit each improvement separately, then delegate an approximately six-hour fuzz campaign to a **GPT6 Luna** subagent, resolve any reproducible findings, and publish the verified release.

This document is an implementation assignment, not an incident report or a refusal to work on the application. The latest user instruction for the agent writing this file was **handoff only**: implementation, fuzzing, commits, tag creation, and publication are left to the receiving agent.

### Starting point

- Package version: `0.3.0`. Annotated `v0.3.0` exists locally and was not pushed during the preceding work. Preserve that tag; use a new version/tag for the improvements.
- Repository remote: `git@github.com:jkalend/latchkey.git`. GitHub CLI authentication was available as `jkalend` when inspected; recheck access before publication.
- Windows workstation. Stable and nightly Rust toolchains and `cargo-fuzz 0.13.2` were available when inspected.
- The configured default agent model was `openai-codex/gpt-6-luna:high`. Verify the actual delegated model rather than assuming its name from an agent label.
- Existing implementation uses authenticated vault format 2 and native plaintext export schema 1. These improvements should not require another file-format change.
- Previous verification: 104 tests passed, clippy/formatting passed, Linux cross-compilation passed, all eight fuzz targets compiled, and the independent Python reader matched the golden vault exactly. Actual CLI and Windows TUI/clipboard scenarios were exercised. These are baseline results, not verification of the future changes.
- No fresh fuzz campaign has run against the format-2 changes.

Already implemented: whole-file HMAC authentication, explicit legacy migration, candidate size rejection, complete index/item encryption counting, terminal escaping, owned clipboard cleanup, and controlled-buffer wiping. Preserve those behaviors rather than reimplementing them.

### Read before changing interfaces

Use these existing documents as the behavioral source of truth:

- `docs/CLI_REFERENCE.md`: commands, prompting, reveal/copy behavior, and import/export contracts.
- `docs/VAULT_FORMAT.md` and `docs/CRYPTO_SPEC.md`: framing, authentication, counters, limits, and cryptographic primitives.
- `docs/TUI_GUIDE.md`: clipboard lifecycle and interactive behavior.
- `docs/DEVELOPMENT.md`, `docs/NEXT_RELEASE.md`, and `.github/workflows/`: verification and release mechanics.
- `fuzz/README.md` and `fuzz/Cargo.toml`: current target inventory and Windows sanitizer setup.

## Execution order and ownership

1. Inspect the current tree and exported-symbol callers. Rust LSP references previously failed because the server exited with code 0; try the available language server and use a documented text-search fallback if it remains unavailable.
2. Implement generated-password output independently.
3. Implement the immutable snapshot interface, then private vault state/fixed-size keys/transactional mutations. These overlap heavily and need one integration owner, but retain separate feature commits.
4. Replace JSON parsing and harden the workflow independently where possible.
5. Build the new fuzz harnesses against the completed vault interface and seed current-format inputs.
6. Verify the integrated implementation and freeze the tested source revision for the campaign.
7. Run the Luna campaign, resolve findings, rerun affected verification, and release.

For parallel work, assign one owner to shared files such as `src/cli/mod.rs`, `src/vault/vault_impl.rs`, and `Cargo.toml`. Agents can prepare isolated changes or coordinate nonoverlapping edits. Run integrated checks after edits settle; avoid simultaneous formatting/build churn across agents.

## 1. Opt-in generated-password display

### Current behavior

`src/cli/mod.rs` prints newly generated passwords to stderr in both `cmd_add` and `cmd_edit` before the credential mutation completes. The mutation flags are `add --generate` and `edit --generate`.

The standalone `generate` command intentionally produces a password as its result, or copies it with `--copy`. Do not silently change that command into a clipboard operation or a no-output command: the improvement concerns incidental disclosure during credential mutations.

### Implement

- Make `add --generate` and `edit --generate` store the generated value without printing it by default.
- Add an explicit opt-in flag, recommended name `--reveal-generated`, to both mutation commands. It must require `--generate`.
- Route the flag through command dispatch and the `AddArgs`/edit argument structures. Keep secret values out of command-line arguments.
- Emit the generated value only after the mutation successfully commits. A failed save must not be accompanied by a misleading successful reveal.
- Keep the generated secret in an existing wiping owner until persistence/reveal completes. Avoid a second secret copy solely for diagnostics.
- Preserve deliberate secret bytes, Unicode handling, `--quiet`, and the existing terminal-escaping distinction between metadata and intentional secret output.
- Update help, CLI reference, and relevant README examples. Completion generation uses clap, so the new flag must appear there automatically.

### Acceptance and verification

Use real CLI subprocesses with a temporary vault:

- Add with `--generate` succeeds; the stored password is valid; neither stdout nor stderr contains that actual generated value.
- Edit with `--generate` replaces the password without printing the replacement.
- Explicit reveal prints the exact value that can subsequently be read from the committed vault.
- The reveal flag without generation is rejected before mutation.
- A failed mutation leaves the vault unchanged and does not reveal an uncommitted generated value.
- Standalone `generate` output and explicit clipboard behavior remain intentional and documented.

Permanent tests should compare actual stored values against captured output, not pin diagnostic wording.

## 2. One immutable snapshot per export and rotation

### Current behavior

`Vault::open_item` in `src/vault/vault_impl.rs` rereads and authenticates the complete file on every call, including cached-item requests. `cmd_export` calls it for every live entry. `Vault::rotate` does the same before saving under new keys. Repeating full-file work makes these operations scale poorly and permits an operation to encounter different disk revisions partway through its preparation.

### Implement

Introduce a small snapshot interface inside the vault module:

- Acquire one bounded file image for a bulk operation.
- Authenticate its complete commit tag and match the session's last observed commit identity before exposing plaintext.
- Parse frame locations once. Borrow ciphertext slices from the owned image rather than copying each frame.
- Decrypt the necessary records from that image, cross-checking embedded IDs, slot bounds, duplicate slots, and entry counts.
- Expose read-only entry/record access to export. A suggested name is `VaultSnapshot`; choose the final interface alongside the private-state work.
- Keep plaintext records in their wiping owning types and release them when the operation ends.
- Keep ordinary single-item reads protective: cached data must not hide a corrupt or stale disk commit.

For rotation, hold the write lock across the relevant read/modify/publish cycle or otherwise revalidate the captured full commit identity under that lock immediately before publication. Reuse the already captured image instead of another unconditional full read. A concurrent committed change must produce a stale-session error rather than be overwritten.

Preserve live records and the documented tombstone behavior. Pay particular attention to cached/decrypted tombstones: rotation must not copy old-DEK ciphertext under a new DEK or silently discard a record it previously preserved.

### Acceptance and verification

- Export contains one coherent authenticated revision and remains read-only.
- A concurrent disk change is either excluded by the lock or detected before publication; no mixed-revision export or lost update.
- Rotation preserves IDs, metadata, credentials, TOTP, and documented tombstone state under fresh keys.
- Authenticated-file splicing and cached-read regressions remain rejected.
- Demonstrate the improvement with a throwaway multi-record runtime benchmark or read-count observation: full-file reads/authentication do not grow once per exported/rotated item.
- Avoid retaining extra plaintext clones just to simplify iteration.

## 3. Private vault state, fixed-size keys, transactional mutations

### Current behavior

`Vault` publicly exposes `path`, `header`, `dek`, `entries`, `open_items`, and `next_item_id`. Application operations in `src/ops.rs` directly mutate these fields and then call `save`.

Examples: `update_entry` removes a cached record before all validation finishes; `delete_entry` changes entry state before saving; `apply_import` modifies adds/updates before its final save. A validation, stale-session, counter, size, or filesystem error can leave the in-memory session different from the unchanged disk file.

`src/crypto/kdf.rs` uses the variable-length `SecretVec = SecretBox<[u8]>` representation for both passwords and 32-byte keys. KDF output uses a temporary vector even though its size is fixed.

### Implement

**Encapsulation**

- Make mutable vault internals and keys private.
- Provide narrow read-only metadata/config/path accessors and an item/snapshot read interface.
- Keep raw key access inside the vault/crypto implementation. Do not replace public fields with public mutable getters or an unrestricted cache map.
- Put record/index mutation behind vault-owned operations or a private candidate-commit seam used by `ops`.
- Migrate every caller: CLI, TUI, import adapters, examples, integration tests, and fuzz harnesses. Remove obsolete field access and redundant open-then-cache-lookup sequences.

**Fixed-size key ownership**

- Separate variable-length password input from KEK/DEK types.
- Use a redacted, wiping owner of `[u8; 32]` for 256-bit keys. Prefer a stack-owned wrapper where practical; a fixed-size heap wrapper is acceptable if existing `secrecy` semantics justify it. Document the choice.
- Derive directly into a guarded fixed-size output buffer and fill fresh DEKs directly from the OS CSPRNG.
- Update AEAD, HKDF, HMAC, wrap/unwrap, password-change, and rotation callers together.
- Reject invalid unwrapped lengths before installing a key. Preserve algorithm and wire compatibility and the independent cryptographic vectors.
- Keep zeroizing Argon2 workspace ownership and supported dependency wiping features.

**Transactional mutations**

- Prepare and validate a candidate without changing committed session state.
- Check expected disk commit identity and write limits before encryption/publication.
- Publish atomically; install candidate metadata, cache, keys, counters, and next ID only after successful publication.
- On a failure before publication, preserve both prior disk bytes and the observable in-memory session, including retained credentials and ID allocation.
- Define failure semantics for errors after publication, such as durability/cleanup failures: callers must be able to distinguish an unchanged vault from a file already published. Do not promise rollback after an irreversible successful filesystem replacement.
- Apply this consistently to add, edit, delete, bulk import, password change, and rotation. Preserve no-op edit behavior and creation/migration no-overwrite semantics.
- Favor staging only changed records/index state over cloning every decrypted credential for every operation. Wipe rejected candidates on drop.

### Acceptance and verification

Exercise the public application-operation seam, then observe session state and reopen disk:

- Invalid edits retain the original cached record and metadata.
- Failed add/import does not consume IDs or install partially prepared records.
- Failed delete leaves the item live and readable in the same session and after reopen.
- Size/counter rejection and stale-session failures leave prior committed state intact.
- Password-change/rotation failure retains the prior working credentials/configuration.
- A successful import is one commit, not a partially persisted series.
- Use deterministic errors such as validation, write-limit boundaries, a held write lock, or a stale commit. Do not depend on timing-sensitive antivirus locks or sleeps.
- Existing golden vectors and cross-algorithm behavior continue to pass with fixed-size keys.

## 4. Maintained JSON parser with explicit limits

### Current behavior

`src/json.rs` contains a hand-written JSON grammar. Its `Json` value tree has redacted debug formatting and drop wiping; adapters use `get`, `as_str`, `as_num`, `as_obj`, and variant matching. Existing limits include depth 128 and 10,000 elements per collection. Import file/record/field limits live in the importer and must be retained.

### Implement

- Replace custom grammar/escape/number handling with a maintained local parser, recommended `serde_json` plus a bounded custom deserializer/visitor.
- Preserve a small wiping value adapter if needed to avoid rewriting all importer interpretation at once. The custom code should enforce policy and ownership, not implement JSON lexical grammar again.
- Enforce input byte, nesting, collection, and decoded-string/resource limits while deserializing, not by building an unbounded `serde_json::Value` and checking afterward.
- Retain the existing 64 MiB import-file limit, 10,000-item import limit, 128-depth policy, and domain field limits. Define any additional total-node/string limits explicitly, justify them against supported real exports, and document any intentional compatibility change.
- Specify duplicate-key behavior. Prefer preserving the current effective last-value-wins behavior while wiping replaced values and counting duplicate fields toward parser work limits.
- Check number handling carefully: IDs/timestamps/TOTP parameters must not be silently rounded or accepted out of range. Use lossless integer handling rather than routing integer validation through an imprecise f64 conversion.
- Preserve forward-compatible unknown-field behavior and valid Unicode/surrogate-pair interpretation.
- Keep errors generic enough not to echo password, notes, TOTP, or entire input fragments.
- Guard partially assembled strings/collections and rejected intermediate values with wiping owners. Account for any unavoidable parser-internal scratch memory honestly.
- Update the root and fuzz dependency locks without unrelated dependency upgrades. Preserve the application's existing no-network dependency policy.
- Remove the obsolete grammar implementation and implementation-coupled/wording-only tests; keep importer-visible behavior tests.

### Acceptance and verification

- Existing native JSON and Bitwarden fixtures import with the same supported data.
- Valid Unicode, escaped controls, malformed surrogate pairs, duplicate keys, numeric boundaries, deep nesting, and oversized collections behave according to the documented policy.
- Rejected imports leave the vault unchanged and diagnostics do not expose supplied secret canaries.
- Export/import round trips preserve IDs and representable credentials. Non-UTF-8 secrets retain the existing explicit refusal rather than lossy replacement.
- Run actual import dry-runs and confirmed imports, and keep plausible boundary/error regressions at parser/import interfaces.

## 5. Pin CI actions and attest release artifacts

### Current behavior

`.github/workflows/ci.yml` and `release.yml` use mutable action tags: checkout, Rust toolchain, cache, artifact upload/download, and GitHub-release publication. Release jobs already package and smoke the copied binaries for Windows/Linux and publish `SHA256SUMS`.

### Implement

- Resolve each external action to a verified full commit SHA from its upstream repository. Include a readable release/version comment beside the pin.
- Cover every workflow action, not only checkout. For the Rust-toolchain action, keep the Rust version explicitly configured in `with:` when replacing its version-named ref with a commit SHA.
- Add GitHub build-provenance attestations using the maintained attestation action, itself SHA-pinned.
- Attest the exact final `.zip`/`.tar.gz` bytes that users download, after packaging, before publication. The digest and subject name must match the uploaded release asset, not an intermediate executable or repackaged directory.
- Grant `id-token: write` and `attestations: write` only to the job that signs provenance; retain least-privilege `contents` permissions elsewhere.
- Preserve tag/package-version checks, locked builds, Windows/Linux artifact smoke runs, checksums, and the no-network application checks.
- Make successful CI verification a prerequisite for publication. Prefer a draft release that becomes public only after all required checks, artifacts, and attestations succeed.
- Update installation/development documentation with actual `gh attestation verify` commands, using `jkalend/latchkey` and the real release assets.

### Acceptance and verification

- Every external `uses:` action has a full verified SHA, with no invented hash or mutable version reference.
- Both platform artifacts pass their packaged-binary runtime smokes.
- Downloaded release asset checksums match `SHA256SUMS` and GitHub attestation verification succeeds against this repository.
- Publication does not race failed/incomplete CI or attestation jobs.

## 6. End-to-end fuzz coverage and GPT6 Luna campaign

### Coverage to add

Existing targets: `parse_header`, `parse_index`, `parse_item`, `split_item_frames`, `otpauth_uri`, `import_native_json`, `import_bitwarden`, and `import_keepassxc`.

Add harnesses for:

1. **Authenticated format-2 vault behavior:** bounded input bytes through the real authentication/parsing path; valid commits, header/index/item/trailer mutations, truncation, count/length inconsistencies, and historical valid index/item splicing with repaired CRC. Successful reads must produce coherent records; corrupt/spliced commits must not expose substituted plaintext.
2. **Explicit legacy migration:** both historical frame layouts, live/tombstone preservation, invalid/truncated records, wrong passwords, duplicate/out-of-range slots/IDs where applicable, source preservation, and existing-target refusal. A rejected migration must not leave an apparently successful target.

Use the real implementation. If a memory-backed snapshot seam is exposed for genuine library use, exercise it; otherwise use isolated per-worker temporary directories. A dedicated feature-gated fuzz adapter may expose the real internal path without making keys or mutable state part of the normal public interface.

Keep fuzz execution bounded. Arbitrary production-valid Argon2 headers can request expensive work; cover the full parameter policy in structural targets and constrain the expensive end-to-end harness to documented fast valid fixture parameters. Migration's production KDF upgrade may need a documented harness-only policy seam calling the same migration implementation. Report constrained coverage explicitly; do not weaken production policy or substitute a fake cryptographic path.

### Seeds and invariants

- Seed header/frame targets from the current `test-vectors/vault-golden.bin` and retain `vault-legacy-v1.bin` for the migration target.
- Keep useful plaintext parser/import/TOTP corpus inputs from previous campaigns; normal v1 vault seeds alone now terminate early at version selection.
- Include valid inputs that reach beyond MAC rejection, plus mutation/operation encodings that exercise authenticated and stale-state transitions.
- Keep property checks deterministic. Record round trips, source/destination preservation, and acceptance/rejection invariants rather than asserting implementation details.
- Bound input sizes, memory, KDF work, files, and temporary-directory cleanup. Keep corpus data synthetic; do not seed user vaults or real credentials.

### Campaign assignment

Delegate execution to a subagent whose resolved model is **GPT6 Luna** (`openai-codex/gpt-6-luna`, appropriate reasoning setting). Supply the frozen commit, target list, seed locations, sanitizer setup, bounds, and this document. An agent named “Luna” running another model does not meet the request.

Budget approximately **21,600 seconds of cumulative active fuzz runtime across the target set**, not six hours per target. Report wall-clock duration separately if targets run concurrently. Build, seed preparation, and triage time are separate from active fuzz time. A reasonable initial split for ten targets is roughly 36 minutes each; rebalance toward authenticated vault, migration, and newly replaced JSON paths while retaining time on all targets.

On Windows, follow the existing nightly/MSVC ASan setup in `fuzz/README.md`. If named supervised processes are needed for the long run, keep their logs and exit results observable. Await completion rather than repeatedly polling. Stop and minimize a crash/resource finding before deciding how to resume its allocation.

The campaign report must contain:

- Actual resolved agent model, source commit, toolchain, sanitizer configuration, and harness bounds.
- Exact commands/arguments, seeds used, target-by-target elapsed active time, execution counts, available coverage statistics, and exit status.
- Crashes, hangs, OOMs, timeouts, minimized reproducers, fixes, and rerun evidence, or an explicit observed no-finding result for completed targets.
- Coverage exclusions and the difference between compilation, a short smoke, and the full campaign.

## Commit, verification, and publication contract

### Feature commits

Create separate reviewable commits for generated output, bulk snapshots, vault encapsulation/fixed keys/transactions, JSON parsing, workflow provenance, and fuzz harnesses. A final release-version/documentation commit and a corpus/results commit are appropriate. Keep unrelated existing user changes out of the commits.

Use a new version/tag; do not move or overwrite local `v0.3.0`. Recommended next pre-1.0 version: `0.4.0`, reflecting CLI/default-output and Rust interface changes while retaining vault format 2/export schema 1. Check current repository history before choosing the final number. Synchronize Cargo manifests/locks, documented package version, artifact names, and release tag.

### Verification after integration

At minimum run and record:

```console
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --release --locked --all-targets
cargo build --release --locked --bin latchkey
cargo check --locked --manifest-path fuzz/Cargo.toml --bins
cargo audit
cargo deny check
python test-vectors/cross_check.py test-vectors/vault-golden.bin test-vector-master-password
```

Compare the independent reader's output exactly with `test-vectors/expected.txt`. Cross-compile as useful, but obtain actual Linux/Windows CI and packaged-runtime results before claiming both platforms verified.

Exercise changed behavior outside unit tests: silent generated add/edit and explicit reveal; multi-item coherent export/rotation; failed-operation session reuse; supported and rejected imports; attestation verification of downloaded artifacts. Preserve the existing actual Windows clipboard quit/restoration checks when changing TUI callers, and preserve deliberate secret versus escaped metadata output.

The earlier suite had one Windows atomic-replacement `AccessDenied` during a run; the final 104-test run passed, and the cause was not established. If it recurs, inspect file/handle ownership and preserve prior-file failure semantics rather than hiding it with an unexplained retry.

### Publish after completion

The user authorized the receiving agent to release once implementation and fuzzing are done. Recheck GitHub access and current release state, then:

1. Finish feature commits and the integrated runtime checks.
2. Complete the requested Luna campaign; resolve findings and verify fixes against the final source.
3. Push the intended branch and observe required CI completion. Handle existing remote changes normally; avoid force-pushing user history.
4. Create and push the new annotated tag only after confirming package/tag agreement and the workflow publication gate.
5. Observe the release workflow through completion, verify packaged artifacts/checksums/attestations, and publish the draft if using a draft gate.
6. Report the release URL, tag/commit, downloadable artifacts, verification evidence, and fuzz report location.

An unavailable credential, failed platform check, or unresolved reproducible finding is an explicit publication blocker, not permission to claim a release. Complete all reachable implementation/verification and report the exact remaining prerequisite.

### Completion checklist

- [ ] Six improvements implemented with migrated callers and separate commits.
- [ ] Existing vault/export compatibility and authentication invariants preserved.
- [ ] Runtime proof and regression checks completed for changed behaviors.
- [ ] All targets seeded appropriately; six-hour GPT6 Luna campaign completed and documented.
- [ ] Findings resolved and affected checks rerun against the final source.
- [ ] Current documentation and release metadata agree.
- [ ] Required CI and packaged-platform checks passed.
- [ ] Release assets, checksums, and attestations verified; release published and URL reported.
