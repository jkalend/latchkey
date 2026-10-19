# Security review: latchkey 0.4.1

- **Review date:** 2026-10-16 (Europe/Prague).
- **Reviewed commit:** `02e704e9bd47dcd5f589b55c832028e5c126e9a7`.
- **Scope:** the application in this repository, including Rust library code, CLI, TUI, cryptography, vault format and persistence, imports/exports/backups, clipboard backends, dependency policy, and build/release workflows.
- **Method:** manual source review, comparison with the documented threat model, execution of the existing test suite, dependency checks, and targeted experiments using synthetic credentials.
- **Changes delivered:** this report only. Temporary reproduction tests were removed after execution; their complete source is preserved in Appendix A.

## Executive assessment

The application has a sound set of foundational controls: authenticated encryption, a KEK/DEK hierarchy, whole-file authentication, bounded vault reads, explicit legacy migration, fresh nonces, and rejection of stale commits. The review did not establish a cryptographic primitive break or a way to decrypt a normally built, properly protected vault without its password or key.

However, **two high-severity issues undermine credential confidentiality**, and several additional issues weaken filesystem safety, clipboard expiry, build configuration, and terminal output. The most serious finding is that `rotate --new-password` publishes the replacement DEK encrypted under the old password before changing the password. A retained intermediate copy gives an attacker access to credentials saved after the password change. Windows plaintext exports can also inherit permissions that expose the entire export to other users.

**Finding totals: 2 High, 5 Medium, 1 Low; no Critical finding established.** These are application-specific findings. Additional policy and memory-hygiene observations are listed separately and are not included in those totals.

Passing tests and a clean dependency audit do not resolve these implementation issues. Address the high findings and the clipboard/build configuration findings before relying on the app for valuable credentials.

## Scope, assumptions, and limitations

The principal protected assets are master passwords, KEKs/DEKs, stored passwords and notes, TOTP seeds, and authenticated vault contents. Relevant external inputs include vault files, imported JSON/CSV, clipboard contents, environment variables, filesystem paths, and terminal input.

Severity reflects both impact and prerequisites:

- **High:** potential exposure of the whole vault or continued access to future secrets under realistic use of supported features.
- **Medium:** a concrete failure of a security control, requiring particular filesystem conditions, concurrent operations, build options, or user interaction.
- **Low:** limited integrity or defense-in-depth impact without an established broader compromise.

Testing took place on native Windows with Rust/Cargo 1.98.1. Windows clipboard experiments used synthetic values, and prior clipboard text was restored. The WSL cleanup failure was reproduced by calling the production WSL bridge with a purpose-built fake PowerShell executable in an isolated test process; it did not alter the real clipboard. Linux-specific behavior was inspected in source; a live X11/Wayland session was not tested.

The review did not audit every transitive dependency internally, independently validate published release binaries or GitHub settings, inspect actual user vaults, perform a new long-running fuzz campaign, or conduct memory-forensics/side-channel testing. Existing fuzz campaign reports were treated as repository evidence, not as tests performed during this review. Source inspection of release YAML cannot establish actual branch protections or release approval settings.

The documented exclusions for same-user malware, a compromised OS, cold boot/DMA, swap/hibernation/crash artifacts, and complete authenticated-file rollback remain relevant. They are not presented below as newly discovered vulnerabilities.

## Findings at a glance

| ID | Severity | Finding | Evidence |
|---|---|---|---|
| SEC-01 | High | Password rotation publishes the new DEK under the old password | Actual CLI intermediate captured; future-secret decryption reproduced |
| SEC-02 | High | Windows plaintext exports inherit potentially broad read permissions | Actual export inherited an Everyone read ACE |
| SEC-03 | Medium | Predictable replacement temp files follow pre-existing links and clobber unrelated files | Hard-link overwrite reproduced on Windows |
| SEC-04 | Medium | Overlapping clipboard copies restore an already expired secret | Two real CLI copy processes reproduced persistence after both exited |
| SEC-05 | Medium | WSL/Linux cleanup read failures return success while leaving the secret available | Production WSL bridge reproduced with a failing tool shim; Linux source confirms equivalent flow |
| SEC-06 | Medium | A release build can silently enable the fuzz-only weak KDF | `--release --all-features` binary created an 8 MiB/t=1 vault |
| SEC-07 | Medium | Revealing an imported password emits terminal control sequences | Actual CLI output contained literal ESC/display-control bytes |
| SEC-08 | Low | Windows clipboard copy silently truncates passwords containing NUL | Native JSON import and real clipboard copy reproduced truncation |

### SEC-01 — Password rotation publishes the new DEK under the old password

**Severity:** High. **Status:** reproduced through both the actual CLI and the cryptographic read path.

**Locations:** [CLI rotation](../src/cli/mod.rs#L1171), lines 1171–1188; [DEK rotation](../src/vault/vault_impl.rs#L896), lines 896–945; [password change](../src/vault/vault_impl.rs#L949), lines 949–972.

**What happens.** `cmd_rotate` first calls `vault.rotate(old_password)`. That generates a new DEK and writes a complete authenticated vault with that DEK wrapped using a KEK derived from the old password. Only after the write completes does the CLI prompt for the new password and call `change_password`. The second operation preserves the DEK.

This creates a real on-disk intermediate state, with an input-dependent window that can remain open while the user types. Sync history, backup tooling, filesystem snapshots, or an observer able to retain successive vault files can capture it.

**Prerequisites and impact.** An attacker must obtain that intermediate copy, know or later crack the old password, and obtain a subsequent vault copy. The intermediate reveals the very DEK used after the password change, permitting decryption of future passwords and TOTP seeds until another DEK rotation. Knowing the old password and possessing only a pre-rotation vault is insufficient; the intermediate-copy prerequisite matters.

This is different from the documented inability to detect a complete rollback: no rollback or successful normal unlock with the old password is required.

**Reproduction evidence.**

1. Created a synthetic vault and started `rotate --new-password` with redirected password input.
2. Supplied only the old password.
3. Captured the changed vault file before supplying either new-password line.
4. Completed the password change, then saved a credential value created only afterward.
5. Unwrapped the DEK from the retained intermediate using the old password and decrypted the subsequent index and item directly.
6. Confirmed that normal `Vault::open` of the final file with the old password failed, while direct decryption of the future secret succeeded.

**Fix.** Collect and validate the replacement password first. Call the existing `Vault::rotate` with that replacement password, so the new DEK is published directly under the replacement KEK in one commit. For this CLI path, there is no need for the second `change_password` operation.

**Regression acceptance.** Pause input before the new password is supplied and assert the original disk bytes remain unchanged. After completion, assert the DEK changed and the old password fails. Retain the direct-DEK decryption probe when testing the old implementation to demonstrate the original impact.

### SEC-02 — Windows plaintext exports inherit potentially broad read permissions

**Severity:** High, conditional on destination permissions. **Status:** reproduced with an explicit inherited read grant.

**Locations:** [export file creation](../src/cli/mod.rs#L1276), lines 1276–1296. Related encrypted-vault writes also rely on inherited Windows ACLs in [atomic_write.rs](../src/vault/atomic_write.rs#L57), lines 57–73 and 89–105.

**What happens.** Plaintext exports use `OpenOptions::create_new`. The owner-only permission configuration is compiled only on Unix. There is no corresponding Windows security descriptor or ACL validation, so the plaintext file inherits the destination directory's access permissions.

**Prerequisites and impact.** A user exports to a directory with inheritable read access for another user/group, such as a shared project, team folder, or permissive custom directory. Every exported password, note, and TOTP seed is readable to those principals without the master password. This does not establish that the default private Windows profile directory is broadly readable.

The explicit plaintext-export opt-in acknowledges writing an unencrypted file; it does not constrain which local users receive access. Unix already enforces the narrower owner-only behavior.

**Reproduction evidence.** In a synthetic directory, granted the well-known Everyone SID an inheritable read ACE, exported a vault there, and inspected the resulting ACL:

~~~text
export.json Everyone:(I)(R)
            NT AUTHORITY\SYSTEM:(I)(F)
            BUILTIN\Administrators:(I)(F)
            OWNER RIGHTS:(I)(F)
~~~

The file was created successfully. The test verified the inherited ACL; it did not log in as a second Windows account.

**Fix.** Create plaintext files with a protected DACL that grants the current user and appropriate system/administrator principals access, without inheriting broad reader ACEs. Set the restriction at creation time to avoid an exposure window. Apply the same approach to any reachable plaintext editor buffers. For encrypted vault/backup files, separately decide and document the intended ACL policy.

**Regression acceptance.** Export into a fixture directory with an inheritable Everyone read grant. Assert the exported file has no effective broad read grant and that a different ordinary user cannot read it. Check restrictions before content is written.

**Platform reference:** Windows documents that default file ACLs inherit from the parent directory. [Microsoft: File Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).

### SEC-03 — Predictable replacement temp files follow links and clobber unrelated files

**Severity:** Medium. **Status:** reproduced on Windows using a hard link.

**Locations:** [temp path and replacement writer](../src/vault/atomic_write.rs#L14), lines 14–21 and 57–80; [lock opening](../src/vault/atomic_write.rs#L29), lines 29–44.

**What happens.** The replacement writer uses the predictable sibling `<vault>.latchkey-tmp` and opens it with `create(true).truncate(true)`. A pre-existing hard link or followed symbolic link makes this open operate on another file. That file is truncated before the replacement is published.

The write lock coordinates cooperating latchkey instances; it does not make a predictable pathname safe. The Unix lock-file symlink check is also separate from opening the lock, leaving a check/open race, and does not address hard links.

**Prerequisites and impact.** An attacker must be able to plant or replace directory entries in the vault/backup destination directory. Link creation and victim-target permissions must also allow the attempted operation. A private directory denies that prerequisite. Under the prerequisite, a normal vault save or backup can destroy unrelated files writable by the victim, potentially another vault. This is not an established plaintext disclosure or cryptographic forgery.

**Reproduction evidence.** Created an unrelated synthetic file and made `vault.bin.latchkey-tmp` a hard link to it. Calling the production `atomic_write(vault_path, replacement)` replaced the unrelated file's contents with `replacement`. No timing race was needed.

**Fix.** Use a random sibling temporary name with exclusive `create_new(true)`, keep the handle until the complete write is ready, and clean up only that uniquely owned file. The existing new-vault writer already demonstrates this creation pattern. Harden lock opening against symlink/reparse-point substitution using atomic platform mechanisms and require a trustworthy parent directory.

**Regression acceptance.** Pre-create temp-path hard links and symbolic links to an unrelated fixture file; the fixture must stay byte-identical. Exercise backup and normal-save callers. On Unix, test lock-path substitution at the open boundary.

**API reference:** Rust documents `create_new` as atomic and rejects existing targets, including dangling symlinks. [Rust: OpenOptions::create_new](https://doc.rust-lang.org/std/fs/struct.OpenOptions.html#method.create_new).

### SEC-04 — Overlapping clipboard copies restore an already expired secret

**Severity:** Medium. **Status:** reproduced with native Windows CLI processes.

**Locations:** [snapshot and restore](../src/clip/win32_delayed.rs#L216), lines 216–246; [owner-based restore](../src/clip/win32_delayed.rs#L162), lines 162–174. Equivalent previous-content restoration exists in [WSL](../src/clip/wsl.rs#L215), lines 215–228, and [Linux](../src/clip/unix.rs#L149), lines 149–158.

**What happens.** Each copy snapshots the preceding clipboard text and restores it at expiry if that copy still owns the clipboard. If a second latchkey process copies while a first copy is active, the second process snapshots the first secret. The first process later sees a different owner and exits. The second process then restores the first secret as ordinary static clipboard text.

Neither process remains to clear the restored secret.

**Prerequisites and impact.** Two copies overlap, for example commands in two terminals or a CLI copy while the TUI has a pending copy. No malware or forced process termination is needed. The first credential can remain available indefinitely after both advertised timeouts, exposing it to subsequent pastes or clipboard readers. The single-worker restriction within one TUI instance does not prevent another process from overlapping.

**Reproduction evidence.**

1. Copied synthetic secret A with a four-second timeout.
2. Before expiry, copied synthetic secret B in a second process with a seven-second timeout.
3. Waited for both processes to exit successfully.
4. Read the clipboard: it contained A.
5. Read again one second later: A was still present.

**Fix.** Prefer clearing the owned clipboard entry instead of restoring previous text, or implement provenance/expiry metadata across copies so an expired secret is never restored. Provenance must survive the interactions between multiple processes, not merely one TUI worker. Apply the policy consistently across backends.

**Regression acceptance.** Run two and three overlapping copies and assert that no expired latchkey secret is restored after the final worker exits. Preserve the existing test that a genuinely unrelated intervening user copy is left alone.

### SEC-05 — WSL/Linux cleanup read failures return success while leaving the secret available

**Severity:** Medium. **Status:** reproduced in the production WSL bridge with an isolated fake clipboard tool; Linux equivalent confirmed in source.

**Locations:** [WSL clipboard reads](../src/clip/wsl.rs#L153), lines 153–160 and 180–193; [WSL cleanup](../src/clip/wsl.rs#L220), lines 220–230; [Linux reads](../src/clip/unix.rs#L82), lines 82–96; [Linux cleanup](../src/clip/unix.rs#L155), lines 155–160.

**What happens.** Tool failure, unreadable clipboard contents, and an empty clipboard collapse into `None`. At expiry, that value fails the ownership comparison, so cleanup is skipped and the function returns `Ok(())`.

Skipping a write when ownership is unknown protects an intervening user copy, but returning success hides the fact that secret removal was not verified. The TUI maps successful worker completion to “clipboard cleared.”

**Prerequisites and impact.** A post-copy clipboard read fails, for example from clipboard contention or a helper failure. The copied value can remain available beyond the advertised timeout while the CLI exits successfully or the TUI reports success. This also exposes a Linux configuration gap: Wayland probing checks for `wl-copy` but not its required `wl-paste` counterpart.

**Reproduction evidence.** A fake `powershell.exe` accepted the initial set operation and recorded the base64-encoded synthetic secret. On the post-copy `Get-Clipboard` invocation it exited with an error. The real `wsl::copy_and_hold` function returned `Ok(())`, and the simulated clipboard state still contained the secret. The probe ran by itself so its temporary PATH change could not affect other tests.

This confirms the error-handling path. A live WSL clipboard-contention experiment and a live Linux desktop experiment were not performed.

**Fix.** Distinguish `Empty`, `Value`, and `ReadError`. Retry transient failures within a bounded cleanup policy. If cleanup cannot verify ownership/removal, return an error and explicitly tell the user the clipboard may still contain the secret. Keep the protection against overwriting an unrelated user's clipboard. Probe both Wayland tools before accepting a copy.

**Regression acceptance.** Inject failures into the expiry read, not just the initial copy. Assert that the command/TUI reports cleanup uncertainty and never claims clearance. Test `wl-copy` present with `wl-paste` absent.

### SEC-06 — A release build can silently enable the fuzz-only weak KDF

**Severity:** Medium. **Status:** reproduced in an optimized release binary.

**Locations:** [Cargo feature](../Cargo.toml#L54), lines 54–59; [conditional KDF defaults](../src/crypto/kdf.rs#L24), lines 24–54; [accepted minimum](../src/crypto/kdf.rs#L81), lines 81–85.

**What happens.** The `fuzz-fast-kdf` feature changes creation/rotation/password-change defaults to 8 MiB and one iteration, including optimized release builds. A comment says it is never enabled in production, but no build constraint enforces that. A normal-looking `cargo build --release --all-features` therefore produces a password manager with the fuzz KDF.

**Prerequisites and impact.** A user, distributor, or build system enables all features or explicitly enables this feature. Newly created or rotated vaults have materially weaker protection against offline password guessing. Existing vaults still derive with their stored header parameters; merely opening one does not downgrade it.

The checked-in release workflow uses the default feature set, so this is not evidence that the official release configuration currently enables the weak feature.

**Reproduction evidence.**

~~~powershell
cargo build --release --locked --offline --all-features
~~~

With `LATCHKEY_FAST_KDF` absent, the resulting release binary created a vault whose header specified `m=8 MiB, t=1, p=1`. A subsequent ordinary release build was restored and verified to create `m=64 MiB, t=36, p=1` vaults.

The weak profile uses eight times less memory and 36 times fewer passes. This review did not benchmark a cracking-speed multiplier.

**Fix.** Keep fast defaults behind a dedicated fuzz-only build condition, require that condition in addition to the feature, or move the substitution into harness code so it cannot alter normal application defaults. Merely rejecting release optimization would also disrupt optimized fuzzing and is not a sufficient design. Production vault creation should enforce its creation policy independently of compatibility acceptance for old files.

**Regression acceptance.** Build the distributable binary with default features and with all ordinary public features. Each build must either reject the unsafe combination or create production-strength vaults. Separately verify that the dedicated fuzz harness can use its test parameters.

**Context:** OWASP's current general password-storage baseline recommends Argon2id with at least 19 MiB and two iterations. A password-manager KDF needs its own performance/threat assessment; that baseline is context for the reduction, not a substitute for it. [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

### SEC-07 — Revealing an imported password emits terminal control sequences

**Severity:** Medium. **Status:** literal control-byte output reproduced; terminal-specific effects were not actively executed.

**Locations:** [secret reveal](../src/cli/mod.rs#L636), lines 636–650; [terminal escaping exclusion](../src/cli/terminal.rs#L5), lines 5–6; [existing raw-output expectation](../tests/cli_security.rs#L148), lines 148–154.

**What happens.** Metadata is escaped at terminal boundaries, but `get --reveal` prints the secret directly after validating only UTF-8. Imported passwords may contain ESC, carriage return, other control characters, or bidirectional formatting. Requesting to view a password therefore also sends its control sequences to the terminal.

**Prerequisites and impact.** An attacker supplies an import containing such a password and persuades the user to reveal that entry. Depending on the terminal, output can move the cursor, erase content, change presentation, or spoof subsequent displayed text. Some terminals support additional OSC operations. This review does not establish command execution, terminal-file writes, or cross-terminal clipboard access.

The `--reveal` opt-in accepts the disclosure of a password to scrollback; it does not make attacker-controlled display commands safe.

**Reproduction evidence.** Imported a synthetic password containing the JSON escape `\u001b[2J` followed by a marker. Captured `get --reveal --quiet` output in a pipe and confirmed it began with literal `0x1b 0x5b 0x32 0x4a`. No live display-clear sequence was emitted to the reviewer's terminal. An existing integration test also deliberately expects an unescaped ESC sequence in password output.

**Fix.** Separate terminal presentation from byte-exact extraction. Escape controls and bidi characters when stdout is a terminal. Preserve exact extraction through an explicitly documented machine-output path or non-terminal output policy. Ensure a revealed password is still useful and that escaped text is visibly identified.

**Regression acceptance.** Use a pseudo-terminal to reveal imported ESC/CR/bidi passwords and assert safe presentation. Independently verify that the machine-output path preserves the original bytes.

**Platform reference:** [Microsoft: Console Virtual Terminal Sequences](https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences) documents cursor and display control through output sequences.

### SEC-08 — Windows clipboard copy silently truncates passwords containing NUL

**Severity:** Low. **Status:** actual import and native clipboard copy reproduced.

**Locations:** [native secret parsing](../src/cli/import.rs#L626), lines 626–630; [UTF-16 conversion](../src/clip/win32.rs#L116), lines 116–118; [NUL-terminated clipboard rendering](../src/clip/win32.rs#L123), lines 123–137; [byte-exact claim](CLI_REFERENCE.md#latchkey-get-title), lines 105–109.

**What happens.** Native JSON imports can store `"prefix\u0000suffix"` as a password. The Windows backend converts the whole value to UTF-16 and exposes it as `CF_UNICODETEXT`. Readers treat the embedded NUL as the end of the string, so the paste contains only `prefix`. The copy operation still succeeds.

Additionally, invalid UTF-8 supplied through the public Rust record API is converted lossily by both native Windows and WSL encoders. The documented byte-exact clipboard promise cannot hold for those values.

**Impact.** The user receives a different credential from the one stored, potentially causing failed authentication or inconsistent downstream password use. No broader disclosure was established.

**Reproduction evidence.** Imported the NUL-bearing password, copied it through the actual native CLI, and read `CF_UNICODETEXT`. The result was `prefix` and the command exit code was zero.

**Fix.** Validate the clipboard representation before copying. Refuse embedded NUL and non-UTF-8 values on text-only backends with a specific error and accurate documentation, or provide a separate binary-safe extraction channel. Do not silently claim an exact copy.

**Regression acceptance.** Exercise NUL-bearing passwords from JSON imports and invalid UTF-8 from the Rust API. The supported representation must round-trip exactly; unsupported values must fail explicitly.

## Additional hardening and policy observations

These observations are distinct from the eight findings above. They are included so the report does not confuse already documented limitations, policy choices, and exploitable defects.

### H-01 — The master-password quality policy accepts extremely weak values

[passwords.rs](../src/cli/passwords.rs#L95), lines 95–103, checks eight characters and a small exact-match deny-list. Synthetic probes confirmed that eight spaces, `1234567890`, and `Password123!` all pass.

This matches the documented small-deny-list policy, but leaves the primary stolen-vault threat heavily dependent on user judgment. Reject blank/whitespace-only input, expand the local common-password check, and warn about predictable choices. Consider a longer minimum and passphrase guidance without imposing arbitrary character-class rules. No arbitrary strong-password guarantee follows from length alone.

### H-02 — Several application-controlled secret copies are not wiped

Examples include:

- [json.rs](../src/json.rs#L90), lines 90–98: an intermediate `serde_json::Value` tree is dropped without wiping; the code acknowledges this.
- [export_item_json](../src/cli/mod.rs#L1328), lines 1328–1364: escaped password/notes strings, formatted JSON fragments, and encoded TOTP text use ordinary `String` allocations, despite the final export body using wiping owners.
- [TUI rendering](../src/tui/mod.rs#L989), lines 989–1019: revealed password strings and UI buffers are ordinary allocations.
- [EntryForm](../src/tui/mod.rs#L70), lines 70–78: derived `Debug` includes raw password, notes, and TOTP text. No current production logging call that emits that Debug value was found.
- [EntryPatch](../src/ops.rs#L54), lines 54–61: `Zeroize` is derived without drop wiping; an early error before fields move into a wiping record can leave unconsumed field allocations unwiped.

Use wiping ownership for application-controlled intermediates and a redacted `Debug` implementation for forms. A custom deserializer can avoid the unwiped intermediate JSON tree if the additional implementation burden is justified. These are defense-in-depth gaps; memory forensics was not performed, and the project's explicit best-effort/swap limitations still apply.

### H-03 — Notes have inconsistent secret classification

The [CLI reference](CLI_REFERENCE.md#latchkey-add-title---username-u---url-u---notes-n---generate---reveal-generated---totp---totp-alg-alg---totp-uri) allows notes as command-line values and calls them non-secret, while [edit handling](../src/cli/mod.rs#L1087), lines 1087–1103, correctly describes notes as potentially containing recovery codes or security answers.

New notes entered by that interactive edit prompt are echoed, and `--notes <value>` can place them in process arguments and shell history. Existing notes are kept out of the prompt, which is a useful protection.

Make the classification consistent. If notes are secret-bearing, provide hidden/masked input and document the exposure of explicitly supplied arguments. The editor path also writes plaintext and cannot promise cleanup of editor swap, backup, or recovery files. This is a documented input-policy trade-off, not a newly demonstrated credential leak from ordinary password prompts.

### H-04 — Backup's “not overwriting” promise uses a non-atomic existence check

[cmd_backup](../src/cli/mod.rs#L895), lines 895–903, checks `out.exists()` and then calls the general replacement writer. Another writer can create the destination after the check, allowing replacement despite the no-overwrite message. Unlike the migration/new-vault path, backup does not use the atomic no-replacement publishing primitive.

Use atomic no-replacement publication for backups. This race was confirmed by source inspection, not a dedicated CLI timing experiment. Also consider bounding backup reads, since this command uses an unbounded `std::fs::read` rather than the vault reader's size cap.

## Controls reviewed that are working as intended

- **KDF and hierarchy:** the normal release defaults were verified as Argon2id 64 MiB/t=36/p=1, with random salts and a random per-vault DEK. Header parameters are bounded before derivation. SEC-06 concerns a separate build configuration.
- **Whole-file integrity:** the format-2 HMAC covers the header and encrypted contents; verification precedes index decryption. The MAC key is derived with a distinct HKDF info string.
- **Record authenticity:** AEAD uses version/domain/item-ID associated data, and decrypted embedded IDs are checked. Historical index/frame substitutions are covered by existing tests.
- **Nonce handling:** wraps, indexes, and re-encrypted items draw fresh random nonces. A committed encryption counter limits DEK use. The documented limits on divergent backup histories remain applicable.
- **Stale writes:** full authenticated commit identity is checked rather than trusting a CRC alone. Cached-item requests reauthenticate the disk snapshot.
- **Input bounds:** normal vault reads and CLI imports are limited to 64 MiB. Field lengths and TOTP parameters are checked. JSON nesting/collection limits and import item limits exist, although the serde tree is allocated before conversion limits are enforced.
- **Secret exposure controls:** master passwords and item passwords are prompted without CLI argument values. Generated values are silent on add/edit unless explicitly revealed after commit. Secret/key Debug formatting is redacted in the principal stored types.
- **Metadata output:** list, import previews, selection, errors, and TUI metadata use terminal escaping. SEC-07 concerns the separate revealed-secret path.
- **Migration/export:** migration is explicit, verifies legacy records, preserves the source, and refuses occupied destinations. Plaintext export requires explicit flags and uses exclusive file creation.
- **Network/supply chain:** no direct socket/listener/client use was found in the application source scan. Locked dependencies, a dependency ban policy, pinned action revisions, and release provenance/checksum steps are present.

These are bounded review conclusions, not certification that every execution path or dependency is secure.

## Verification record

| Check | Result |
|---|---|
| `cargo test --locked` | Passed: **108 existing tests**, zero failures |
| `cargo audit --json` | Passed: 238 locked dependencies; **0 reported vulnerabilities**, no advisory warnings |
| RustSec snapshot used by audit | Commit `edb58f5974b83eb8302332821cb6d389777aa351`; last update `2026-10-14T22:18:32+02:00` |
| `cargo deny check` | Passed: advisories, bans, licenses, sources; non-failing duplicate-dependency/unused-license-allowance warnings |
| Four targeted Rust probes, with debug fast-KDF override | **4 passed**: rotation key retention, temp hard-link clobber, weak password policy, NUL import |
| Isolated WSL cleanup-failure Rust probe | **1 passed**, reproducing silent-success behavior |
| Actual CLI rotation with delayed replacement-password input | Intermediate file captured before new-password input |
| Actual Windows export into permissive ACL fixture | Inherited Everyone read ACE observed |
| Two actual overlapping Windows copy processes | Both exited zero; expired first secret remained |
| Actual imported control-sequence reveal | Literal ESC/display-control bytes observed in captured output |
| Actual native clipboard copy of NUL-bearing password | Truncated paste observed; exit zero |
| `cargo build --release --locked --offline --all-features` | Build succeeded; created weak 8 MiB/t=1 vault |
| Subsequent ordinary release build | Rebuilt and verified at 64 MiB/t=36/p=1 |

The primary test suite did not include the temporary probes when Cargo initially enumerated its tests. The four probes and the isolated fifth probe were run separately. A probe “pass” means the assert confirmed the issue, not that the vulnerability is fixed.

Dependency results are a point-in-time match against the stated advisory database. They are not a claim that all dependencies are vulnerability-free. The checks did not audit the separate fuzz dependency lockfile.

## Remediation order

1. **Fix SEC-01:** collect the replacement password first and rotate directly into a single final commit. Retain the intermediate-file regression test.
2. **Fix SEC-02 and SEC-03:** enforce Windows plaintext-file access at creation and use exclusive random sibling temp files for replacement writes.
3. **Fix SEC-04 and SEC-05:** define clipboard expiry consistently across overlapping operations and report unverifiable cleanup.
4. **Fix SEC-06:** prevent test KDF defaults from reaching a distributable app build and add a release-policy smoke check.
5. **Fix SEC-07 and SEC-08:** separate terminal presentation from exact extraction and validate text clipboard representation.
6. Address the policy/memory observations and update affected guarantees in the CLI reference, cryptographic specification, and threat model.

After fixes, rerun the existing suite and targeted reproductions on native Windows and WSL. Add real X11/Wayland coverage if Linux clipboard guarantees are to be strengthened.

## Appendix A — Reproducible Rust probes

The following is the complete source of the temporary `tests/security_review_probe.rs` used during this review. It uses only synthetic data. It was removed from the working tree after execution to keep the deliverable limited to this report.

To repeat the experiments, save this block at that test path. Run the first four tests with a debug-only fast-KDF override. Run the fake-PowerShell test separately because it temporarily changes PATH within its test process:

~~~powershell
$env:LATCHKEY_FAST_KDF = '1'
cargo test --locked --offline --test security_review_probe -- --skip wsl_failed_cleanup_read_is_silently_successful
cargo test --locked --offline --test security_review_probe wsl_failed_cleanup_read_is_silently_successful -- --exact --nocapture
Remove-Item Env:LATCHKEY_FAST_KDF
~~~

The fast override is for synthetic test execution; SEC-01 and SEC-03 do not depend on weak KDF parameters. The optimized all-features experiment in SEC-06 was run without that override.

~~~rust
//! Temporary, synthetic-only probes for the October 2026 security review.
use latchkey::crypto::{AeadCipher, Algorithm, Kdf, KdfParams};
use latchkey::crypto::keys::{Key32, SecretVec};
use latchkey::ops::{self, Change, EntryPatch, NewEntry};
use latchkey::vault::{atomic_write, parse, shape};
use latchkey::vault::vault_impl::{Vault, index_aad, item_aad};
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("latchkey_review_{label}_{}_{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn pw(text: &str) -> SecretVec { SecretVec::new(text.as_bytes().to_vec().into_boxed_slice()) }

#[test]
fn preexisting_temp_hardlink_clobbers_an_unrelated_file() {
    let fixture = Fixture::new("hardlink");
    let vault = fixture.0.join("vault.bin");
    let unrelated = fixture.0.join("unrelated.txt");
    std::fs::write(&unrelated, b"original unrelated data").unwrap();
    std::fs::hard_link(&unrelated, atomic_write::temp_path_for(&vault)).unwrap();
    atomic_write::atomic_write(&vault, b"synthetic replacement").unwrap();
    assert_eq!(std::fs::read(&unrelated).unwrap(), b"synthetic replacement");
}

#[test]
fn rotation_intermediate_key_decrypts_future_secrets_after_password_change() {
    let fixture = Fixture::new("rotation");
    let path = fixture.0.join("vault.bin");
    let old_password = pw("old-review-master");
    let mut vault = Vault::create(&path, &old_password, KdfParams::new(8,1,1).unwrap(), Algorithm::Aes256Gcm, Algorithm::Aes256Gcm).unwrap();
    let id = ops::add_entry(&mut vault, NewEntry { title: "review.example".into(), username: "alice".into(), password: Some(b"before rotation".to_vec()), ..Default::default() }).unwrap();
    // These are the same two calls and order used by cmd_rotate --new-password.
    vault.rotate(&old_password).unwrap();
    let intermediate = std::fs::read(&path).unwrap();
    let h = parse::parse_header(&intermediate).unwrap();
    let kek = Kdf::new(h.kdf_params()).derive(&old_password, &h.kdf_salt).unwrap();
    let wrapped: Vec<u8> = h.wrapped_dek.iter().chain(h.wrap_tag.iter()).copied().collect();
    let dek_bytes = AeadCipher::new(h.wrap_algorithm().unwrap()).decrypt_raw(&kek, &h.wrap_nonce, &wrapped, &parse::header_aad(&h)).unwrap();
    let retained_dek = Key32::from_exact(&dek_bytes).unwrap();
    vault.change_password(&pw("new-review-master")).unwrap();
    ops::update_entry(&mut vault, id, EntryPatch { password: Change::Set(b"created only AFTER password change".to_vec()), ..Default::default() }).unwrap();
    assert!(Vault::open(&path, &old_password).is_err());
    let final_bytes = std::fs::read(&path).unwrap();
    let final_header = parse::parse_header(&final_bytes).unwrap();
    let cipher = AeadCipher::new(final_header.item_algorithm().unwrap());
    let offset = parse::HEADER_LEN;
    let nonce = final_bytes[offset..offset+12].try_into().unwrap();
    let len = u32::from_be_bytes(final_bytes[offset+12..offset+16].try_into().unwrap()) as usize;
    let index_plain = cipher.decrypt_raw(&retained_dek, &nonce, &final_bytes[offset+16..offset+16+len], &index_aad(final_header.version)).unwrap();
    let index = shape::parse_index(&index_plain).unwrap();
    let entry = &index.entries[0];
    let frames = Vault::split_item_frames(&final_bytes).unwrap();
    let frame = &frames[entry.slot as usize];
    let nonce = frame[..12].try_into().unwrap();
    let plaintext = cipher.decrypt_raw(&retained_dek, &nonce, &frame[16..], &item_aad(final_header.version, entry.item_id)).unwrap();
    let (record, _) = shape::parse_item(&plaintext).unwrap();
    assert_eq!(record.password.as_deref(), Some(b"created only AFTER password change".as_slice()));
}

#[test]
fn weak_master_passwords_pass_current_quality_policy() {
    for value in ["        ", "1234567890", "Password123!"] {
        assert_eq!(latchkey::cli::passwords::check_quality(value), None);
    }
}

#[test]
fn native_import_accepts_nul_in_password() {
    let parsed = latchkey::cli::import::parse_native(r#"{"format_version":1,"items":{"1":{"title":"review","password":"prefix\u0000suffix"}}}"#).unwrap();
    assert_eq!(parsed.records[0].record.password.as_deref(), Some(b"prefix\0suffix".as_slice()));
}

#[cfg(windows)]
#[test]
fn wsl_failed_cleanup_read_is_silently_successful() {
    // Run this test alone: PATH is changed only inside this test process.
    let fixture = Fixture::new("wsl_cleanup");
    let source = fixture.0.join("shim.rs");
    let state = fixture.0.join("clipboard-state");
    std::fs::write(&source, r#"
        use std::io::Read;
        fn main() {
            let state = std::env::var_os("LATCHKEY_REVIEW_CLIP_STATE").unwrap();
            if std::env::args().any(|arg| arg.contains("Get-Clipboard")) {
                if std::path::Path::new(&state).exists() { std::process::exit(1); }
            } else {
                let mut input = String::new();
                std::io::stdin().read_to_string(&mut input).unwrap();
                std::fs::write(state, input).unwrap();
            }
        }
    "#).unwrap();
    let shim = fixture.0.join("powershell.exe");
    assert!(std::process::Command::new("rustc").arg(&source).arg("-o").arg(&shim).status().unwrap().success());
    let old_path = std::env::var_os("PATH").unwrap();
    let mut paths = vec![fixture.0.clone()];
    paths.extend(std::env::split_paths(&old_path));
    std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
    std::env::set_var("LATCHKEY_REVIEW_CLIP_STATE", &state);
    let result = latchkey::clip::wsl::copy_and_hold(b"synthetic-review-secret", 0);
    std::env::set_var("PATH", old_path);
    std::env::remove_var("LATCHKEY_REVIEW_CLIP_STATE");
    assert!(result.is_ok(), "backend reports successful cleanup despite failed verification read");
    assert!(!std::fs::read(&state).unwrap().is_empty(), "fake clipboard still holds secret");
}
~~~

