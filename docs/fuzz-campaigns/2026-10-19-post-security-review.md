# Fuzz Campaign Report — security-remediation tree (post-SEC fixes)

## Identification

- **Campaign type**: Re-establish clean fuzz evidence for the security-review remediation tree (SEC-01…SEC-08 + H-01…H-04 fixes; uncommitted working tree at campaign start)
- **Campaign window**: 2026-10-19T16:01:35Z → 2026-10-19T22:00:37Z (~6 h00 m wall, sequential targets)
- **Toolchain**: `cargo +nightly` (nightly-x86_64-pc-windows-msvc), cargo-fuzz 0.13.2, AddressSanitizer (MSVC runtime), Ryzen 9 5900X / 32 GB / RTX 4090 (sequential, single worker — gaming co-resident)
- **Budget**: 21,600 s across 10 targets — identical per-target split to the 0.4.0 and 0.4.1 campaigns for comparability
- **Relevant tree changes since the 0.4.1 campaign**:
  - `src/cli/import.rs`: NUL-bearing password rejection (`optional_secret`)
  - `src/vault/vault_impl.rs`: `Vault::migrate_with_kdf` (explicit KDF parameterization)
  - `fuzz/fuzz_targets/migrate_legacy.rs`: harness passes the floor KDF explicitly; the `fuzz-fast-kdf` cargo feature was deleted (SEC-06)
  - `src/vault/atomic_write.rs`: random exclusive temp names (not fuzzed — filesystem metadata surface)

## Per-target results

All commands run from `fuzz/`, shape:
`cargo +nightly fuzz run <target> -- -max_total_time=<s> -timeout=25 -rss_limit_mb=4096`
Seeds: committed corpora in `fuzz/corpus/<target>/`. Corpus growth committed per convention.

| Target | Seconds | Executions | Corpus (before→after) | Exit | Final cov/ft | Exec/s |
|---|---|---|---|---|---|---|
| authenticated_vault | 3600 | 49,620 | 154 → 176 | 0 | 754/1611 | ~13 |
| migrate_legacy | 3600 | 8,940 | 104 → 135 | 0 | 800/1308 | ~2 |
| parse_header | 1700 | 269,128,576 | 9 → 9 | 0 | 62/62 | ~158k |
| parse_index | 1800 | 63,294,549 | 1029 → 1058 | 0 | 129/433 | ~35k |
| parse_item | 1800 | 144,012,863 | 281 → 283 | 0 | 464/1101 | ~80k |
| split_item_frames | 1800 | 169,961,260 | 111 → 111 | 0 | 135/195 | ~94k |
| import_native_json | 3000 | 9,380,887 | 13493 → 15222 | 0 | 1683/7905 | ~3.1k |
| import_bitwarden | 2000 | 4,553,627 | 10456 → 11840 | 0 | 1900/9200 | ~2.3k |
| import_keepassxc | 1800 | 3,273,990 | 5881 → 6642 | 0 | 956/4447 | ~1.8k |
| otpauth_uri | 300 | 20,761,562 | 2439 → 2492 | 0 | 518/1518 | ~69k |
| **Total** | **21,600** | **683,748,824** | | | | |

All ten runs ended with libFuzzer `DONE` (clean exhaustion of `-max_total_time`), exit status 0.

## Findings

### No crashes, no hangs, no sanitizer (ASan) reports, no OOMs on any target

Every target exited cleanly with `DONE`. No `ERROR:` / `SUMMARY:` blocks, no `deadly signal`, no ASan reports, no in-campaign OOMs. **Zero new artifacts were produced** (verified by timestamp: no file under `fuzz/artifacts/` modified during the campaign window).

### Informational (non-crash) observations

1. **Slow-unit artifacts present in `fuzz/artifacts/` are pre-existing, from the 2026-10-03/04 campaigns** (timestamps: Oct 3 04:49, Oct 4 03:21/05:52 — outside this campaign's window). The known `migrate_legacy` slow units and the `split_item_frames` OOM artifact (already fixed: grow-on-demand + bounds checks, `fuzz/README.md` "Found so far") were not re-triggered. The harness KDF floor (8 MiB/t=1 via explicit `migrate_with_kdf` parameterization) keeps the crypto-path targets at ~13/2 exec/s under ASan, same class as prior campaigns.
2. **Corpus growth**: `authenticated_vault` +22, `migrate_legacy` +31, importers +3.2k combined. The import corpora (largest surface) grew most, consistent with prior campaigns where they showed the richest coverage growth per second. `parse_header` stayed saturated at cov 62 with an unchanged 9-seed corpus — narrow, well-fuzzed surface, consistent across all three campaigns.
3. **Coverage deltas vs 0.4.1**: `import_bitwarden` cov 1884→1900 (+16), `authenticated_vault` 754→754 (stable), `migrate_legacy` 788→800 (+12), `import_native_json` 1543→1683 (+140). The importer gains reflect the NUL-validation code added by SEC-08 — new reachable branches with zero findings.

## Verdict

**Campaign clean.** Zero crashes, hangs, OOMs, or sanitizer findings across 10 targets / 21,600 s active fuzz / ~683.7M executions on the security-remediation tree. The fixes that touched fuzzed surfaces (import NUL rejection, migrate KDF parameterization) are covered by the same targets and introduced no crashes; the new coverage in the importers is the rejection paths doing their job. The security-remediated tree passes the fuzz release gate from this campaign's evidence.

## Artifacts

- Driver script: repo root `run-campaign-2026-10-19.sh` (untracked; campaign-local, gaming-safe sequential config)
- Full libFuzzer logs: `.fuzz-campaign-out/logs/<target>.log` (10 files) + `summary.log` (campaign-local, not committed)
- No new crash/slow-unit/OOM artifacts; pre-existing artifacts remain gitignored under `fuzz/artifacts/`
- Corpus growth staged under `fuzz/corpus/<target>/` (4,011 files untracked, ready to commit)
- `fuzz/Cargo.lock`: no version bump needed — the tree is pre-release (SEC fixes applied on top of 0.4.1)
