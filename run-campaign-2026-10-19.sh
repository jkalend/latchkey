#!/usr/bin/env bash
# Fuzz campaign driver — security-remediation tree (post SEC-01..08 fixes).
# Sequential targets, identical per-target budget to the 0.4.0/0.4.1 campaigns
# (21,600 s total) for comparability. One process at a time: gaming-safe
# (leaves 11 cores + ~28 GB RAM free; actual RSS per target is a few hundred MB).
# Stops at the first nonzero exit (crash/hang/OOM artifact lands in fuzz/artifacts/).
set -u
cd "$(dirname "$0")/fuzz"

# MSVC ASan runtime (clang_rt.asan_dynamic-x86_64.dll) must be on PATH.
export PATH="/c/Program Files (x86)/Microsoft Visual Studio/18/BuildTools/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64:$PATH"

OUT="../.fuzz-campaign-out/logs"
mkdir -p "$OUT"

# Per-target seconds — identical to docs/fuzz-campaigns/2026-10-04-latchkey-0.4.1.md
BUDGET_authenticated_vault=3600
BUDGET_migrate_legacy=3600
BUDGET_parse_header=1700
BUDGET_parse_index=1800
BUDGET_parse_item=1800
BUDGET_split_item_frames=1800
BUDGET_import_native_json=3000
BUDGET_import_bitwarden=2000
BUDGET_import_keepassxc=1800
BUDGET_otpauth_uri=300

TARGETS="authenticated_vault migrate_legacy parse_header parse_index parse_item split_item_frames import_native_json import_bitwarden import_keepassxc otpauth_uri"

overall_rc=0
for target in $TARGETS; do
  eval "budget=\$BUDGET_$target"
  echo "=== $target start $(date -u '+%Y-%m-%dT%H:%M:%SZ') budget=${budget}s ===" | tee -a "$OUT/summary.log"
  cargo +nightly fuzz run "$target" -- \
    -max_total_time="$budget" -timeout=25 -rss_limit_mb=4096 \
    > "$OUT/$target.log" 2>&1
  rc=$?
  echo "=== $target end rc=$rc $(date -u '+%Y-%m-%dT%H:%M:%SZ') ===" | tee -a "$OUT/summary.log"
  if [ "$rc" -ne 0 ]; then
    overall_rc=$rc
    echo "!!! $target FAILED (rc=$rc) — campaign aborted, artifact in fuzz/artifacts/$target/" | tee -a "$OUT/summary.log"
    break
  fi
done

echo "campaign overall_rc=$overall_rc finished $(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee -a "$OUT/summary.log"
exit "$overall_rc"
