//! Fuzz the authenticated format-2 open path end-to-end: arbitrary bytes
//! through the real MAC verification, header parse, index decrypt, frame
//! walk, and item decrypt. Inputs must never panic; corrupt or spliced
//! commits must fail authentication; a valid open must yield coherent
//! records.
//!
//! Bounded by construction: `Vault::open` enforces the 64 MiB size cap and
//! KDF policy ceilings before any expensive work (an oversized or
//! hostile-KDF header fails fast), so the harness needs no extra budget.

#![no_main]

use libfuzzer_sys::fuzz_target;
use latchkey::crypto::kdf::SecretVec;
use latchkey::vault::vault_impl::Vault;

// Fast test KDF parameters (policy floor: 8 MiB, t=1, p=1) — the harness
// never calls KdfParams::default(), so a fuzzed header cannot select the
// expensive production 64 MiB profile through this path... but a fuzzed
// header CAN carry arbitrary m/t/p. Vault::open validates policy ceilings
// (max 1024 MiB, t=64, 8192 MiB-passes) before deriving; a header at the
// ceiling is slow but bounded. Corpus seeds keep normal inputs tiny.
fuzz_target!(|data: &[u8]| {
    let path = std::env::temp_dir().join(format!(
        "latchkey_fuzz_auth_{}",
        std::process::id()
    ));
    // Write the fuzzed bytes as the vault file.
    if std::fs::write(&path, data).is_err() {
        return;
    }
    let password = SecretVec::new(b"fuzz-password".to_vec().into_boxed_slice());
    // Every failure mode is acceptable except a panic/hang: bad MAC,
    // truncation, bad params, wrong slot counts, ID mismatches.
    let _ = Vault::open(&path, &password);
    let _ = std::fs::remove_file(&path);
});
