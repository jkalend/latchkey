//! Fuzz the on-disk frame walker: arbitrary "vault-shaped" bytes must split
//! into frames or error — never panic, never index out of bounds. The walker
//! is what untrusted files (a USB stick, a sync conflict) hit first.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rpass::vault::vault_impl::Vault;

fuzz_target!(|data: &[u8]| {
    let _ = Vault::split_item_frames(data);
});
