//! Fuzz the Bitwarden JSON import adapter: unencrypted Bitwarden exports are
//! attacker-chosen files parsed before any vault mutation. Must return Ok or
//! a structured error — never panic (type dispatch, field extraction, TOTP
//! URI handling are the guards under test).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = latchkey::cli::import::parse_bitwarden(s);
    }
});
