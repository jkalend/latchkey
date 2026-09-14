//! Fuzz the KeePassXC CSV import adapter: exported CSV is attacker-chosen
//! input parsed via the csv crate with our record/field caps. Must return Ok
//! or a structured error — never panic, never exceed the caps.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = latchkey::cli::import::parse_keepassxc(s);
    }
});
