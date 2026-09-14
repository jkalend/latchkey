//! Fuzz the native schema-1 JSON import path end-to-end: hand-rolled JSON
//! grammar + schema interpretation must return Ok or a structured error —
//! never panic (stack depth, collection caps, and field validation are the
//! guards under test).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = latchkey::cli::import::parse_native(s);
    }
});
