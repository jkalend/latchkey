//! Fuzz the header parser: arbitrary bytes must either parse or return a
//! structured error — never panic. Covers magic, version, length checks, and
//! the KDF/algorithm id decoders.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = latchkey::vault::parse::parse_header(data);
});
