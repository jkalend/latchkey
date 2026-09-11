//! Fuzz the index payload parser: whatever decrypts out of an index frame
//! must parse as entries or error — never panic, never loop unboundedly
//! (the count cap + string length caps are the guards under test).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rpass::vault::shape::parse_index(data);
});
