//! Fuzz the ItemRecord parser. Also exercises the serializer round-trip:
//! anything that parses must re-serialize and re-parse to the same value —
//! a serialize/parse desync here is vault corruption on the next save.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((rec, id)) = rpass::vault::shape::parse_item(data) {
        let ser = rpass::vault::shape::serialize_item(&rec, id);
        let (rec2, id2) = rpass::vault::shape::parse_item(&ser).unwrap();
        assert_eq!(id, id2);
        assert_eq!(rec, rec2);
    }
});
