//! Fuzz the otpauth:// URI parser: arbitrary strings must parse or return a
//! structured error — never panic. Percent-decoding and query splitting run
//! on attacker-shaped input here (a URI pasted from a phishing page is a
//! realistic vector).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(p) = latchkey::totp::parse_otpauth_uri(s) {
            // A parsed URI must produce a computable code.
            let _ = latchkey::totp::totp_at(&p, 59);
        }
    }
});
