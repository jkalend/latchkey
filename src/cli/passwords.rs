//! Master-password prompting and quality checks (THREAT_MODEL §5.1).

use std::io::BufRead;

use rpassword::prompt_password;
use zeroize::Zeroizing;

use crate::cli::error::{CliError, Result};

/// Small embedded deny-list of hopeless passwords (THREAT_MODEL §5.1 —
/// "not a network API"). Checked case-insensitively on `latchkey init`.
const DENY_LIST: &[&str] = &[
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwertyuiop",
    "abc123",
    "letmein",
    "welcome",
    "admin",
    "admin123",
    "iloveyou",
    "monkey",
    "dragon",
    "master",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "latchkey",
    "correcthorsebatterystaple",
];

const MIN_LEN: usize = 8;

/// Common password set beyond the hopeless list above (H-01). Not a network
/// API — a local filter for the most-predictable choices that pass the
/// length floor. Checked case-insensitively.
const WEAK_LIST: &[&str] = &[
    "1234567890",
    "11111111",
    "00000000",
    "12121212",
    "12341234",
    "123123123",
    "123456789",
    "12345678910",
    "qwerty123",
    "1q2w3e4r",
    "qazwsx",
    "zaq12wsx",
    "abcd1234",
    "abcd12345",
    "asdf1234",
    "iloveyou1",
    "letmein1",
    "welcome1",
    "password123!",
    "p@ssw0rd",
    "p@ssword1",
    "trustno1",
    "sunshine2",
    "princess1",
    "dragon123",
    "master123",
    "football1",
    "baseball1",
    "superman1",
    "batman123",
    "starwars1",
    "whatever1",
    "changeme1",
    "changeme123",
    "secret123",
    "latchkey123",
];

/// Read once for unlock. `from_stdin` is explicit because redirected standard
/// input is visible to any process that can read the producing pipe or file.
pub fn prompt_master(from_stdin: bool) -> Result<Zeroizing<Vec<u8>>> {
    read_password("Master password: ", from_stdin)
}

/// Prompt twice and check they match; refuse empty, short, or deny-listed
/// passwords (CLI_REFERENCE `latchkey init`).
pub fn prompt_new_master(from_stdin: bool) -> Result<Zeroizing<Vec<u8>>> {
    loop {
        let a = read_password("New master password: ", from_stdin)?;
        let b = read_password("Repeat master password: ", from_stdin)?;

        if *a != *b {
            eprintln!("passwords do not match — try again");
            continue;
        }
        let a_text = std::str::from_utf8(&a)
            .map_err(|_| CliError::Other("master password from stdin is not valid UTF-8".into()))?;
        if a.is_empty() {
            eprintln!("refusing an empty master password — try again");
            continue;
        }
        if let Some(err) = check_quality(a_text) {
            eprintln!("{err} — try again");
            continue;
        }
        return Ok(Zeroizing::new(a.to_vec()));
    }
}

fn read_password(prompt: &str, from_stdin: bool) -> Result<Zeroizing<Vec<u8>>> {
    if !from_stdin {
        let value = prompt_password(prompt)
            .map_err(|error| CliError::Other(format!("could not read password: {error}")))?;
        return Ok(Zeroizing::new(value.into_bytes()));
    }

    let mut value = Zeroizing::new(Vec::new());
    let count = std::io::stdin()
        .lock()
        .read_until(b'\n', &mut value)
        .map_err(|error| CliError::Other(format!("could not read password from stdin: {error}")))?;
    if count == 0 {
        return Err(CliError::Other(
            "could not read password from stdin: unexpected end of input".into(),
        ));
    }
    while matches!(value.last(), Some(b'\n' | b'\r')) {
        value.pop();
    }
    Ok(value)
}

/// Length floor + deny-list + whitespace-only rejection + weak-list warning.
/// Returns Some(complaint) on failure.
pub fn check_quality(pw: &str) -> Option<&'static str> {
    if pw.chars().count() < MIN_LEN {
        return Some("master password must be at least 8 characters");
    }
    if !pw.is_empty() && pw.trim().is_empty() {
        return Some("master password must not be all whitespace");
    }
    let lower = pw.to_ascii_lowercase();
    if DENY_LIST.contains(&lower.as_str()) {
        return Some("that password is on a common-password deny-list");
    }
    if WEAK_LIST.contains(&lower.as_str()) {
        return Some("that password is on a predictable-password deny-list");
    }
    None
}

/// Prompt for an item password (hidden, never a CLI argument — §5.7).
pub fn prompt_item_password(from_stdin: bool) -> Result<Zeroizing<Vec<u8>>> {
    read_password("Password: ", from_stdin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_check() {
        assert!(check_quality("short").is_some());
        assert!(check_quality("password123").is_some());
        assert!(check_quality("PASSWORD").is_some()); // case-insensitive deny-list
        assert!(check_quality("a-reasonable-master-pw").is_none());
    }
}
