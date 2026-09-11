//! Master-password prompting and quality checks (THREAT_MODEL §5.1).

use rpassword::prompt_password;
use zeroize::Zeroizing;

use crate::cli::error::{CliError, Result};

/// Small embedded deny-list of hopeless passwords (THREAT_MODEL §5.1 —
/// "not a network API"). Checked case-insensitively on `rpass init`.
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
    "rpass",
    "correcthorsebatterystaple",
];

const MIN_LEN: usize = 8;

/// Prompt once (for unlock). Returns a zeroized buffer.
pub fn prompt_master() -> Result<Zeroizing<Vec<u8>>> {
    let pw = prompt_password("Master password: ")
        .map_err(|e| CliError::Other(format!("could not read password: {e}")))?;
    Ok(Zeroizing::new(pw.into_bytes()))
}

/// Prompt twice and check they match; refuse empty, short, or deny-listed
/// passwords (CLI_REFERENCE `rpass init`).
pub fn prompt_new_master() -> Result<Zeroizing<Vec<u8>>> {
    loop {
        let a = prompt_password("New master password: ")
            .map_err(|e| CliError::Other(format!("could not read password: {e}")))?;
        let b = prompt_password("Repeat master password: ")
            .map_err(|e| CliError::Other(format!("could not read password: {e}")))?;

        if a != b {
            eprintln!("passwords do not match — try again");
            continue;
        }
        if a.is_empty() {
            eprintln!("refusing an empty master password — try again");
            continue;
        }
        if let Some(err) = check_quality(&a) {
            eprintln!("{err} — try again");
            continue;
        }
        return Ok(Zeroizing::new(a.into_bytes()));
    }
}

/// Length floor + deny-list. Returns Some(complaint) on failure.
pub fn check_quality(pw: &str) -> Option<&'static str> {
    if pw.chars().count() < MIN_LEN {
        return Some("master password must be at least 8 characters");
    }
    let lower = pw.to_ascii_lowercase();
    if DENY_LIST.contains(&lower.as_str()) {
        return Some("that password is on a common-password deny-list");
    }
    None
}

/// Prompt for an item password (hidden, never a CLI argument — §5.7).
pub fn prompt_item_password() -> Result<Zeroizing<Vec<u8>>> {
    let pw = prompt_password("Password: ")
        .map_err(|e| CliError::Other(format!("could not read password: {e}")))?;
    Ok(Zeroizing::new(pw.into_bytes()))
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
