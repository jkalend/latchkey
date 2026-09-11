//! Password generation (ADR-0006).
//!
//! - Randomness: OS CSPRNG (`getrandom`), never a userspace PRNG.
//! - Alphabet mapping: rejection sampling over u32 draws — no modulo bias.
//! - Wordlist: EFF short wordlist 2.0 (1296 words), embedded via `include_str!`,
//!   never downloaded (ADR-0005 no-network).
//!
//! Entropy floor: every preset targets ≥ 78 bits (ADR-0006 §3).

use crate::crypto::error::{Error, Result};
use std::sync::OnceLock;

pub const ALPHANUMERIC: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// 16 common safe symbols (ADR-0006 preset table: 62 + 16 = 78-char alphabet).
pub const SYMBOLS: &str = "!@#$%^&*()-_=+";
/// Characters removed by `--no-ambiguous`.
pub const AMBIGUOUS: &str = "0OoIl1|";
pub const HEX: &str = "0123456789abcdef";

pub const MIN_LEN: usize = 8;
pub const MAX_LEN: usize = 256;
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 20;

/// Default passphrase length in words. 8 × log2(1296) ≈ 82.7 bits — clears the
/// 78-bit floor. (6 words would be ~62 bits with this list; see ADR-0006
/// amendment note.)
pub const DEFAULT_WORDS: usize = 8;

const EFF_SHORT_2: &str = include_str!("eff_short_2.txt");

fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Box<[&'static str]>> = OnceLock::new();
    WORDS
        .get_or_init(|| {
            // Slices of a `&'static str` are themselves 'static — no transmute needed.
            EFF_SHORT_2
                .lines()
                .filter_map(|l| l.split('\t').nth(1))
                .collect::<Box<[&'static str]>>()
        })
        .as_ref()
}

/// Draw one unbiased index in [0, alphabet.len()) via rejection sampling on
/// a u32 CSPRNG draw (ADR-0006 §2).
fn random_index(alphabet_len: usize) -> Result<usize> {
    debug_assert!(alphabet_len > 0 && alphabet_len <= u32::MAX as usize);
    let alphabet_len = alphabet_len as u32;
    // Largest multiple of alphabet_len that fits in u32 — reject anything above.
    let limit = match alphabet_len.checked_mul(u32::MAX / alphabet_len) {
        Some(l) => l,
        None => return Err(Error::Rng("alphabet too large".into())),
    };
    let mut buf = [0u8; 4];
    loop {
        getrandom::getrandom(&mut buf).map_err(|e| Error::Rng(e.to_string()))?;
        let v = u32::from_be_bytes(buf);
        if v < limit {
            return Ok((v % alphabet_len) as usize);
        }
    }
}

fn pick(alphabet: &str, n: usize) -> Result<String> {
    let chars: Vec<char> = alphabet.chars().collect();
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        let i = random_index(chars.len())?;
        out.push(chars[i]);
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Preset {
    /// 62-char alphabet, 20 chars, ~119 bits.
    Alphanumeric,
    /// 78-char alphabet, 20 chars, ~125 bits.
    WithSymbols,
    /// EFF short 2.0, 8 words, ~83 bits.
    Passphrase,
    /// 16-char hex, 32 chars, 128 bits.
    Hex,
}

#[derive(Clone, Debug)]
pub struct GenerateSpec {
    pub preset: Preset,
    pub length: Option<usize>,
    pub words: Option<usize>,
    pub no_ambiguous: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Generated {
    pub value: String,
    /// Estimated entropy in bits.
    pub entropy_bits: f64,
}

impl GenerateSpec {
    pub fn generate(&self) -> Result<Generated> {
        match self.preset {
            Preset::Alphanumeric => self.char_based(ALPHANUMERIC, 20),
            Preset::WithSymbols => self.char_based(&format!("{ALPHANUMERIC}{SYMBOLS}"), 20),
            Preset::Hex => self.char_based(HEX, 32),
            Preset::Passphrase => {
                let words = self.words.unwrap_or(DEFAULT_WORDS);
                if !(MIN_WORDS..=MAX_WORDS).contains(&words) {
                    return Err(Error::Encrypt(format!(
                        "passphrase word count must be in [{MIN_WORDS}, {MAX_WORDS}], got {words}"
                    )));
                }
                let list = wordlist();
                let mut parts = Vec::with_capacity(words);
                for _ in 0..words {
                    let i = random_index(list.len())?;
                    parts.push(list[i]);
                }
                Ok(Generated {
                    value: parts.join("-"),
                    entropy_bits: (list.len() as f64).log2() * words as f64,
                })
            }
        }
    }

    fn char_based(&self, alphabet: &str, default_len: usize) -> Result<Generated> {
        let len = self.length.unwrap_or(default_len);
        if !(MIN_LEN..=MAX_LEN).contains(&len) {
            return Err(Error::Encrypt(format!(
                "length must be in [{MIN_LEN}, {MAX_LEN}], got {len}"
            )));
        }
        let effective: String = if self.no_ambiguous {
            alphabet
                .chars()
                .filter(|c| !AMBIGUOUS.contains(*c))
                .collect()
        } else {
            alphabet.to_string()
        };
        if effective.chars().count() < 2 {
            return Err(Error::Encrypt("alphabet reduced below 2 characters".into()));
        }
        let alphabet_size = effective.chars().count();
        let value = pick(&effective, len)?;
        Ok(Generated {
            value,
            entropy_bits: (alphabet_size as f64).log2() * len as f64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn spec(preset: Preset) -> GenerateSpec {
        GenerateSpec {
            preset,
            length: None,
            words: None,
            no_ambiguous: false,
        }
    }

    #[test]
    fn default_meets_entropy_floor() {
        let g = spec(Preset::Alphanumeric).generate().unwrap();
        assert_eq!(g.value.chars().count(), 20);
        assert!(
            g.entropy_bits > 118.0 && g.entropy_bits < 120.0,
            "{}",
            g.entropy_bits
        );
    }

    #[test]
    fn symbols_preset() {
        let g = spec(Preset::WithSymbols).generate().unwrap();
        assert_eq!(g.value.chars().count(), 20);
        // 78-char alphabet: 20 × log2(78) ≈ 125.4 bits.
        assert!((g.entropy_bits - 125.4).abs() < 0.5, "{}", g.entropy_bits);
        assert!(g
            .value
            .chars()
            .all(|c| ALPHANUMERIC.contains(c) || SYMBOLS.contains(c)));
    }

    #[test]
    fn hex_preset() {
        let g = spec(Preset::Hex).generate().unwrap();
        assert_eq!(g.value.chars().count(), 32);
        assert!(g.value.chars().all(|c| HEX.contains(c)));
        assert!((g.entropy_bits - 128.0).abs() < 0.001, "{}", g.entropy_bits);
    }

    #[test]
    fn passphrase_defaults_8_words() {
        let g = spec(Preset::Passphrase).generate().unwrap();
        assert_eq!(g.value.split('-').count(), DEFAULT_WORDS);
        assert!(g.entropy_bits > 78.0, "{}", g.entropy_bits);
    }

    #[test]
    fn passphrase_honors_words_flag() {
        let g = GenerateSpec {
            words: Some(3),
            ..spec(Preset::Passphrase)
        }
        .generate()
        .unwrap();
        assert_eq!(g.value.split('-').count(), 3);
    }

    #[test]
    fn no_ambiguous_strips_and_reduces() {
        let g = GenerateSpec {
            no_ambiguous: true,
            ..spec(Preset::Alphanumeric)
        }
        .generate()
        .unwrap();
        assert!(g.value.chars().all(|c| !AMBIGUOUS.contains(c)));
        // AMBIGUOUS has 7 chars but only 6 are in ALPHANUMERIC ('|' isn't): 62 - 6 = 56.
        assert!(
            (g.entropy_bits - 56f64.log2() * 20.0).abs() < 0.01,
            "{}",
            g.entropy_bits
        );
    }

    #[test]
    fn long_generation_spans_the_alphabet() {
        // Coupon-collector: 256 draws over 62 chars can legitimately miss ~2
        // (P ≈ 3%), so assert a floor, not exact coverage.
        let g = GenerateSpec {
            length: Some(MAX_LEN),
            ..spec(Preset::Alphanumeric)
        }
        .generate()
        .unwrap();
        let seen: HashSet<char> = g.value.chars().collect();
        assert!(
            seen.len() >= 58,
            "only {} distinct chars in 256 draws",
            seen.len()
        );
        assert!(g.value.chars().all(|c| ALPHANUMERIC.contains(c)));
    }

    #[test]
    fn length_bounds_enforced() {
        assert!(GenerateSpec {
            length: Some(7),
            ..spec(Preset::Alphanumeric)
        }
        .generate()
        .is_err());
        assert!(GenerateSpec {
            length: Some(257),
            ..spec(Preset::Alphanumeric)
        }
        .generate()
        .is_err());
        assert!(GenerateSpec {
            words: Some(2),
            ..spec(Preset::Passphrase)
        }
        .generate()
        .is_err());
        assert!(GenerateSpec {
            words: Some(21),
            ..spec(Preset::Passphrase)
        }
        .generate()
        .is_err());
    }

    #[test]
    fn wordlist_shape() {
        let list = wordlist();
        assert_eq!(list.len(), 1296);
        // EFF short 2.0 words are 4-10 chars, all lowercase a-z.
        assert!(list.iter().all(|w| !w.is_empty() && w.len() <= 10));
    }

    #[test]
    fn two_generations_differ() {
        let a = spec(Preset::Alphanumeric).generate().unwrap();
        let b = spec(Preset::Alphanumeric).generate().unwrap();
        assert_ne!(a.value, b.value);
    }
}
