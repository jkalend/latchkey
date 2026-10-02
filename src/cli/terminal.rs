//! Escape untrusted values at terminal-output boundaries, not in stored data.

use std::fmt::{self, Display, Write};

/// A streaming, allocation-free terminal-safe view of any displayable value.
/// Deliberately revealed secrets and machine-readable JSON must not use this.
pub struct Terminal<T>(pub T);

struct EscapedWriter<'a, W>(&'a mut W);

impl<W: Write> Write for EscapedWriter<'_, W> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut start = 0;
        for (offset, character) in text.char_indices() {
            if character.is_control()
                || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                self.0.write_str(&text[start..offset])?;
                match character {
                    '\n' => self.0.write_str("\\n")?,
                    '\r' => self.0.write_str("\\r")?,
                    '\t' => self.0.write_str("\\t")?,
                    c if (c as u32) <= 0xff => write!(self.0, "\\x{:02x}", c as u32)?,
                    c => write!(self.0, "\\u{{{:04x}}}", c as u32)?,
                }
                start = offset + character.len_utf8();
            }
        }
        self.0.write_str(&text[start..])
    }
}

impl<T: Display> Display for Terminal<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(width) = formatter.width() else {
            return write!(EscapedWriter(formatter), "{}", self.0);
        };
        // Measure only when alignment needs it; no intermediate secret-bearing
        // or metadata string allocation is required.
        let mut count = CharacterCount(0);
        write!(EscapedWriter(&mut count), "{}", self.0)?;
        let padding = width.saturating_sub(count.0);
        let before = match formatter.align() {
            Some(fmt::Alignment::Right) => padding,
            Some(fmt::Alignment::Center) => padding / 2,
            _ => 0,
        };
        let fill = formatter.fill();
        for _ in 0..before {
            formatter.write_char(fill)?;
        }
        write!(EscapedWriter(formatter), "{}", self.0)?;
        for _ in before..padding {
            formatter.write_char(fill)?;
        }
        Ok(())
    }
}

struct CharacterCount(usize);

impl Write for CharacterCount {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0 += text.chars().count();
        Ok(())
    }
}
