//! Title → item resolution with the fuzzy-disambiguation rule (Q7,
//! CLI_REFERENCE `latchkey get`): titles are not unique, so a title resolves to
//! ALL live entries; several matches require interactive selection.

use crate::cli::error::{CliError, Result};
use crate::vault::shape::{IndexEntry, LIVE_STATE};
use crate::vault::vault_impl::Vault;

/// Resolve a title to one entry. Errors list similar titles (up to 3) when
/// nothing matches; interactive selection when several match.
pub fn resolve_title(vault: &Vault, title: &str, item_id: Option<u32>) -> Result<IndexEntry> {
    // --id bypasses title matching entirely (CLI_REFERENCE `latchkey get`).
    if let Some(id) = item_id {
        return vault
            .entries
            .iter()
            .find(|e| e.item_id == id && e.state == LIVE_STATE)
            .cloned()
            .ok_or_else(|| CliError::Other(format!("no live item with id {id}")));
    }

    let matches: Vec<&IndexEntry> = vault
        .entries
        .iter()
        .filter(|e| e.state == LIVE_STATE && e.title == title)
        .collect();

    match matches.len() {
        0 => Err(no_match(vault, title)),
        1 => Ok(matches[0].clone()),
        _ => interactive_select(matches),
    }
}

fn no_match(vault: &Vault, title: &str) -> CliError {
    // Rank similar titles by case-insensitive substring, then prefix.
    let mut similar: Vec<(usize, &str)> = vault
        .entries
        .iter()
        .filter(|e| e.state == LIVE_STATE)
        .map(|e| e.title.as_str())
        .filter(|t| t != &title)
        .map(|t| {
            let (tl, tt) = (t.to_lowercase(), title.to_lowercase());
            let score = if tt.contains(&tl) || tl.contains(&tt) {
                0
            } else if tl
                .chars()
                .zip(tt.chars())
                .take_while(|(a, b)| a == b)
                .count()
                >= 2
            {
                1
            } else {
                2
            };
            (score, t)
        })
        .collect();
    similar.sort_by_key(|(s, _)| *s);
    let names: Vec<&str> = similar.iter().take(3).map(|(_, t)| *t).collect();
    if names.is_empty() {
        CliError::Other(format!("no matching entry for '{title}'"))
    } else {
        CliError::Other(format!(
            "no matching entry for '{title}'; similar: {}",
            names.join(", ")
        ))
    }
}

/// Interactive picker over duplicate titles. Lists username + item_id for
/// disambiguation (CLI_REFERENCE).
fn interactive_select(matches: Vec<&IndexEntry>) -> Result<IndexEntry> {
    eprintln!("{} entries share this title — pick one:", matches.len());
    for (i, e) in matches.iter().enumerate() {
        eprintln!("  {}. {} (id {})", i + 1, e.username, e.item_id);
    }
    loop {
        let mut line = String::new();
        print!("selection [1-{}]: ", matches.len());
        use std::io::Write;
        let _ = std::io::stdout().flush();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| CliError::Other(format!("could not read selection: {e}")))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "q" {
            return Err(CliError::Cancelled);
        }
        if let Ok(n) = trimmed.parse::<usize>() {
            if (1..=matches.len()).contains(&n) {
                return Ok(matches[n - 1].clone());
            }
        }
        eprintln!("enter a number in 1..={} or q to cancel", matches.len());
    }
}

#[cfg(test)]
mod tests {

    use crate::vault::shape::{IndexEntry, LIVE_STATE};
    fn entry(id: u32, title: &str, user: &str) -> IndexEntry {
        IndexEntry {
            item_id: id,
            slot: id,
            state: LIVE_STATE,
            title: title.to_string(),
            username: user.to_string(),
        }
    }

    // resolve_title needs a Vault which needs a file; test the pure helpers by
    // extracting the match logic. `matches_for` mirrors resolve_title's filter.
    fn matches_for<'a>(entries: &'a [IndexEntry], title: &str) -> Vec<&'a IndexEntry> {
        entries
            .iter()
            .filter(|e| e.state == LIVE_STATE && e.title == title)
            .collect()
    }

    #[test]
    fn duplicate_titles_match_all() {
        let entries = vec![
            entry(1, "github.com", "alice"),
            entry(2, "github.com", "bob"),
            entry(3, "gmail.com", "carol"),
        ];
        assert_eq!(matches_for(&entries, "github.com").len(), 2);
        assert_eq!(matches_for(&entries, "gmail.com").len(), 1);
        assert_eq!(matches_for(&entries, "missing").len(), 0);
    }
}
