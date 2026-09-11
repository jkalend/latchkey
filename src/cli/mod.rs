//! CLI dispatch (CLI_REFERENCE.md).

pub mod error;
pub mod passwords;
pub mod resolve;
pub mod vault_path;

pub use error::{CliError, ExitCode, Result};
pub use vault_path::default_vault_path;

use clap::{Parser, Subcommand};
use secrecy::SecretBox;
use zeroize::Zeroizing;

use crate::crypto::ciphers::Algorithm;
use crate::crypto::kdf::{KdfParams, SecretVec};
use crate::gen::{GenerateSpec, Preset};
use crate::vault::shape::ItemRecord;
use crate::vault::vault_impl::Vault;
use crate::{clip, totp};

#[derive(Parser)]
#[command(
    name = "rpass",
    version,
    about = "Local-first password manager — encrypted vault, no network, no telemetry",
    disable_colored_help = false
)]
pub struct Cli {
    /// Vault path override (flag > RPASS_VAULT env > platform default)
    #[arg(long, global = true, value_name = "PATH")]
    vault: Option<std::path::PathBuf>,

    /// Suppress security warnings (never errors or usability warnings)
    #[arg(short = 'q', long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault; prompts for the master password twice
    Init {
        /// Overwrite an existing vault (renames the old one to .bak.<n> first)
        #[arg(long)]
        force: bool,
    },
    /// Add a credential
    Add {
        title: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        /// Generate the password per ADR-0006 instead of prompting
        #[arg(long)]
        generate: bool,
        /// Prompt for a TOTP secret (base32, hidden)
        #[arg(long)]
        totp: bool,
    },
    /// List titles + usernames; never decrypts secrets
    List,
    /// Print a secret; requires --reveal unless copying
    Get {
        title: String,
        #[arg(long)]
        id: Option<u32>,
        /// Print to stdout (leaves the secret in terminal scrollback)
        #[arg(long)]
        reveal: bool,
        /// Copy to clipboard instead of printing (default behavior)
        #[arg(long)]
        copy: bool,
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Copy a secret to the clipboard; auto-clears (ADR-0003)
    Copy {
        title: String,
        #[arg(long)]
        id: Option<u32>,
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Generate a password (ADR-0006 presets)
    Generate {
        #[arg(long)]
        length: Option<usize>,
        #[arg(long)]
        symbols: bool,
        #[arg(long)]
        passphrase: bool,
        #[arg(long)]
        words: Option<usize>,
        #[arg(long)]
        hex: bool,
        /// Exclude 0/O/o/I/l/1 (reduces entropy slightly)
        #[arg(long)]
        no_ambiguous: bool,
        /// Copy to clipboard instead of printing
        #[arg(long)]
        copy: bool,
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Show the current TOTP code for an item
    Totp {
        title: String,
        #[arg(long)]
        id: Option<u32>,
        #[arg(long)]
        copy: bool,
    },
    /// Delete an item
    Rm {
        title: String,
        #[arg(long)]
        id: Option<u32>,
        /// Skip the confirmation prompt
        #[arg(long)]
        purge: bool,
    },
    /// Copy the vault file to a backup path (still encrypted)
    Backup {
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
    },
    /// Interactive interface (fuzzy search, detail view, copy)
    Tui,
}

/// Entry point. Returns the process exit code.
pub fn run(args: std::env::Args) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            // clap handles --help/--version exits itself (exit 0); usage errors 2.
            use clap::error::ErrorKind;
            match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    print!("{e}");
                    return ExitCode::Success as i32;
                }
                _ => {
                    eprint!("{e}");
                    return ExitCode::Usage as i32;
                }
            }
        }
    };
    match dispatch(cli) {
        Ok(()) => ExitCode::Success as i32,
        Err(e) => {
            eprintln!("rpass: {e}");
            e.exit_code()
        }
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    let vault_path = vault_path::resolve(cli.vault.as_deref());
    match cli.command {
        Command::Init { force } => cmd_init(&vault_path, force),
        Command::Add {
            title,
            username,
            url,
            generate,
            totp: want_totp,
        } => cmd_add(&vault_path, title, username, url, generate, want_totp),
        Command::List => cmd_list(&vault_path),
        Command::Get {
            title,
            id,
            reveal,
            copy,
            timeout,
        } => cmd_get(&vault_path, &title, id, reveal, copy, timeout),
        Command::Copy { title, id, timeout } => cmd_copy(&vault_path, &title, id, timeout),
        Command::Generate {
            length,
            symbols,
            passphrase,
            words,
            hex,
            no_ambiguous,
            copy,
            timeout,
        } => cmd_generate(GenerateArgs {
            length,
            symbols,
            passphrase,
            words,
            hex,
            no_ambiguous,
            copy,
            timeout,
        }),
        Command::Totp { title, id, copy } => cmd_totp(&vault_path, &title, id, copy),
        Command::Rm { title, id, purge } => cmd_rm(&vault_path, &title, id, purge),
        Command::Backup { out } => cmd_backup(&vault_path, out),
        Command::Tui => {
            crate::tui::run(vault_path);
            Ok(())
        }
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn secret_vec(v: Vec<u8>) -> SecretVec {
    SecretVec::new(v.into_boxed_slice())
}

fn open_vault(path: &std::path::Path) -> Result<(Vault, Zeroizing<Vec<u8>>)> {
    if !path.exists() {
        return Err(CliError::VaultNotFound(path.to_path_buf()));
    }
    let pw = passwords::prompt_master()?;
    let v =
        Vault::open(path, &secret_vec(pw.to_vec())).map_err(|e| CliError::Other(e.to_string()))?;
    Ok((v, pw))
}

// ─── commands ───────────────────────────────────────────────────────────────

fn cmd_init(path: &std::path::Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(CliError::Other(format!(
            "vault already exists at {} — use --force to replace it (the old file is renamed, not deleted)",
            path.display()
        )));
    }
    if path.exists() && force {
        let mut n = 1;
        let mut bak = path.with_extension(format!("bin.bak.{n}"));
        while bak.exists() {
            n += 1;
            bak = path.with_extension(format!("bin.bak.{n}"));
        }
        std::fs::rename(path, &bak)
            .map_err(|e| CliError::Other(format!("backup old vault: {e}")))?;
        eprintln!("existing vault renamed to {}", bak.display());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::Other(format!("create vault dir: {e}")))?;
    }

    let pw = passwords::prompt_new_master()?;
    let start = std::time::Instant::now();
    let vault = Vault::create(
        path,
        &secret_vec(pw.to_vec()),
        KdfParams::default(),
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Gcm,
    )
    .map_err(|e| CliError::Other(e.to_string()))?;
    let elapsed = start.elapsed();

    println!("vault created at {}", path.display());
    println!(
        "Argon2id key derivation took {:.2}s ({} MiB, t={}, p={})",
        elapsed.as_secs_f64(),
        vault.header.kdf_params.argon2_m_mib,
        vault.header.kdf_params.argon2_t,
        vault.header.kdf_params.argon2_p,
    );
    Ok(())
}

fn cmd_add(
    path: &std::path::Path,
    title: String,
    username: Option<String>,
    url: Option<String>,
    generate: bool,
    want_totp: bool,
) -> Result<()> {
    let (mut vault, _pw) = open_vault(path)?;

    let username = match username {
        Some(u) => u,
        None => {
            let mut s = String::new();
            print!("Username: ");
            use std::io::Write;
            let _ = std::io::stdout().flush();
            std::io::stdin()
                .read_line(&mut s)
                .map_err(|e| CliError::Other(format!("read username: {e}")))?;
            s.trim().to_string()
        }
    };

    let (password, generated_value) = if generate {
        let spec = GenerateSpec {
            preset: Preset::Alphanumeric,
            length: None,
            words: None,
            no_ambiguous: false,
        };
        let g = spec
            .generate()
            .map_err(|e| CliError::Other(e.to_string()))?;
        eprintln!(
            "generated password ({} bits): {}",
            g.entropy_bits as u64, g.value
        );
        (Some(g.value.clone().into_bytes()), Some(g.value))
    } else {
        (Some(passwords::prompt_item_password()?.to_vec()), None)
    };
    let _ = generated_value; // re-displayed above for --generate

    let totp_rec = if want_totp {
        let s = rpassword::prompt_password("TOTP secret (base32): ")
            .map_err(|e| CliError::Other(format!("read totp secret: {e}")))?;
        let secret = totp::validate_secret(&s, crate::vault::shape::TotpAlgorithm::Sha1)
            .map_err(|e| CliError::Other(e.to_string()))?;
        Some(crate::vault::shape::TotpSubRecord {
            secret,
            period: 30,
            digits: 6,
            algorithm: crate::vault::shape::TotpAlgorithm::Sha1,
        })
    } else {
        None
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let record = ItemRecord {
        password,
        url: url.unwrap_or_default(),
        notes: None,
        totp: totp_rec,
        created_unix: now,
        modified_unix: now,
    };
    let id = vault
        .add_item(title, username, record)
        .map_err(|e| CliError::Other(e.to_string()))?;
    vault.save().map_err(|e| CliError::Other(e.to_string()))?;
    println!("added item {id}");
    Ok(())
}

fn cmd_list(path: &std::path::Path) -> Result<()> {
    let (vault, _pw) = open_vault(path)?;
    if vault.entries.is_empty() {
        eprintln!("vault is empty — add something with `rpass add <title>`");
        return Ok(());
    }
    for e in &vault.entries {
        if e.state == 0xFF {
            continue;
        }
        println!("{:<6} {:<40} {}", e.item_id, e.title, e.username);
    }
    Ok(())
}

fn cmd_get(
    path: &std::path::Path,
    title: &str,
    id: Option<u32>,
    reveal: bool,
    copy: bool,
    timeout: u64,
) -> Result<()> {
    let (mut vault, _pw) = open_vault(path)?;
    let entry = resolve::resolve_title(&vault, title, id)?;
    vault
        .open_item(entry.item_id)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let rec = vault
        .open_items
        .get(&entry.slot)
        .ok_or_else(|| CliError::Other("item not open".into()))?;
    let pw = rec
        .password
        .clone()
        .ok_or_else(|| CliError::Other("item has no password".into()))?;
    let pw_str =
        String::from_utf8(pw).map_err(|_| CliError::Other("password is not UTF-8".into()))?;

    if reveal {
        eprintln!(
            "warning: the secret is now in your terminal scrollback; clear it (or close the terminal) when done"
        );
        println!("{pw_str}");
        Ok(())
    } else if copy {
        clip::copy_and_hold(pw_str.as_bytes(), timeout).map_err(|e| CliError::Other(e.to_string()))
    } else {
        // Default per CLI_REFERENCE `rpass get`: clipboard, not stdout.
        clip::copy_and_hold(pw_str.as_bytes(), timeout).map_err(|e| CliError::Other(e.to_string()))
    }
}

fn cmd_copy(path: &std::path::Path, title: &str, id: Option<u32>, timeout: u64) -> Result<()> {
    let (mut vault, _pw) = open_vault(path)?;
    let entry = resolve::resolve_title(&vault, title, id)?;
    vault
        .open_item(entry.item_id)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let rec = vault
        .open_items
        .get(&entry.slot)
        .ok_or_else(|| CliError::Other("item not open".into()))?;
    let pw = rec
        .password
        .clone()
        .ok_or_else(|| CliError::Other("item has no password".into()))?;
    clip::copy_and_hold(&pw, timeout).map_err(|e| CliError::Other(e.to_string()))
}

/// All `rpass generate` flags in one struct (keeps cmd_generate at one arg).
struct GenerateArgs {
    length: Option<usize>,
    symbols: bool,
    passphrase: bool,
    words: Option<usize>,
    hex: bool,
    no_ambiguous: bool,
    copy: bool,
    timeout: u64,
}

fn cmd_generate(a: GenerateArgs) -> Result<()> {
    let GenerateArgs {
        length,
        symbols,
        passphrase,
        words,
        hex,
        no_ambiguous,
        copy,
        timeout,
    } = a;
    // Mutual exclusion is not enforced by clap here — last flag wins is bad;
    // be explicit: hex > passphrase > symbols > default.
    let preset = if hex {
        Preset::Hex
    } else if passphrase {
        Preset::Passphrase
    } else if symbols {
        Preset::WithSymbols
    } else {
        Preset::Alphanumeric
    };
    let spec = GenerateSpec {
        preset,
        length,
        words,
        no_ambiguous,
    };
    let g = spec
        .generate()
        .map_err(|e| CliError::Other(e.to_string()))?;
    if copy {
        clip::copy_and_hold(g.value.as_bytes(), timeout)
            .map_err(|e| CliError::Other(e.to_string()))?;
        eprintln!(
            "copied ({} bits); clipboard clears in {timeout}s",
            g.entropy_bits as u64
        );
    } else {
        println!("{}", g.value);
        eprintln!("~{} bits of entropy", g.entropy_bits as u64);
    }
    Ok(())
}

fn cmd_totp(path: &std::path::Path, title: &str, id: Option<u32>, copy: bool) -> Result<()> {
    let (mut vault, _pw) = open_vault(path)?;
    let entry = resolve::resolve_title(&vault, title, id)?;
    vault
        .open_item(entry.item_id)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let rec = vault
        .open_items
        .get(&entry.slot)
        .ok_or_else(|| CliError::Other("item not open".into()))?;
    let t = rec
        .totp
        .as_ref()
        .ok_or_else(|| CliError::Other(format!("'{}' has no TOTP secret", entry.title)))?;
    let now =
        totp::totp_now(&totp::TotpParams::from(t)).map_err(|e| CliError::Other(e.to_string()))?;
    if copy {
        clip::copy_and_hold(now.code.as_bytes(), clip::DEFAULT_TIMEOUT_SECS)
            .map_err(|e| CliError::Other(e.to_string()))
    } else {
        println!("{} ({}s remaining)", now.code, now.remaining);
        Ok(())
    }
}

fn cmd_rm(path: &std::path::Path, title: &str, id: Option<u32>, purge: bool) -> Result<()> {
    let (mut vault, _pw) = open_vault(path)?;
    let entry = resolve::resolve_title(&vault, title, id)?;
    if !purge {
        print!(
            "delete '{}' ({}), item {}? [y/N] ",
            entry.title, entry.username, entry.item_id
        );
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| CliError::Other(format!("read confirm: {e}")))?;
        if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
            return Err(CliError::Cancelled);
        }
    }
    // Tombstone the entry and drop the item from the items region.
    let entry_idx = vault
        .entries
        .iter()
        .position(|e| e.item_id == entry.item_id)
        .ok_or_else(|| CliError::Other("entry vanished".into()))?;
    vault.entries[entry_idx].state = 0xFF;
    vault.open_items.remove(&entry.slot);

    // Compact tombstones when they exceed half the live entries (VAULT_FORMAT §5).
    let live = vault.entries.iter().filter(|e| e.state != 0xFF).count();
    let dead = vault.entries.len() - live;
    if live > 0 && dead * 2 > vault.entries.len() {
        vault.entries.retain(|e| e.state != 0xFF);
        // Renumber slots densely.
        for (i, e) in vault.entries.iter_mut().enumerate() {
            let old_slot = e.slot;
            if let Some(rec) = vault.open_items.remove(&old_slot) {
                vault.open_items.insert(i as u32, rec);
            }
            e.slot = i as u32;
        }
    }
    vault.save().map_err(|e| CliError::Other(e.to_string()))?;
    println!("deleted item {}", entry.item_id);
    Ok(())
}

fn cmd_backup(path: &std::path::Path, out: Option<std::path::PathBuf>) -> Result<()> {
    if !path.exists() {
        return Err(CliError::VaultNotFound(path.to_path_buf()));
    }
    let out = match out {
        Some(o) => o,
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let dir = path.parent().unwrap_or(std::path::Path::new("."));
            dir.join(format!("vault-backup-{ts}.bin"))
        }
    };
    if out.exists() {
        return Err(CliError::Other(format!(
            "backup path {} already exists — not overwriting",
            out.display()
        )));
    }
    let data = std::fs::read(path).map_err(|e| CliError::Other(format!("read vault: {e}")))?;
    crate::vault::atomic_write::atomic_write(&out, &data)
        .map_err(|e| CliError::Other(e.to_string()))?;
    println!("backup written to {}", out.display());
    Ok(())
}

// Keep SecretBox referenced so the import isn't dead in cfg combinations.
#[allow(unused)]
fn _secret_box_marker(_: SecretBox<[u8]>) {}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_parses() {
        use clap::CommandFactory;
        super::Cli::command().debug_assert();
    }
}
