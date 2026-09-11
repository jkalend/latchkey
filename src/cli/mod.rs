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

    /// Interactive interface (fuzzy search, detail view, copy)
    #[command(subcommand)]
    command: Option<Command>,
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
        /// Notes on the command line (not classified as secrets — documented trade-off)
        #[arg(long)]
        notes: Option<String>,
        /// Generate the password per ADR-0006 instead of prompting
        #[arg(long)]
        generate: bool,
        /// Prompt for a TOTP secret (base32, hidden)
        #[arg(long)]
        totp: bool,
        /// Take the TOTP secret from an otpauth:// URI instead (prompted hidden)
        #[arg(long)]
        totp_uri: bool,
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
    /// Change username/password/notes/TOTP on an item
    Edit {
        title: String,
        #[arg(long)]
        id: Option<u32>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Generate a new password per ADR-0006 instead of prompting
        #[arg(long)]
        generate: bool,
        /// Replace the TOTP secret (base32, prompted hidden)
        #[arg(long)]
        totp: bool,
        /// Replace the TOTP secret from an otpauth:// URI (prompted hidden)
        #[arg(long)]
        totp_uri: bool,
    },
    /// Raise KDF params to current policy and rotate the DEK
    Rotate {
        /// Change the master password at the same time (prompts twice)
        #[arg(long)]
        new_password: bool,
    },
    /// Plaintext export of the vault (requires --format json + --yes-i-mean-it)
    Export {
        /// Export format; only json exists in v1
        #[arg(long)]
        format: String,
        /// The explicit opt-in flag this command requires
        #[arg(long)]
        yes_i_mean_it: bool,
        /// Write to a file instead of stdout ('-' for stdout)
        #[arg(long, value_name = "FILE")]
        out: Option<std::path::PathBuf>,
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
    // Bare `rpass` → the TUI (CLI_REFERENCE: tui is the interactive default).
    let command = cli.command.unwrap_or(Command::Tui);
    match command {
        Command::Init { force } => cmd_init(&vault_path, force),
        Command::Add {
            title,
            username,
            url,
            notes,
            generate,
            totp: want_totp,
            totp_uri,
        } => cmd_add(
            &vault_path,
            AddArgs {
                title,
                username,
                url,
                notes,
                generate,
                want_totp,
                want_totp_uri: totp_uri,
            },
        ),
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
        Command::Edit {
            title,
            id,
            username,
            url,
            notes,
            generate,
            totp,
            totp_uri,
        } => cmd_edit(
            &vault_path,
            EditArgs {
                title,
                id,
                username,
                url,
                notes,
                generate,
                want_totp: totp,
                want_totp_uri: totp_uri,
            },
        ),
        Command::Rotate { new_password } => cmd_rotate(&vault_path, new_password),
        Command::Export {
            format,
            yes_i_mean_it,
            out,
        } => cmd_export(&vault_path, &format, yes_i_mean_it, out),
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

/// All `rpass add` flags in one struct (keeps cmd_add at one arg).
struct AddArgs {
    title: String,
    username: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    generate: bool,
    want_totp: bool,
    want_totp_uri: bool,
}

fn cmd_add(path: &std::path::Path, a: AddArgs) -> Result<()> {
    let AddArgs {
        title,
        username,
        url,
        notes,
        generate,
        want_totp,
        want_totp_uri,
    } = a;
    let (mut vault, _pw) = open_vault(path)?;

    let username = match username {
        Some(u) => u,
        None => prompt_line("Username")?,
    };

    let password = if generate {
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
        Some(g.value.into_bytes())
    } else {
        Some(passwords::prompt_item_password()?.to_vec())
    };

    let totp_rec = if want_totp_uri {
        Some(prompt_totp_uri()?)
    } else if want_totp {
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

    let now = unix_now();
    let record = ItemRecord {
        password,
        url: url.unwrap_or_default(),
        notes: notes.map(|n| n.into_bytes()),
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

// ─── shared prompt helpers ──────────────────────────────────────────────────

/// Prompt for one line of (non-secret) text; empty input → empty string.
fn prompt_line(label: &str) -> Result<String> {
    print!("{label}: ");
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    std::io::stdin()
        .read_line(&mut s)
        .map_err(|e| CliError::Other(format!("read {label}: {e}")))?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

/// Prompt (hidden) for an otpauth:// URI and parse it into a sub-record.
/// The URI string is zeroized on drop.
fn prompt_totp_uri() -> Result<crate::vault::shape::TotpSubRecord> {
    let uri = Zeroizing::new(
        rpassword::prompt_password("otpauth:// URI: ")
            .map_err(|e| CliError::Other(format!("read otpauth URI: {e}")))?,
    );
    let p = totp::parse_otpauth_uri(&uri).map_err(|e| CliError::Other(e.to_string()))?;
    Ok(crate::vault::shape::TotpSubRecord {
        secret: p.secret,
        period: p.period,
        digits: p.digits,
        algorithm: p.algorithm,
    })
}

/// Prompt (hidden) for a base32 TOTP secret, SHA1 defaults.
fn prompt_totp_secret() -> Result<crate::vault::shape::TotpSubRecord> {
    let s = Zeroizing::new(
        rpassword::prompt_password("TOTP secret (base32): ")
            .map_err(|e| CliError::Other(format!("read totp secret: {e}")))?,
    );
    let secret = totp::validate_secret(&s, crate::vault::shape::TotpAlgorithm::Sha1)
        .map_err(|e| CliError::Other(e.to_string()))?;
    Ok(crate::vault::shape::TotpSubRecord {
        secret,
        period: 30,
        digits: 6,
        algorithm: crate::vault::shape::TotpAlgorithm::Sha1,
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── edit / rotate / export ─────────────────────────────────────────────────

/// Interactive single-field prompt: shows the current value, keeps it on Enter.
/// Returns Some(new value) when the user typed something, None to keep as-is.
fn edit_field(label: &str, current: &str) -> Result<Option<String>> {
    let shown = if current.is_empty() { "∅" } else { current };
    let input = prompt_line(&format!("{label} [{shown}]"))?;
    if input.is_empty() {
        Ok(None)
    } else {
        Ok(Some(input))
    }
}

/// All `rpass edit` flags in one struct (keeps cmd_edit at one arg).
struct EditArgs {
    title: String,
    id: Option<u32>,
    username: Option<String>,
    url: Option<String>,
    notes: Option<String>,
    generate: bool,
    want_totp: bool,
    want_totp_uri: bool,
}

fn cmd_edit(path: &std::path::Path, a: EditArgs) -> Result<()> {
    let EditArgs {
        title,
        id,
        username,
        url,
        notes,
        generate,
        want_totp,
        want_totp_uri,
    } = a;
    let (mut vault, _pw) = open_vault(path)?;
    let entry = resolve::resolve_title(&vault, &title, id)?;
    vault
        .open_item(entry.item_id)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let rec = vault
        .open_items
        .get(&entry.slot)
        .ok_or_else(|| CliError::Other("item not open".into()))?
        .clone();

    // Username lives in the index (title/username are the encrypted metadata).
    let new_username = match &username {
        Some(u) => Some(u.clone()),
        None => edit_field("Username", &entry.username)?,
    };
    let new_url = match &url {
        Some(u) => Some(u.clone()),
        None => edit_field("URL", &rec.url)?,
    };
    let new_notes = match &notes {
        Some(n) => Some(n.clone()),
        None => edit_field(
            "Notes",
            &String::from_utf8_lossy(rec.notes.as_deref().unwrap_or(b"")),
        )?,
    };

    let new_password = if generate {
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
        Some(g.value.into_bytes())
    } else {
        let entered = Zeroizing::new(
            rpassword::prompt_password("New password [Enter = keep current]: ")
                .map_err(|e| CliError::Other(format!("read password: {e}")))?,
        );
        if entered.is_empty() {
            None
        } else {
            Some(entered.as_bytes().to_vec())
        }
    };

    let new_totp = if want_totp_uri {
        Some(prompt_totp_uri()?)
    } else if want_totp {
        Some(prompt_totp_secret()?)
    } else {
        rec.totp.clone()
    };

    let mut updated = rec.clone();
    if let Some(u) = new_url {
        updated.url = u;
    }
    if let Some(n) = new_notes {
        updated.notes = Some(n.into_bytes());
    }
    if let Some(p) = new_password {
        updated.password = Some(p);
    }
    updated.totp = new_totp;
    updated.modified_unix = unix_now();

    if updated == rec && new_username.is_none() {
        eprintln!("nothing changed");
        return Ok(());
    }

    // Single atomic write: index (username) + item (secrets) are parts of one
    // file — there is no partial-edit split-brain mode (CLI_REFERENCE `edit`).
    if let Some(u) = new_username {
        let idx = vault
            .entries
            .iter()
            .position(|e| e.item_id == entry.item_id)
            .ok_or_else(|| CliError::Other("entry vanished".into()))?;
        vault.entries[idx].username = u;
    }
    vault.open_items.insert(entry.slot, updated);
    vault.save().map_err(|e| CliError::Other(e.to_string()))?;
    println!("updated item {}", entry.item_id);
    Ok(())
}

fn cmd_rotate(path: &std::path::Path, new_password: bool) -> Result<()> {
    let (mut vault, pw) = open_vault(path)?;
    eprintln!(
        "current KDF: {} MiB, t={}, p={}",
        vault.header.kdf_params.argon2_m_mib,
        vault.header.kdf_params.argon2_t,
        vault.header.kdf_params.argon2_p
    );
    // Rotate first (fresh DEK, current-policy KDF); then optionally re-wrap
    // under a new master password. Two atomic writes, each self-consistent.
    vault
        .rotate(&secret_vec(pw.to_vec()))
        .map_err(|e| CliError::Other(e.to_string()))?;
    if new_password {
        let np = passwords::prompt_new_master()?;
        vault
            .change_password(&secret_vec(np.to_vec()))
            .map_err(|e| CliError::Other(e.to_string()))?;
    }
    let h = &vault.header.kdf_params;
    println!(
        "rotated — KDF is now {} MiB, t={}, p={}",
        h.argon2_m_mib, h.argon2_t, h.argon2_p
    );
    Ok(())
}

fn cmd_export(
    path: &std::path::Path,
    format: &str,
    yes_i_mean_it: bool,
    out: Option<std::path::PathBuf>,
) -> Result<()> {
    if format != "json" {
        return Err(CliError::Usage(format!(
            "unknown export format '{format}' — only json exists in v1"
        )));
    }
    if !yes_i_mean_it {
        eprintln!(
            "export writes the vault in PLAINTEXT. Re-run with --yes-i-mean-it if you are sure."
        );
        return Err(CliError::Cancelled);
    }
    // Refuse stdout unless the user spelled it out (CLI_REFERENCE: never piped
    // through shell redirects that could end up in scrollback).
    let to_stdout = matches!(&out, Some(p) if p.as_os_str() == "-");
    if out.is_none() {
        return Err(CliError::Usage(
            "export writes plaintext — pass --out <file> (or --out - to force stdout)".into(),
        ));
    }

    let (mut vault, _pw) = open_vault(path)?;
    let mut items = Vec::new();
    let live: Vec<crate::vault::shape::IndexEntry> = vault
        .entries
        .iter()
        .filter(|e| e.state != 0xFF)
        .cloned()
        .collect();

    for e in &live {
        vault
            .open_item(e.item_id)
            .map_err(|er| CliError::Other(er.to_string()))?;
        let rec = vault
            .open_items
            .get(&e.slot)
            .ok_or_else(|| CliError::Other("item not open".into()))?
            .clone();
        items.push(export_item_json(e, &rec));
    }

    let now = unix_now();
    let mut body = String::with_capacity(items.len() * 256);
    body.push_str("{\n  \"format_version\": 1,\n  \"exported_at\": ");
    body.push_str(&now.to_string());
    body.push_str(",\n  \"items\": {\n");
    body.push_str(&items.join(",\n"));
    body.push_str("\n  }\n}\n");

    if to_stdout {
        use std::io::Write;
        std::io::stdout()
            .write_all(body.as_bytes())
            .map_err(|e| CliError::Other(format!("write stdout: {e}")))?;
    } else {
        let out = out.unwrap();
        if out.exists() {
            return Err(CliError::Other(format!(
                "export path {} already exists — not overwriting",
                out.display()
            )));
        }
        std::fs::write(&out, body.as_bytes())
            .map_err(|e| CliError::Other(format!("write {}: {e}", out.display())))?;
        eprintln!(
            "plaintext export written to {} — handle it carefully",
            out.display()
        );
    }
    Ok(())
}

/// One item's JSON block (CLI_REFERENCE export schema v1).
fn export_item_json(
    e: &crate::vault::shape::IndexEntry,
    rec: &crate::vault::shape::ItemRecord,
) -> String {
    fn esc(s: &str) -> String {
        // JSON string escaping for the handful of control characters that can
        // appear; non-ASCII passes through as UTF-8.
        let mut out = String::with_capacity(s.len() + 2);
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }
    let password = rec
        .password
        .as_ref()
        .map(|p| String::from_utf8_lossy(p).to_string())
        .unwrap_or_default();
    let notes = rec
        .notes
        .as_ref()
        .map(|n| String::from_utf8_lossy(n).to_string())
        .unwrap_or_default();
    let totp = rec.totp.as_ref().map(|t| {
        let alg = match t.algorithm {
            crate::vault::shape::TotpAlgorithm::Sha1 => "SHA1",
            crate::vault::shape::TotpAlgorithm::Sha256 => "SHA256",
            crate::vault::shape::TotpAlgorithm::Sha512 => "SHA512",
        };
        format!(
            "      \"secret\": \"{}\",\n      \"period\": {},\n      \"digits\": {},\n      \"algorithm\": \"{}\"",
            esc(&base32::encode(
                base32::Alphabet::Rfc4648 { padding: false },
                &t.secret
            )),
            t.period,
            t.digits,
            alg
        )
    });
    let totp_json = match totp {
        Some(t) => format!("{{\n{t}\n    }}"),
        None => "null".to_string(),
    };
    format!(
        "    \"{}\": {{\n      \"title\": \"{}\",\n      \"username\": \"{}\",\n      \"password\": \"{}\",\n      \"url\": \"{}\",\n      \"notes\": \"{}\",\n      \"totp\": {},\n      \"created_unix\": {},\n      \"modified_unix\": {}\n    }}",
        e.item_id,
        esc(&e.title),
        esc(&e.username),
        esc(&password),
        esc(&rec.url),
        esc(&notes),
        totp_json,
        rec.created_unix,
        rec.modified_unix
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_parses() {
        use clap::CommandFactory;
        super::Cli::command().debug_assert();
    }

    #[test]
    fn export_json_escapes_and_roundtrips() {
        use crate::vault::shape::{IndexEntry, ItemRecord, TotpAlgorithm, TotpSubRecord};
        let e = IndexEntry {
            item_id: 7,
            slot: 0,
            state: 1,
            title: "weird\"title\\\n".into(),
            username: "alice".into(),
        };
        let rec = ItemRecord {
            password: Some(b"p@ss\"w\\rd".to_vec()),
            url: "https://example.com".into(),
            notes: Some(b"line1\nline2".to_vec()),
            totp: Some(TotpSubRecord {
                secret: b"1234567890".to_vec(),
                period: 30,
                digits: 6,
                algorithm: TotpAlgorithm::Sha1,
            }),
            created_unix: 1,
            modified_unix: 2,
        };
        let json = super::export_item_json(&e, &rec);
        assert!(json.contains("\\\"title\\\\\\n"), "title escaped: {json}");
        assert!(json.contains("\"totp\": {"));
        assert!(json.contains("GEZDGNBVGY3TQOJQ")); // base32("1234567890")
        assert!(json.contains("\"period\": 30"));
        assert!(json.contains("line1\\nline2"));
        // The whole block parses as valid JSON.
        let wrapped = format!("{{\n  \"items\": {{\n{json}\n  }}\n}}");
        // No JSON crate on the tree (by design) — sanity checks only.
        assert!(wrapped.starts_with('{') && wrapped.ends_with('}'));
    }

    #[test]
    fn export_null_totp_and_missing_optionals() {
        use crate::vault::shape::{IndexEntry, ItemRecord};
        let e = IndexEntry {
            item_id: 1,
            slot: 0,
            state: 1,
            title: "t".into(),
            username: "u".into(),
        };
        let rec = ItemRecord {
            password: None,
            url: String::new(),
            notes: None,
            totp: None,
            created_unix: 0,
            modified_unix: 0,
        };
        let json = super::export_item_json(&e, &rec);
        assert!(json.contains("\"totp\": null"));
        assert!(json.contains("\"password\": \"\""));
        assert!(json.contains("\"notes\": \"\""));
    }
}
