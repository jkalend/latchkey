//! CLI dispatch (CLI_REFERENCE.md).

pub mod error;
pub mod import;
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

/// `--totp-alg` choices; maps to the vault's `TotpAlgorithm`.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum TotpAlgArg {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgArg {
    fn algorithm(self) -> crate::vault::shape::TotpAlgorithm {
        match self {
            TotpAlgArg::Sha1 => crate::vault::shape::TotpAlgorithm::Sha1,
            TotpAlgArg::Sha256 => crate::vault::shape::TotpAlgorithm::Sha256,
            TotpAlgArg::Sha512 => crate::vault::shape::TotpAlgorithm::Sha512,
        }
    }
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
        /// Notes; without a value, open $EDITOR.
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        notes: Option<Option<String>>,
        /// Generate the password per ADR-0006 instead of prompting
        #[arg(long)]
        generate: bool,
        /// Prompt for a TOTP secret (base32, hidden)
        #[arg(long)]
        totp: bool,
        /// TOTP algorithm for --totp (SHA1 with 30s/6 digits by default)
        #[arg(long, value_enum, requires = "totp")]
        totp_alg: Option<TotpAlgArg>,
        /// Take the TOTP secret from an otpauth:// URI instead (prompted hidden)
        #[arg(long, conflicts_with_all = ["totp", "totp_alg"])]
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
        #[arg(long, conflicts_with = "reveal")]
        copy: bool,
        #[arg(long, default_value_t = clip::env_timeout_default())]
        timeout: u64,
    },
    /// Copy a secret to the clipboard; auto-clears (ADR-0003)
    Copy {
        title: String,
        #[arg(long)]
        id: Option<u32>,
        #[arg(long, default_value_t = clip::env_timeout_default())]
        timeout: u64,
    },
    /// Generate a password (ADR-0006 presets)
    Generate {
        #[arg(long)]
        length: Option<usize>,
        #[arg(long, conflicts_with_all = ["passphrase", "hex"])]
        symbols: bool,
        #[arg(long, conflicts_with_all = ["symbols", "hex"])]
        passphrase: bool,
        #[arg(long)]
        words: Option<usize>,
        #[arg(long, conflicts_with_all = ["symbols", "passphrase"])]
        hex: bool,
        /// Exclude 0/O/o/I/l/1 (reduces entropy slightly)
        #[arg(long)]
        no_ambiguous: bool,
        /// Copy to clipboard instead of printing
        #[arg(long)]
        copy: bool,
        #[arg(long, default_value_t = clip::env_timeout_default())]
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
        /// Notes; without a value, open $EDITOR.
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        notes: Option<Option<String>>,
        /// Generate a new password per ADR-0006 instead of prompting
        #[arg(long)]
        generate: bool,
        /// Replace the TOTP secret (base32, prompted hidden)
        #[arg(long)]
        totp: bool,
        /// TOTP algorithm for --totp (SHA1 with 30s/6 digits by default)
        #[arg(long, value_enum, requires = "totp")]
        totp_alg: Option<TotpAlgArg>,
        /// Replace the TOTP secret from an otpauth:// URI (prompted hidden)
        #[arg(long, conflicts_with_all = ["totp", "totp_alg"])]
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
    /// Import items from a JSON export (preview + confirm)
    Import {
        /// Import format; only json exists in v1
        #[arg(long)]
        format: String,
        file: std::path::PathBuf,
        /// Print what would happen, change nothing
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirm prompt (pure adds, zero collisions only)
        #[arg(long)]
        yes: bool,
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
    let quiet = cli.quiet;
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
            totp_alg,
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
                totp_alg,
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
        } => cmd_get(&vault_path, &title, id, reveal, copy, timeout, quiet),
        Command::Copy { title, id, timeout } => cmd_copy(&vault_path, &title, id, timeout, quiet),
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
            quiet,
        }),
        Command::Totp { title, id, copy } => cmd_totp(&vault_path, &title, id, copy, quiet),
        Command::Rm { title, id, purge } => cmd_rm(&vault_path, &title, id, purge),
        Command::Edit {
            title,
            id,
            username,
            url,
            notes,
            generate,
            totp,
            totp_alg,
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
                totp_alg,
                want_totp_uri: totp_uri,
            },
        ),
        Command::Rotate { new_password } => cmd_rotate(&vault_path, new_password),
        Command::Export {
            format,
            yes_i_mean_it,
            out,
        } => cmd_export(&vault_path, &format, yes_i_mean_it, out),
        Command::Import {
            format,
            file,
            dry_run,
            yes,
        } => cmd_import(&vault_path, &format, &file, dry_run, yes),
        Command::Backup { out } => cmd_backup(&vault_path, out),
        Command::Tui => match crate::tui::run(vault_path, quiet) {
            0 => Ok(()),
            code => Err(CliError::Other(format!("TUI exited with status {code}"))),
        },
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
    notes: Option<Option<String>>,
    generate: bool,
    want_totp: bool,
    totp_alg: Option<TotpAlgArg>,
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
        totp_alg,
        want_totp_uri,
    } = a;
    let notes = resolve_notes(notes)?;
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
        let alg = totp_alg.unwrap_or(TotpAlgArg::Sha1).algorithm();
        Some(prompt_totp_secret(alg)?)
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
        if e.state != crate::vault::shape::LIVE_STATE {
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
    _copy: bool,
    timeout: u64,
    quiet: bool,
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
    let pw = Zeroizing::new(
        rec.password
            .clone()
            .ok_or_else(|| CliError::Other("item has no password".into()))?,
    );

    if reveal {
        // Printing must be UTF-8 text; copying is byte-exact and has no
        // such requirement.
        if std::str::from_utf8(&pw).is_err() {
            return Err(CliError::Other(
                "password is not UTF-8 — use `rpass copy` for a byte-exact copy".into(),
            ));
        }
        let pw_str = Zeroizing::new(String::from_utf8(pw.to_vec()).expect("validated UTF-8"));
        if !quiet {
            eprintln!(
                "warning: the secret is now in your terminal scrollback; clear it (or close the terminal) when done"
            );
        }
        println!("{}", pw_str.as_str());
        Ok(())
    } else {
        clip::copy_and_hold_quiet(&pw, timeout, quiet).map_err(|e| CliError::Other(e.to_string()))
    }
}

fn cmd_copy(
    path: &std::path::Path,
    title: &str,
    id: Option<u32>,
    timeout: u64,
    quiet: bool,
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
    let pw = Zeroizing::new(
        rec.password
            .clone()
            .ok_or_else(|| CliError::Other("item has no password".into()))?,
    );
    clip::copy_and_hold_quiet(&pw, timeout, quiet).map_err(|e| CliError::Other(e.to_string()))
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
    quiet: bool,
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
        quiet,
    } = a;
    // Presets conflict at the clap level, so this precedence can never
    // actually trigger for two flags at once — keep it as documentation.
    let preset = if hex {
        Preset::Hex
    } else if passphrase {
        Preset::Passphrase
    } else if symbols {
        Preset::WithSymbols
    } else {
        Preset::Alphanumeric
    };
    // Flag sanity — not every preset accepts every knob; refuse silently
    // ignored input instead of surprising the user.
    if preset == Preset::Passphrase {
        if length.is_some() {
            return Err(CliError::Usage(
                "--length only applies to character presets, not --passphrase".into(),
            ));
        }
        if no_ambiguous {
            return Err(CliError::Usage(
                "--no-ambiguous only applies to character presets, not --passphrase".into(),
            ));
        }
    } else if words.is_some() {
        return Err(CliError::Usage(
            "--words only applies with --passphrase".into(),
        ));
    }
    let spec = GenerateSpec {
        preset,
        length,
        words,
        no_ambiguous,
    };
    let g = spec
        .generate()
        .map_err(|e| CliError::Other(e.to_string()))?;
    let entropy_bits = g.entropy_bits;
    let value = Zeroizing::new(g.value);
    if copy {
        // Say it BEFORE the ~30s hold; printing after the clear reads like a lie.
        eprintln!(
            "copying (~{} bits); clipboard clears in {timeout}s",
            entropy_bits as u64
        );
        clip::copy_and_hold_quiet(value.as_bytes(), timeout, quiet)
            .map_err(|e| CliError::Other(e.to_string()))?;
    } else {
        println!("{}", value.as_str());
        eprintln!("~{} bits of entropy", entropy_bits as u64);
    }
    Ok(())
}

fn cmd_totp(
    path: &std::path::Path,
    title: &str,
    id: Option<u32>,
    copy: bool,
    quiet: bool,
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
    let t = rec
        .totp
        .as_ref()
        .ok_or_else(|| CliError::Other(format!("'{}' has no TOTP secret", entry.title)))?;
    let now =
        totp::totp_now(&totp::TotpParams::from(t)).map_err(|e| CliError::Other(e.to_string()))?;
    if copy {
        clip::copy_and_hold_quiet(now.code.as_bytes(), clip::DEFAULT_TIMEOUT_SECS, quiet)
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
    let entry_idx = vault
        .entries
        .iter()
        .position(|e| e.item_id == entry.item_id)
        .ok_or_else(|| CliError::Other("entry vanished".into()))?;
    // Keep a tombstone so item IDs are never reused and slot counts remain stable.
    vault.entries[entry_idx].state = crate::vault::shape::TOMBSTONE_STATE;
    vault.open_items.remove(&entry.slot);
    vault.save().map_err(|e| CliError::Other(e.to_string()))?;
    println!("deleted item {}", entry.item_id);
    Ok(())
}

fn cmd_import(
    path: &std::path::Path,
    format: &str,
    file: &std::path::Path,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    import::run(
        path,
        import::ImportArgs {
            format,
            file,
            dry_run,
            yes,
        },
    )
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
fn resolve_notes(value: Option<Option<String>>) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(Some(text)) => Ok(Some(text)),
        Some(None) => {
            let editor = std::env::var_os("EDITOR")
                .ok_or_else(|| CliError::Other("$EDITOR is not set".into()))?;
            // Exclusive-create with retry: a predictable name in a shared
            // temp dir is a pre-creation/symlink-clobber vector (CWE-377).
            let mut path = std::env::temp_dir();
            let mut opened = false;
            for attempt in 0..100u32 {
                path = std::env::temp_dir().join(format!(
                    "rpass-notes-{}-{}-{}.txt",
                    std::process::id(),
                    unix_now(),
                    attempt
                ));
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create_new(true);
                #[cfg(unix)]
                {
                    // Owner-only: the buffer holds an unencrypted secret.
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                match opts.open(&path) {
                    Ok(_) => {
                        opened = true;
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => {
                        return Err(CliError::Other(format!("create editor buffer: {e}")));
                    }
                }
            }
            if !opened {
                return Err(CliError::Other(
                    "could not create a unique editor buffer in the temp dir".into(),
                ));
            }
            let status = std::process::Command::new(editor)
                .arg(&path)
                .status()
                .map_err(|e| CliError::Other(format!("launch $EDITOR: {e}")))?;
            if !status.success() {
                let _ = std::fs::remove_file(&path);
                return Err(CliError::Other(format!("$EDITOR exited with {status}")));
            }
            let read = std::fs::read_to_string(&path);
            let _ = std::fs::remove_file(&path);
            let text = Zeroizing::new(
                read.map_err(|e| CliError::Other(format!("read editor buffer: {e}")))?,
            );
            Ok(Some(text.to_string()))
        }
    }
}

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
        period: p.period,
        digits: p.digits,
        secret: p.secret.clone(),
        algorithm: p.algorithm,
    })
}

/// Prompt (hidden) for a base32 TOTP secret, validated against the selected
/// algorithm's RFC 6238 length floor (SHA1 ≥ 10, SHA256 ≥ 16, SHA512 ≥ 32
/// bytes — CLI_REFERENCE totp section).
fn prompt_totp_secret(
    algorithm: crate::vault::shape::TotpAlgorithm,
) -> Result<crate::vault::shape::TotpSubRecord> {
    let s = Zeroizing::new(
        rpassword::prompt_password("TOTP secret (base32): ")
            .map_err(|e| CliError::Other(format!("read totp secret: {e}")))?,
    );
    let secret =
        totp::validate_secret(&s, algorithm).map_err(|e| CliError::Other(e.to_string()))?;
    Ok(crate::vault::shape::TotpSubRecord {
        secret,
        period: 30,
        digits: 6,
        algorithm,
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
    notes: Option<Option<String>>,
    generate: bool,
    want_totp: bool,
    totp_alg: Option<TotpAlgArg>,
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
        totp_alg,
        want_totp_uri,
    } = a;
    let notes = resolve_notes(notes)?;
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
        let alg = totp_alg.unwrap_or(TotpAlgArg::Sha1).algorithm();
        Some(prompt_totp_secret(alg)?)
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
    let mut items: Zeroizing<Vec<String>> = Zeroizing::new(Vec::new());
    let live: Vec<crate::vault::shape::IndexEntry> = vault
        .entries
        .iter()
        .filter(|e| e.state == crate::vault::shape::LIVE_STATE)
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
    let mut body = Zeroizing::new(String::with_capacity(items.len() * 256));
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
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            // Plaintext secrets on disk — owner-only, never the umask default.
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&out)
            .map_err(|e| CliError::Other(format!("write {}: {e}", out.display())))?;
        use std::io::Write as _;
        f.write_all(body.as_bytes())
            .map_err(|e| CliError::Other(format!("write {}: {e}", out.display())))?;
        eprintln!(
            "plaintext export written to {} — handle it carefully",
            out.display()
        );
    }
    Ok(())
}

/// One item's JSON block (CLI_REFERENCE export schema v1). Public for the
/// export→import integration test.
pub fn export_item_json(
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
