//! `rpass import --format json <file>` (CLI_REFERENCE import contract).
//!
//! Preview-and-confirm: reads the file, computes { adds, updates,
//! title-collisions }, prints them, asks interactively. `--yes` skips the
//! confirm only for pure adds with zero collisions — anything that would
//! overwrite existing secrets requires a human.
//!
//! Identity rule: `<item_id>` keys whose *title* matches a live vault entry
//! update that entry (its item_id is preserved); everything else creates a
//! new entry with a generated item_id — the file never owns identity
//! allocation.

use crate::cli::error::{CliError, Result};
use crate::json::{self, Json};
use crate::vault::shape::{ItemRecord, TotpAlgorithm, TotpSubRecord};
use crate::vault::vault_impl::Vault;

pub struct ImportArgs<'a> {
    pub format: &'a str,
    pub file: &'a std::path::Path,
    pub dry_run: bool,
    pub yes: bool,
}

pub fn run(path: &std::path::Path, a: ImportArgs<'_>) -> Result<()> {
    if a.format != "json" {
        return Err(CliError::Usage(format!(
            "unknown import format '{}' — only json exists in v1",
            a.format
        )));
    }
    let text = std::fs::read_to_string(a.file)
        .map_err(|e| CliError::Other(format!("read {}: {e}", a.file.display())))?;
    let (mut vault, _pw) = super::open_vault(path)?;
    import_into(&mut vault, &text, a.dry_run, a.yes)
}

/// Core import over an already-open vault (CLI wrapper handles the password;
/// tests call this directly so nothing prompts).
pub fn import_into(vault: &mut Vault, export_text: &str, dry_run: bool, yes: bool) -> Result<()> {
    let doc = json::parse(export_text).map_err(|e| CliError::Other(e.to_string()))?;
    let plan = build_plan(vault, &doc)?;

    // Preview (always — even with --yes, the user should see the shape).
    eprintln!(
        "import plan: {} add{}, {} update{}, {} title-collision{}",
        plan.adds.len(),
        if plan.adds.len() == 1 { "" } else { "s" },
        plan.updates.len(),
        if plan.updates.len() == 1 { "" } else { "s" },
        plan.collisions.len(),
        if plan.collisions.len() == 1 { "" } else { "s" },
    );
    for add in &plan.adds {
        eprintln!("  + {} ({})", add.title, add.username);
    }
    for upd in &plan.updates {
        eprintln!(
            "  ~ {} (id {}, {}) — secrets replaced from import",
            upd.title, upd.item_id, upd.username
        );
    }
    for c in &plan.collisions {
        eprintln!(
            "  ! '{}' exists {} times — the import's '{}' becomes an add",
            c.0, c.1, c.0
        );
    }

    if dry_run {
        eprintln!("dry run — nothing written");
        return Ok(());
    }

    // --yes only bypasses the prompt when nothing gets overwritten.
    let pure_adds = plan.updates.is_empty();
    if !(yes && pure_adds) {
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Err(CliError::Other(
                "refusing to overwrite data with no terminal to confirm on — \
                 re-run with --dry-run to inspect, or --yes for pure adds"
                    .into(),
            ));
        }
        print!("proceed? [y/N] ");
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

    apply(vault, &plan)?;
    vault.save().map_err(|e| CliError::Other(e.to_string()))?;
    println!(
        "imported: {} added, {} updated",
        plan.adds.len(),
        plan.updates.len()
    );
    Ok(())
}

// ─── plan ───────────────────────────────────────────────────────────────────

struct PlannedAdd {
    title: String,
    username: String,
    record: ItemRecord,
}

struct PlannedUpdate {
    item_id: u32,
    title: String,
    username: String,
    record: ItemRecord,
}

struct Plan {
    adds: Vec<PlannedAdd>,
    updates: Vec<PlannedUpdate>,
    /// (title, times-it-exists) for titles present 2+ times in the vault.
    collisions: Vec<(String, usize)>,
}

fn build_plan(vault: &Vault, doc: &Json) -> Result<Plan> {
    let items = doc
        .get("items")
        .and_then(|v| v.as_obj())
        .ok_or_else(|| CliError::Other("import: missing 'items' object".into()))?;

    let mut adds = Vec::new();
    let mut updates = Vec::new();
    let mut collisions = Vec::new();

    for (_file_id, value) in items {
        let title = required_str(value, "title")?;
        let username = optional_str(value, "username")?;
        let record = parse_record(value)?;

        // Identity: a title matching exactly one live vault entry updates it;
        // 0 or ≥2 matches → add (with the collision recorded for the preview).
        let live: Vec<_> = vault
            .entries
            .iter()
            .filter(|e| e.state != 0xFF && e.title == title)
            .collect();
        match live.len() {
            0 => adds.push(PlannedAdd {
                title,
                username,
                record,
            }),
            1 => updates.push(PlannedUpdate {
                item_id: live[0].item_id,
                title: live[0].title.clone(),
                username: live[0].username.clone(),
                record,
            }),
            n => {
                collisions.push((title.clone(), n));
                adds.push(PlannedAdd {
                    title,
                    username,
                    record,
                });
            }
        }
    }
    Ok(Plan {
        adds,
        updates,
        collisions,
    })
}

fn apply(vault: &mut Vault, plan: &Plan) -> Result<()> {
    for add in &plan.adds {
        vault
            .add_item(add.title.clone(), add.username.clone(), add.record.clone())
            .map_err(|e| CliError::Other(e.to_string()))?;
    }
    for upd in &plan.updates {
        let entry = vault
            .entries
            .iter()
            .find(|e| e.item_id == upd.item_id && e.state != 0xFF)
            .ok_or_else(|| CliError::Other("entry vanished mid-import".into()))?;
        let slot = entry.slot;
        // Open first so unmodified fields (created_unix) survive the update.
        vault
            .open_item(upd.item_id)
            .map_err(|e| CliError::Other(e.to_string()))?;
        let existing = vault
            .open_items
            .get(&slot)
            .ok_or_else(|| CliError::Other("item not open".into()))?;
        let mut record = upd.record.clone();
        record.created_unix = existing.created_unix;
        vault.open_items.insert(slot, record);
    }
    Ok(())
}

// ─── field decoding ─────────────────────────────────────────────────────────

fn required_str(obj: &Json, key: &str) -> Result<String> {
    obj.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| CliError::Other(format!("import: item missing string '{key}'")))
}

fn optional_str(obj: &Json, key: &str) -> Result<String> {
    match obj.get(key) {
        None | Some(Json::Null) => Ok(String::new()),
        Some(v) => v
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| CliError::Other(format!("import: '{key}' must be a string or null"))),
    }
}

fn parse_record(obj: &Json) -> Result<ItemRecord> {
    let password = match obj.get("password") {
        None | Some(Json::Null) => None,
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| CliError::Other("import: 'password' must be a string".into()))?
                .as_bytes()
                .to_vec(),
        ),
    };
    let url = optional_str(obj, "url")?;
    let notes = match obj.get("notes") {
        None | Some(Json::Null) => None,
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| CliError::Other("import: 'notes' must be a string".into()))?
                .as_bytes()
                .to_vec(),
        ),
    };
    let totp = match obj.get("totp") {
        None | Some(Json::Null) => None,
        Some(t) => Some(parse_totp(t)?),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(ItemRecord {
        password,
        url,
        notes,
        totp,
        created_unix: now,
        modified_unix: now,
    })
}

fn parse_totp(t: &Json) -> Result<TotpSubRecord> {
    let secret_b32 = t
        .get("secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CliError::Other("import: totp missing 'secret'".into()))?;
    let algorithm = match t.get("algorithm").and_then(|v| v.as_str()) {
        None => Ok(TotpAlgorithm::Sha1),
        Some("SHA1") | Some("SHA") => Ok(TotpAlgorithm::Sha1),
        Some("SHA256") => Ok(TotpAlgorithm::Sha256),
        Some("SHA512") => Ok(TotpAlgorithm::Sha512),
        Some(other) => Err(CliError::Other(format!(
            "import: unsupported totp algorithm '{other}'"
        ))),
    }?;
    let period = uint_field(t, "period", 30)?;
    let digits = uint_field(t, "digits", 6)?;

    // Same write-time validation as add/edit: the decoded secret must meet
    // the RFC 6238 length floor for the algorithm.
    let secret = crate::totp::validate_secret(secret_b32, algorithm)
        .map_err(|e| CliError::Other(e.to_string()))?;
    Ok(TotpSubRecord {
        secret,
        period,
        digits,
        algorithm,
    })
}

fn uint_field(obj: &Json, key: &str, default: u32) -> Result<u32> {
    match obj.get(key) {
        None | Some(Json::Null) => Ok(default),
        Some(v) => {
            let n = v
                .as_num()
                .ok_or_else(|| CliError::Other(format!("import: totp '{key}' must be a number")))?;
            if n < 0.0 || n.fract() != 0.0 || n > u32::MAX as f64 {
                return Err(CliError::Other(format!(
                    "import: totp '{key}' must be a non-negative integer"
                )));
            }
            Ok(n as u32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn record_decoding() {
        let doc = parse(
            r#"{"title":"t","username":"u","password":"pw","url":"https://x",
                "notes":"n","totp":{"secret":"GEZDGNBVGY3TQOJQ","period":60,"digits":8,"algorithm":"SHA1"},
                "created_unix":1,"modified_unix":2}"#,
        )
        .unwrap();
        let rec = parse_record(&doc).unwrap();
        assert_eq!(rec.password.as_deref(), Some(b"pw".as_ref()));
        assert_eq!(rec.url, "https://x");
        assert_eq!(rec.notes.as_deref(), Some(b"n".as_ref()));
        let t = rec.totp.unwrap();
        assert_eq!(t.secret.len(), 10);
        assert_eq!(t.period, 60);
        assert_eq!(t.digits, 8);

        // null optionals → empty
        let doc = parse(r#"{"title":"t"}"#).unwrap();
        let rec = parse_record(&doc).unwrap();
        assert!(rec.password.is_none());
        assert_eq!(rec.url, "");
        assert!(rec.notes.is_none());
        assert!(rec.totp.is_none());
    }

    #[test]
    fn totp_validation_rejects_short_secret_for_alg() {
        // 10 bytes is fine for SHA1 but under the SHA256 floor.
        let doc =
            parse(r#"{"secret":"GEZDGNBVGY3TQOJQ","period":30,"digits":6,"algorithm":"SHA256"}"#)
                .unwrap();
        let err = parse_totp(&doc).unwrap_err();
        assert!(err.to_string().contains("need ≥16"), "{err}");
    }

    #[test]
    fn bad_fields_rejected() {
        let doc = parse(r#"{"username": 5}"#).unwrap();
        assert!(parse_record(&doc).is_ok()); // missing title is plan-level
        let doc = parse(r#"{"title":"t","password": 5}"#).unwrap();
        assert!(parse_record(&doc).is_err());
        let doc = parse(r#"{"title":"t","totp":{"period": -1}}"#).unwrap();
        assert!(parse_record(&doc).is_err());
        let doc = parse(r#"{"title":"t","totp":{"period": 1.5}}"#).unwrap();
        assert!(parse_record(&doc).is_err());
        let doc = parse(r#"{"title":"t","totp":{"algorithm":"MD5"}}"#).unwrap();
        assert!(parse_record(&doc).is_err());
    }

    #[test]
    fn plan_rules_add_update_collision() {
        // A real (fast-KDF) vault so the identity rule is exercised for real.
        let dir = std::env::temp_dir().join(format!("rpass_imp_plan_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.bin");
        let secret = crate::crypto::kdf::SecretVec::new(b"x".to_vec().into_boxed_slice());
        let kdf = crate::crypto::kdf::KdfParams::new(8, 1, 1).unwrap();

        let mut v = {
            use crate::crypto::ciphers::Algorithm as Alg;
            let mut v = Vault::create(&path, &secret, kdf, Alg::Aes256Gcm, Alg::Aes256Gcm).unwrap();
            let rec = || ItemRecord {
                password: Some(b"old".to_vec()),
                url: String::new(),
                notes: None,
                totp: None,
                created_unix: 111,
                modified_unix: 111,
            };
            v.add_item("one.example".into(), "u1".into(), rec())
                .unwrap();
            // two same-titled items → collision territory
            v.add_item("dup".into(), "a".into(), rec()).unwrap();
            v.add_item("dup".into(), "b".into(), rec()).unwrap();
            v.save().unwrap();
            v
        };

        let doc = parse(
            r#"{"format_version":1,"items":{
                "9":  {"title":"one.example","username":"u1-new","password":"new-pw"},
                "10": {"title":"dup","username":"c","password":"pw"},
                "11": {"title":"fresh.example","username":"u","password":"pw2"}
            }}"#,
        )
        .unwrap();
        let plan = build_plan(&v, &doc).unwrap();

        // one.example matches exactly once → update
        assert_eq!(plan.updates.len(), 1);
        assert_eq!(plan.updates[0].title, "one.example");
        // dup matches twice → collision + add
        assert_eq!(plan.collisions.len(), 1);
        assert_eq!(plan.collisions[0].0, "dup");
        assert_eq!(plan.collisions[0].1, 2);
        // fresh.example matches nothing → add; plus the collided dup
        assert_eq!(plan.adds.len(), 2);

        apply(&mut v, &plan).unwrap();
        v.save().unwrap();

        // The update preserved item_id and created_unix, replaced secrets.
        let updated = v.entries.iter().find(|e| e.title == "one.example").unwrap();
        let rec = v.open_items.get(&updated.slot).unwrap();
        assert_eq!(rec.password.as_deref(), Some(b"new-pw".as_ref()));
        assert_eq!(rec.created_unix, 111);
        // The collision became a third 'dup'.
        assert_eq!(v.entries.iter().filter(|e| e.title == "dup").count(), 3);
        // next_item_id never reused a file id (9/10/11 are ignored).
        assert!(v.next_item_id >= 4);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
