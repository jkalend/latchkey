//! Import adapters and preview/confirm planning.
//!
//! Native schema-1 JSON may update an exact single title match. External
//! Bitwarden and KeePassXC identities never become latchkey identities: every
//! external record is an addition. Every adapter fully parses and validates
//! into canonical records before the planner can mutate the vault.

use std::fs::File;
use std::io::Read;

use crate::cli::error::{CliError, Result};
use crate::json::{self, Json};
use crate::ops::{self, ImportedEntry, ImportedUpdate};
use crate::vault::shape::{ItemRecord, TotpAlgorithm, TotpSubRecord, LIVE_STATE};
use crate::vault::vault_impl::Vault;
use zeroize::Zeroizing;

#[cfg(not(test))]
const MAX_IMPORT_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(test)]
const MAX_IMPORT_BYTES: u64 = 1024 * 1024;
const MAX_IMPORT_ITEMS: usize = 10_000;
const MAX_CSV_FIELD_BYTES: usize = 1024 * 1024;

pub struct ImportArgs<'a> {
    pub format: &'a str,
    pub file: &'a std::path::Path,
    pub dry_run: bool,
    pub yes: bool,
    pub from_stdin: bool,
    pub quiet: bool,
}

pub fn run(path: &std::path::Path, a: ImportArgs<'_>) -> Result<()> {
    let text = read_import_text(a.file)?;
    let (mut vault, _pw) = super::open_vault(
        path,
        super::CommandContext {
            quiet: a.quiet,
            from_stdin: a.from_stdin,
        },
    )?;
    import_format_into_with_quiet(&mut vault, a.format, &text, a.dry_run, a.yes, a.quiet)
}

fn read_import_text(path: &std::path::Path) -> Result<Zeroizing<String>> {
    let file =
        File::open(path).map_err(|e| CliError::Other(format!("read {}: {e}", path.display())))?;
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_IMPORT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| CliError::Other(format!("read {}: {e}", path.display())))?;
    if text.len() as u64 > MAX_IMPORT_BYTES {
        return Err(CliError::Other(format!(
            "import exceeds the {} MiB size limit",
            MAX_IMPORT_BYTES / 1024 / 1024
        )));
    }
    Ok(text)
}

/// Native-import compatibility entry point used by integration tests.
pub fn import_into(vault: &mut Vault, export_text: &str, dry_run: bool, yes: bool) -> Result<()> {
    import_format_into(vault, "json", export_text, dry_run, yes)
}

/// Core import over an already-open vault. Parsing, source validation, and
/// planning all complete before the single mutation/save operation.
pub fn import_format_into(
    vault: &mut Vault,
    format: &str,
    export_text: &str,
    dry_run: bool,
    yes: bool,
) -> Result<()> {
    import_format_into_with_quiet(vault, format, export_text, dry_run, yes, false)
}

fn import_format_into_with_quiet(
    vault: &mut Vault,
    format: &str,
    export_text: &str,
    dry_run: bool,
    yes: bool,
    quiet: bool,
) -> Result<()> {
    let parsed = match format {
        "json" => parse_native(export_text)?,
        "bitwarden-json" => parse_bitwarden(export_text)?,
        "keepassxc-csv" => parse_keepassxc(export_text)?,
        other => {
            return Err(CliError::Usage(format!(
                "unknown import format '{other}' — expected json, bitwarden-json, or keepassxc-csv"
            )))
        }
    };
    let plan = build_plan(vault, parsed)?;

    if !quiet {
        eprintln!(
            "warning: '{}' is a plaintext export; secure or remove it after import",
            format
        );
    }
    eprintln!(
        "import plan: {} add{}, {} update{}, {} title-collision{}, {} unsupported/skipped field{}",
        plan.adds.len(),
        if plan.adds.len() == 1 { "" } else { "s" },
        plan.updates.len(),
        if plan.updates.len() == 1 { "" } else { "s" },
        plan.collisions.len(),
        if plan.collisions.len() == 1 { "" } else { "s" },
        plan.skipped,
        if plan.skipped == 1 { "" } else { "s" },
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
    for (title, count) in &plan.collisions {
        eprintln!(
            "  ! '{title}' collides with {count} existing/imported title{}",
            if *count == 1 { "" } else { "s" }
        );
    }

    if dry_run {
        eprintln!("dry run — nothing written");
        return Ok(());
    }

    let pure_adds = plan.updates.is_empty() && plan.collisions.is_empty();
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

    let add_count = plan.adds.len();
    let update_count = plan.updates.len();
    apply(vault, plan)?;
    println!("imported: {add_count} added, {update_count} updated");
    Ok(())
}

// ─── plan ───────────────────────────────────────────────────────────────────

struct CanonicalRecord {
    title: String,
    username: String,
    record: ItemRecord,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IdentityMode {
    Native,
    AddOnly,
}

struct ParsedImport {
    records: Vec<CanonicalRecord>,
    identity: IdentityMode,
    skipped: usize,
}

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
    collisions: Vec<(String, usize)>,
    skipped: usize,
}

fn build_plan(vault: &Vault, parsed: ParsedImport) -> Result<Plan> {
    let mut file_counts = std::collections::HashMap::<String, usize>::new();
    for record in &parsed.records {
        *file_counts.entry(record.title.clone()).or_default() += 1;
    }

    let mut adds = Vec::new();
    let mut updates = Vec::new();
    let mut collisions = Vec::new();
    let mut collided = std::collections::HashSet::<String>::new();
    let mut note_collision = |title: &str, count: usize| {
        if collided.insert(title.to_string()) {
            collisions.push((title.to_string(), count));
        }
    };

    for record in parsed.records {
        let duplicate_count = file_counts.get(&record.title).copied().unwrap_or(0);
        let live: Vec<_> = vault
            .entries
            .iter()
            .filter(|entry| entry.state == LIVE_STATE && entry.title == record.title)
            .collect();

        if parsed.identity == IdentityMode::AddOnly {
            let other_titles = live.len() + duplicate_count.saturating_sub(1);
            if other_titles > 0 {
                note_collision(&record.title, other_titles);
            }
            adds.push(PlannedAdd {
                title: record.title,
                username: record.username,
                record: record.record,
            });
            continue;
        }

        if duplicate_count > 1 {
            note_collision(&record.title, duplicate_count);
            adds.push(PlannedAdd {
                title: record.title,
                username: record.username,
                record: record.record,
            });
            continue;
        }

        match live.len() {
            0 => adds.push(PlannedAdd {
                title: record.title,
                username: record.username,
                record: record.record,
            }),
            1 => updates.push(PlannedUpdate {
                item_id: live[0].item_id,
                title: live[0].title.clone(),
                username: live[0].username.clone(),
                record: record.record,
            }),
            count => {
                note_collision(&record.title, count);
                adds.push(PlannedAdd {
                    title: record.title,
                    username: record.username,
                    record: record.record,
                });
            }
        }
    }

    Ok(Plan {
        adds,
        updates,
        collisions,
        skipped: parsed.skipped,
    })
}

fn apply(vault: &mut Vault, plan: Plan) -> Result<()> {
    let adds = plan
        .adds
        .into_iter()
        .map(|add| ImportedEntry {
            title: add.title,
            username: add.username,
            record: add.record,
        })
        .collect();
    let updates = plan
        .updates
        .into_iter()
        .map(|update| ImportedUpdate {
            item_id: update.item_id,
            record: update.record,
        })
        .collect();
    ops::apply_import(vault, adds, updates).map_err(|e| CliError::Other(e.to_string()))
}

// ─── source adapters ────────────────────────────────────────────────────────

fn parse_native(text: &str) -> Result<ParsedImport> {
    let doc = Zeroizing::new(json::parse(text).map_err(|e| CliError::Other(e.to_string()))?);
    validate_format_version(&doc)?;
    let items = doc
        .get("items")
        .and_then(Json::as_obj)
        .ok_or_else(|| CliError::Other("import: missing 'items' object".into()))?;
    enforce_item_limit(items.len())?;

    let mut records = Vec::with_capacity(items.len());
    for (index, (_id, value)) in items.iter().enumerate() {
        let parsed = (|| {
            Ok(CanonicalRecord {
                title: required_str(value, "title")?,
                username: optional_str(value, "username")?,
                record: parse_record(value)?,
            })
        })()
        .map_err(|error: CliError| record_error("json", index + 1, error))?;
        records.push(parsed);
    }
    Ok(ParsedImport {
        records,
        identity: IdentityMode::Native,
        skipped: 0,
    })
}

fn parse_bitwarden(text: &str) -> Result<ParsedImport> {
    let doc = Zeroizing::new(json::parse(text).map_err(|e| CliError::Other(e.to_string()))?);
    if matches!(doc.get("encrypted"), Some(Json::Bool(true))) {
        return Err(CliError::Other(
            "bitwarden-json: encrypted exports are not supported; export unencrypted JSON".into(),
        ));
    }
    let items = match doc.get("items") {
        Some(Json::Arr(items)) => items,
        _ => {
            return Err(CliError::Other(
                "bitwarden-json: missing 'items' array".into(),
            ))
        }
    };
    enforce_item_limit(items.len())?;

    let mut records = Vec::with_capacity(items.len());
    let mut skipped = 0;
    for (index, item) in items.iter().enumerate() {
        let parsed = parse_bitwarden_item(item, &mut skipped)
            .map_err(|error| record_error("bitwarden-json", index + 1, error))?;
        if let Some(record) = parsed {
            records.push(record);
        }
    }
    Ok(ParsedImport {
        records,
        identity: IdentityMode::AddOnly,
        skipped,
    })
}

fn parse_bitwarden_item(item: &Json, skipped: &mut usize) -> Result<Option<CanonicalRecord>> {
    let item_type = item
        .get("type")
        .and_then(Json::as_num)
        .ok_or_else(|| CliError::Other("missing numeric 'type'".into()))?;
    if item_type.fract() != 0.0 {
        return Err(CliError::Other("'type' must be an integer".into()));
    }
    let item_type = item_type as u32;
    if matches!(item_type, 3 | 4) {
        *skipped += 1;
        return Ok(None);
    }
    if !matches!(item_type, 1 | 2) {
        return Err(CliError::Other(format!(
            "unsupported Bitwarden item type {item_type}"
        )));
    }

    let title = required_str(item, "name")?;
    let notes = optional_secret(item, "notes")?;
    *skipped += json_array_len(item, "attachments")?;
    *skipped += json_array_len(item, "fields")?;

    if item_type == 2 {
        return Ok(Some(CanonicalRecord {
            title,
            username: String::new(),
            record: new_record(None, String::new(), notes, None),
        }));
    }

    let login = item
        .get("login")
        .ok_or_else(|| CliError::Other("login item is missing 'login' object".into()))?;
    login
        .as_obj()
        .ok_or_else(|| CliError::Other("'login' must be an object".into()))?;
    let username = optional_str(login, "username")?;
    let password = optional_secret(login, "password")?;
    let totp = match optional_json_str(login, "totp")? {
        Some(value) if !value.is_empty() => Some(parse_external_totp(&value)?),
        _ => None,
    };
    *skipped += json_array_len(login, "fido2Credentials")?;

    let uris = match login.get("uris") {
        None | Some(Json::Null) => &[][..],
        Some(Json::Arr(values)) => values.as_slice(),
        Some(_) => return Err(CliError::Other("'login.uris' must be an array".into())),
    };
    let mut url = String::new();
    for (uri_index, uri) in uris.iter().enumerate() {
        let value = required_str(uri, "uri")?;
        if uri_index == 0 {
            url = value;
        } else {
            *skipped += 1;
        }
    }

    Ok(Some(CanonicalRecord {
        title,
        username,
        record: new_record(password, url, notes, totp),
    }))
}

fn parse_keepassxc(text: &str) -> Result<ParsedImport> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(false)
        .from_reader(text.as_bytes());
    let headers = reader
        .headers()
        .map_err(|error| CliError::Other(format!("keepassxc-csv header: {error}")))?
        .clone();
    for required in ["Title", "Username", "Password", "URL", "Notes"] {
        if !headers.iter().any(|header| header == required) {
            return Err(CliError::Other(format!(
                "keepassxc-csv: missing '{required}' column"
            )));
        }
    }
    validate_csv_fields(&headers, "header")?;

    let mut records = Vec::new();
    let mut skipped = 0;
    for (index, row) in reader.records().enumerate() {
        if index >= MAX_IMPORT_ITEMS {
            return Err(CliError::Other(format!(
                "import has more than {MAX_IMPORT_ITEMS} items"
            )));
        }
        let row = row.map_err(|error| {
            CliError::Other(format!("keepassxc-csv record {}: {error}", index + 1))
        })?;
        validate_csv_fields(&row, &format!("record {}", index + 1))?;
        let field = |name: &str| -> &str {
            headers
                .iter()
                .position(|header| header == name)
                .and_then(|column| row.get(column))
                .unwrap_or("")
        };
        let totp = match field("TOTP") {
            "" => None,
            value => Some(
                parse_external_totp(value)
                    .map_err(|error| record_error("keepassxc-csv", index + 1, error))?,
            ),
        };
        skipped += headers
            .iter()
            .zip(row.iter())
            .filter(|(header, value)| {
                !value.is_empty()
                    && !matches!(
                        *header,
                        "Title" | "Username" | "Password" | "URL" | "Notes" | "TOTP"
                    )
            })
            .count();
        records.push(CanonicalRecord {
            title: field("Title").to_string(),
            username: field("Username").to_string(),
            record: new_record(
                nonempty_secret(field("Password")),
                field("URL").to_string(),
                nonempty_secret(field("Notes")),
                totp,
            ),
        });
    }

    Ok(ParsedImport {
        records,
        identity: IdentityMode::AddOnly,
        skipped,
    })
}

fn enforce_item_limit(count: usize) -> Result<()> {
    if count > MAX_IMPORT_ITEMS {
        return Err(CliError::Other(format!(
            "import has {count} items; maximum is {MAX_IMPORT_ITEMS}"
        )));
    }
    Ok(())
}

fn validate_csv_fields(record: &csv::StringRecord, label: &str) -> Result<()> {
    if let Some(field) = record
        .iter()
        .find(|field| field.len() > MAX_CSV_FIELD_BYTES)
    {
        return Err(CliError::Other(format!(
            "keepassxc-csv {label}: field is {} bytes; maximum is {MAX_CSV_FIELD_BYTES}",
            field.len()
        )));
    }
    Ok(())
}

fn optional_json_str(obj: &Json, key: &str) -> Result<Option<String>> {
    match obj.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .ok_or_else(|| CliError::Other(format!("'{key}' must be a string or null"))),
    }
}

fn optional_secret(obj: &Json, key: &str) -> Result<Option<Vec<u8>>> {
    Ok(optional_json_str(obj, key)?.map(|value| value.into_bytes()))
}

fn json_array_len(obj: &Json, key: &str) -> Result<usize> {
    match obj.get(key) {
        None | Some(Json::Null) => Ok(0),
        Some(Json::Arr(values)) => Ok(values.len()),
        Some(_) => Err(CliError::Other(format!("'{key}' must be an array"))),
    }
}

fn nonempty_secret(value: &str) -> Option<Vec<u8>> {
    (!value.is_empty()).then(|| value.as_bytes().to_vec())
}

fn new_record(
    password: Option<Vec<u8>>,
    url: String,
    notes: Option<Vec<u8>>,
    totp: Option<TotpSubRecord>,
) -> ItemRecord {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    ItemRecord {
        password,
        url,
        notes,
        totp,
        created_unix: now,
        modified_unix: now,
    }
}

fn parse_external_totp(value: &str) -> Result<TotpSubRecord> {
    if value.starts_with("otpauth://") {
        let mut parsed = crate::totp::parse_otpauth_uri(value)
            .map_err(|error| CliError::Other(error.to_string()))?;
        return Ok(TotpSubRecord {
            secret: std::mem::take(&mut parsed.secret),
            period: parsed.period,
            digits: parsed.digits,
            algorithm: parsed.algorithm,
        });
    }
    Ok(TotpSubRecord {
        secret: crate::totp::validate_secret(value, TotpAlgorithm::Sha1)
            .map_err(|error| CliError::Other(error.to_string()))?,
        period: 30,
        digits: 6,
        algorithm: TotpAlgorithm::Sha1,
    })
}

fn record_error(source: &str, index: usize, error: CliError) -> CliError {
    CliError::Other(format!("{source} record {index}: {error}"))
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

fn validate_format_version(doc: &Json) -> Result<()> {
    match doc.get("format_version").and_then(Json::as_num) {
        Some(1.0) => Ok(()),
        Some(version) => Err(CliError::Other(format!(
            "import: unsupported format_version {version}; expected 1"
        ))),
        None => Err(CliError::Other(
            "import: missing or invalid 'format_version'; expected 1".into(),
        )),
    }
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
    if period == 0 || !matches!(digits, 6 | 8) {
        return Err(CliError::Other(
            "import: TOTP period must be >0 and digits must be 6 or 8".into(),
        ));
    }

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
    fn oversized_import_is_rejected_before_parsing() {
        let path = std::env::temp_dir().join(format!("latchkey_import_big_{}", std::process::id()));
        let file = File::create(&path).unwrap();
        file.set_len(MAX_IMPORT_BYTES + 1).unwrap();
        drop(file);

        let err = read_import_text(&path).unwrap_err().to_string();
        assert!(err.contains("size limit"), "{err}");
        let _ = std::fs::remove_file(path);
    }

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
        let t = rec.totp.clone().unwrap();
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
    fn format_version_is_required_and_pinned() {
        assert!(validate_format_version(&parse(r#"{"format_version":1}"#).unwrap()).is_ok());
        assert!(validate_format_version(&parse(r#"{"format_version":2}"#).unwrap()).is_err());
        assert!(validate_format_version(&parse(r#"{"items":{}}"#).unwrap()).is_err());
    }

    #[test]
    fn plan_rules_add_update_collision() {
        // A real (fast-KDF) vault so the identity rule is exercised for real.
        let dir = std::env::temp_dir().join(format!("latchkey_imp_plan_{}", std::process::id()));
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

        let parsed = parse_native(
            r#"{"format_version":1,"items":{
                "9":  {"title":"one.example","username":"u1-new","password":"new-pw"},
                "10": {"title":"dup","username":"c","password":"pw"},
                "11": {"title":"fresh.example","username":"u","password":"pw2"}
            }}"#,
        )
        .unwrap();
        let plan = build_plan(&v, parsed).unwrap();

        // one.example matches exactly once → update
        assert_eq!(plan.updates.len(), 1);
        assert_eq!(plan.updates[0].title, "one.example");
        // dup matches twice → collision + add
        assert_eq!(plan.collisions.len(), 1);
        assert_eq!(plan.collisions[0].0, "dup");
        assert_eq!(plan.collisions[0].1, 2);
        // fresh.example matches nothing → add; plus the collided dup
        assert_eq!(plan.adds.len(), 2);

        apply(&mut v, plan).unwrap();

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

    /// Two same-titled items in ONE import file must never queue two updates
    /// on the same live entry (the second would silently overwrite the
    /// first). Both become adds; the collision is reported exactly once.
    #[test]
    fn plan_intra_file_duplicates_become_adds() {
        let dir = std::env::temp_dir().join(format!("latchkey_imp_dup_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v.bin");
        let secret = crate::crypto::kdf::SecretVec::new(b"x".to_vec().into_boxed_slice());
        let kdf = crate::crypto::kdf::KdfParams::new(8, 1, 1).unwrap();

        let v = {
            use crate::crypto::ciphers::Algorithm as Alg;
            let mut v = Vault::create(&path, &secret, kdf, Alg::Aes256Gcm, Alg::Aes256Gcm).unwrap();
            v.add_item(
                "solo".into(),
                "u".into(),
                ItemRecord {
                    password: Some(b"old".to_vec()),
                    url: String::new(),
                    notes: None,
                    totp: None,
                    created_unix: 1,
                    modified_unix: 1,
                },
            )
            .unwrap();
            v.save().unwrap();
            v
        };

        let parsed = parse_native(
            r#"{"format_version":1,"items":{
                "1": {"title":"solo","username":"a","password":"pw-a"},
                "2": {"title":"solo","username":"b","password":"pw-b"}
            }}"#,
        )
        .unwrap();
        let plan = build_plan(&v, parsed).unwrap();
        assert_eq!(plan.updates.len(), 0, "file duplicates must not update");
        assert_eq!(plan.adds.len(), 2);
        assert_eq!(plan.collisions.len(), 1);
        assert_eq!(plan.collisions[0], ("solo".to_string(), 2));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bitwarden_fixture_preserves_supported_fields_and_never_updates() {
        let fixture = include_str!("../../test-vectors/import/bitwarden.json");
        let parsed = parse_bitwarden(fixture).unwrap();
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.skipped, 6);
        assert_eq!(parsed.records[0].title, "Bitwarden Login");
        assert_eq!(parsed.records[0].username, "alice");
        assert_eq!(
            parsed.records[0].record.password.as_deref(),
            Some(b"correct horse".as_slice())
        );
        assert_eq!(parsed.records[0].record.url, "https://example.com");
        assert!(parsed.records[0].record.totp.is_some());
        assert_eq!(
            parsed.records[1].record.notes.as_deref(),
            Some(b"standalone note".as_slice())
        );

        let path = std::env::temp_dir().join(format!("latchkey_bw_{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let password = crate::crypto::kdf::SecretVec::new(b"x".to_vec().into_boxed_slice());
        let mut vault = Vault::create(
            &path,
            &password,
            crate::crypto::kdf::KdfParams::new(8, 1, 1).unwrap(),
            crate::crypto::ciphers::Algorithm::Aes256Gcm,
            crate::crypto::ciphers::Algorithm::Aes256Gcm,
        )
        .unwrap();
        ops::add_entry(
            &mut vault,
            crate::ops::NewEntry {
                title: "Bitwarden Login".into(),
                username: "existing".into(),
                password: None,
                url: String::new(),
                notes: None,
                totp: None,
            },
        )
        .unwrap();
        let plan = build_plan(&vault, parsed).unwrap();
        assert_eq!(plan.updates.len(), 0);
        assert_eq!(plan.adds.len(), 2);
        assert_eq!(plan.collisions.len(), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn keepassxc_fixture_handles_csv_quoting_and_reports_skipped_fields() {
        let fixture = include_str!("../../test-vectors/import/keepassxc.csv");
        let parsed = parse_keepassxc(fixture).unwrap();
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.skipped, 5);
        assert_eq!(
            parsed.records[0].record.notes.as_deref(),
            Some(b"note, with comma".as_slice())
        );
        assert_eq!(
            parsed.records[1].record.notes.as_deref(),
            Some(b"line one\nline two".as_slice())
        );
        assert!(parsed.records[0].record.totp.is_some());

        let path = std::env::temp_dir().join(format!(
            "latchkey_keepass_import_{}.bin",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let password = crate::crypto::kdf::SecretVec::new(b"x".to_vec().into_boxed_slice());
        let mut vault = Vault::create(
            &path,
            &password,
            crate::crypto::kdf::KdfParams::new(8, 1, 1).unwrap(),
            crate::crypto::ciphers::Algorithm::Aes256Gcm,
            crate::crypto::ciphers::Algorithm::Aes256Gcm,
        )
        .unwrap();
        import_format_into(&mut vault, "keepassxc-csv", fixture, false, true).unwrap();
        drop(vault);
        let mut reopened = Vault::open(&path, &password).unwrap();
        assert_eq!(reopened.entries.len(), 2);
        let item_id = reopened
            .entries
            .iter()
            .find(|entry| entry.title == "KeePassXC Login")
            .unwrap()
            .item_id;
        reopened.open_item(item_id).unwrap();
        assert!(reopened
            .open_items
            .values()
            .any(|record| record.password.as_deref() == Some(b"open-sesame".as_slice())));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn malformed_external_record_leaves_vault_unchanged() {
        let path =
            std::env::temp_dir().join(format!("latchkey_import_atomic_{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let password = crate::crypto::kdf::SecretVec::new(b"x".to_vec().into_boxed_slice());
        let mut vault = Vault::create(
            &path,
            &password,
            crate::crypto::kdf::KdfParams::new(8, 1, 1).unwrap(),
            crate::crypto::ciphers::Algorithm::Aes256Gcm,
            crate::crypto::ciphers::Algorithm::Aes256Gcm,
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        let error = import_format_into(
            &mut vault,
            "keepassxc-csv",
            include_str!("../../test-vectors/import/keepassxc-malformed.csv"),
            false,
            true,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("keepassxc-csv record 2"),
            "{error}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(vault.entries.is_empty());
        let _ = std::fs::remove_file(path);
    }
}
