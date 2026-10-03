//! Security regressions through the actual command-line output boundary.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use latchkey::crypto::ciphers::Algorithm;
use latchkey::crypto::kdf::{KdfParams, SecretVec};
use latchkey::vault::vault_impl::Vault;

struct Workspace(PathBuf);

impl Workspace {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "latchkey_cli_{name}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn password(text: &str) -> SecretVec {
    SecretVec::new(text.as_bytes().to_vec().into_boxed_slice())
}

fn cli(path: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_latchkey"))
        .arg("--vault")
        .arg(path)
        .arg("--from-stdin")
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn assert_terminal_safe(bytes: &[u8]) -> &str {
    let text = std::str::from_utf8(bytes).unwrap();
    assert!(
        !text.chars().any(|c| (c.is_control() && c != '\n')
            || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
        "unsafe terminal output: {text:?}"
    );
    text
}

#[test]
fn external_import_preview_list_and_delete_escape_metadata_without_changing_data() {
    let workspace = Workspace::new("metadata");
    let path = workspace.0.join("vault.bin");
    let master = password("cli-security-master");
    drop(
        Vault::create(
            &path,
            &master,
            KdfParams::new(8, 1, 1).unwrap(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap(),
    );
    let import_path = workspace.0.join("external.json");
    std::fs::write(&import_path, r#"{"items":[{"type":1,"name":"café 東京\u001b[2J\u0007\t\r\n\u007f\u009b\u202e\u2066spoof\u2069","login":{"username":"用户\u0000\u001b[H\u0085\u200f","password":"secret\u001b[2J","uris":[]}}]}"#).unwrap();
    let title = "café 東京\u{001b}[2J\u{0007}\t\r\n\u{007f}\u{009b}\u{202e}\u{2066}spoof\u{2069}";
    let username = "用户\0\u{001b}[H\u{0085}\u{200f}";
    let import_file = import_path.to_str().unwrap();
    let original = std::fs::read(&path).unwrap();

    let preview = cli(
        &path,
        &[
            "import",
            "--format",
            "bitwarden-json",
            import_file,
            "--dry-run",
        ],
        "cli-security-master\n",
    );
    assert!(preview.status.success(), "{:?}", preview);
    let preview_text = assert_terminal_safe(&preview.stderr);
    assert!(preview_text.contains("café 東京\\x1b[2J"));
    assert!(preview_text.contains("\\x07\\t\\r\\n\\x7f\\x9b\\u{202e}\\u{2066}spoof\\u{2069}"));
    assert!(preview_text.contains("用户\\x00\\x1b[H\\x85\\u{200f}"));
    assert_eq!(std::fs::read(&path).unwrap(), original);

    let imported = cli(
        &path,
        &["import", "--format", "bitwarden-json", import_file, "--yes"],
        "cli-security-master\n",
    );
    assert!(imported.status.success(), "{:?}", imported);
    assert_terminal_safe(&imported.stderr);
    let id = {
        let mut vault = Vault::open(&path, &master).unwrap();
        assert_eq!(vault.entries()[0].title, title);
        assert_eq!(vault.entries()[0].username, username);
        let entry = vault.entries()[0].clone();
        vault.open_item(entry.item_id).unwrap();
        assert_eq!(
            vault.open_record(entry.slot).unwrap().password.as_deref(),
            Some(b"secret\x1b[2J".as_slice())
        );
        entry.item_id.to_string()
    };

    let listing = cli(&path, &["list"], "cli-security-master\n");
    assert!(listing.status.success(), "{:?}", listing);
    let listed = assert_terminal_safe(&listing.stdout);
    assert!(listed.contains("café 東京\\x1b[2J"));
    assert!(listed.contains("用户\\x00\\x1b[H"));

    let before_cancel = std::fs::read(&path).unwrap();
    let deletion = cli(
        &path,
        &["rm", "ignored", "--id", &id],
        "cli-security-master\nn\n",
    );
    assert_eq!(deletion.status.code(), Some(4));
    let confirmation = assert_terminal_safe(&deletion.stdout);
    assert!(confirmation.contains("café 東京\\x1b[2J"));
    assert!(confirmation.contains("用户\\x00\\x1b[H"));
    assert_eq!(std::fs::read(&path).unwrap(), before_cancel);

    let reveal = cli(
        &path,
        &["get", "ignored", "--id", &id, "--reveal", "--quiet"],
        "cli-security-master\n",
    );
    assert!(reveal.status.success(), "{:?}", reveal);
    assert_eq!(reveal.stdout, b"secret\x1b[2J\n");

    let missing = cli(
        &path,
        &["get", "missing\u{001b}[H\u{202e}"],
        "cli-security-master\n",
    );
    assert_eq!(missing.status.code(), Some(1));
    let error = assert_terminal_safe(&missing.stderr);
    assert!(error.contains("missing\\x1b[H\\u{202e}"));
    assert!(error.contains("café 東京\\x1b[2J"));

    // The real duplicate chooser must not turn usernames into terminal commands.
    {
        let mut vault = Vault::open(&path, &master).unwrap();
        vault
            .add_item(
                title.into(),
                "second\u{001b}]0;spoof\u{0007}\u{2067}".into(),
                latchkey::vault::shape::ItemRecord {
                    password: Some(b"selected-second-secret".to_vec()),
                    url: String::new(),
                    notes: None,
                    totp: None,
                    created_unix: 1,
                    modified_unix: 1,
                },
            )
            .unwrap();
        vault.save().unwrap();
    }
    let chosen = cli(
        &path,
        &["get", title, "--reveal", "--quiet"],
        "cli-security-master\n2\n",
    );
    assert!(chosen.status.success(), "{:?}", chosen);
    let chooser = assert_terminal_safe(&chosen.stderr);
    assert!(chooser.contains("用户\\x00\\x1b[H"));
    assert!(chooser.contains("second\\x1b]0;spoof\\x07\\u{2067}"));
    assert!(chosen.stdout.ends_with(b"selected-second-secret\n"));

    let invalid = workspace.0.join("invalid.json");
    std::fs::write(&invalid, r#"{"format_version":1,"items":{"1":{"title":"bad","password":"private","notes":"private note","totp":{"secret":"GEZDGNBVGY3TQOJQ","algorithm":"bad\u001b[2J\u202e"}}}}"#).unwrap();
    let before_invalid = std::fs::read(&path).unwrap();
    let rejected = cli(
        &path,
        &[
            "import",
            "--format",
            "json",
            invalid.to_str().unwrap(),
            "--dry-run",
        ],
        "cli-security-master\n",
    );
    assert_eq!(rejected.status.code(), Some(1));
    assert!(assert_terminal_safe(&rejected.stderr).contains("bad\\x1b[2J\\u{202e}"));
    assert_eq!(std::fs::read(&path).unwrap(), before_invalid);
}

#[test]
fn migrate_is_explicit_preserves_source_and_refuses_existing_destinations() {
    let workspace = Workspace::new("migration");
    let source = workspace.0.join("legacy.bin");
    let target = workspace.0.join("current.bin");
    std::fs::copy("test-vectors/vault-legacy-v1.bin", &source).unwrap();
    let original = std::fs::read(&source).unwrap();
    let input = "test-vector-master-password\n";

    let legacy_open = cli(&source, &["list"], input);
    assert_eq!(legacy_open.status.code(), Some(1));
    assert!(assert_terminal_safe(&legacy_open.stderr).contains("migrate"));

    let same_path = cli(&source, &["migrate", "--out", source.to_str().unwrap()], "");
    assert_eq!(same_path.status.code(), Some(2));
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::write(&target, b"do not overwrite").unwrap();
    let occupied = cli(&source, &["migrate", "--out", target.to_str().unwrap()], "");
    assert_eq!(occupied.status.code(), Some(1));
    assert_eq!(std::fs::read(&target).unwrap(), b"do not overwrite");
    std::fs::remove_file(&target).unwrap();

    let migrated = cli(
        &source,
        &["migrate", "--out", target.to_str().unwrap()],
        input,
    );
    assert!(migrated.status.success(), "{:?}", migrated);
    assert_terminal_safe(&migrated.stderr);
    assert_eq!(std::fs::read(&source).unwrap(), original);
    let mut vault = Vault::open(&target, &password(input.trim_end())).unwrap();
    let entry = vault
        .entries()
        .iter()
        .find(|entry| entry.item_id == 1)
        .unwrap()
        .clone();
    assert_eq!(entry.title, "example.com");
    assert_eq!(entry.username, "alice");
    vault.open_item(entry.item_id).unwrap();
    assert_eq!(
        vault.open_record(entry.slot).unwrap().password.as_deref(),
        Some(b"correct horse battery staple".as_slice())
    );
    drop(vault);
    let current = std::fs::read(&target).unwrap();
    let repeated = cli(&source, &["migrate", "--out", target.to_str().unwrap()], "");
    assert_eq!(repeated.status.code(), Some(1));
    assert_eq!(std::fs::read(&source).unwrap(), original);
    assert_eq!(std::fs::read(&target).unwrap(), current);
}
