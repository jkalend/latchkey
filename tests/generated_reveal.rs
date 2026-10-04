//! `add --generate` / `edit --generate` are silent by default; the generated
//! password prints only with `--reveal-generated` and only after the commit.

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
            "latchkey_gen_{name}_{}_{}",
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
        .env("LATCHKEY_FAST_KDF", "1")
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

fn stored_password(path: &Path, item_id: u32) -> String {
    let mut vault = Vault::open(path, &password("gen-master")).unwrap();
    vault.open_item(item_id).unwrap();
    let entry = vault
        .entries()
        .iter()
        .find(|e| e.item_id == item_id)
        .unwrap()
        .clone();
    let record = vault.open_record(entry.slot).unwrap();
    String::from_utf8(record.password.clone().unwrap()).unwrap()
}

#[test]
fn generated_passwords_are_silent_unless_revealed_after_commit() {
    let workspace = Workspace::new("reveal");
    let path = workspace.0.join("vault.bin");
    drop(
        Vault::create(
            &path,
            &password("gen-master"),
            KdfParams::new(8, 1, 1).unwrap(),
            Algorithm::Aes256Gcm,
            Algorithm::Aes256Gcm,
        )
        .unwrap(),
    );

    // add --generate: stored, never printed on either stream.
    let silent = cli(
        &path,
        &[
            "add",
            "site1",
            "--username",
            "u1",
            "--generate",
            "--url",
            "https://x.example",
        ],
        "gen-master\n",
    );
    assert!(silent.status.success(), "{:?}", silent);
    let added = stored_password(&path, 1);
    assert!(!added.is_empty());
    let stdout = String::from_utf8_lossy(&silent.stdout);
    let stderr = String::from_utf8_lossy(&silent.stderr);
    assert!(!stdout.contains(&added), "stdout leaked the secret");
    assert!(!stderr.contains(&added), "stderr leaked the secret");

    // add --generate --reveal-generated: prints exactly the committed value.
    let revealed = cli(
        &path,
        &[
            "add",
            "site2",
            "--username",
            "u2",
            "--generate",
            "--reveal-generated",
        ],
        "gen-master\n",
    );
    assert!(revealed.status.success(), "{:?}", revealed);
    let printed = String::from_utf8_lossy(&revealed.stdout);
    let committed = stored_password(&path, 2);
    assert!(
        printed.contains(&committed),
        "reveal must print the committed value: {printed:?}"
    );
    // The reveal line comes after the commit confirmation.
    let commit_pos = printed.find("added item 2").unwrap();
    let reveal_pos = printed.find(&committed).unwrap();
    assert!(commit_pos < reveal_pos);

    // edit --generate: replacement is silent.
    let edited = cli(
        &path,
        &["edit", "site1", "--id", "1", "--generate"],
        "gen-master\n\n\n\n",
    );
    assert!(edited.status.success(), "{:?}", edited);
    let replaced = stored_password(&path, 1);
    assert_ne!(replaced, added);
    let edit_out = String::from_utf8_lossy(&edited.stdout);
    let edit_err = String::from_utf8_lossy(&edited.stderr);
    assert!(!edit_out.contains(&replaced), "stdout leaked replacement");
    assert!(!edit_err.contains(&replaced), "stderr leaked replacement");

    // edit --generate --reveal-generated: prints the new committed value.
    let revealed_edit = cli(
        &path,
        &[
            "edit",
            "site1",
            "--id",
            "1",
            "--generate",
            "--reveal-generated",
        ],
        "gen-master\n\n\n\n",
    );
    assert!(revealed_edit.status.success(), "{:?}", revealed_edit);
    let edit_printed = String::from_utf8_lossy(&revealed_edit.stdout);
    let after = stored_password(&path, 1);
    assert!(edit_printed.contains(&after));

    // --reveal-generated without --generate is rejected before mutation.
    let before = std::fs::read(&path).unwrap();
    let rejected = cli(
        &path,
        &["add", "site3", "--username", "u3", "--reveal-generated"],
        "gen-master\n",
    );
    assert_eq!(rejected.status.code(), Some(2));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
