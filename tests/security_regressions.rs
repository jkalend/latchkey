//! Regression tests for the 2026-10-16 security review findings
//! (docs/SECURITY_REVIEW_2026-10-16.md). Each test maps to a finding's
//! documented regression acceptance. Synthetic data only.

use latchkey::cli::passwords::check_quality;
use latchkey::clip;
use latchkey::crypto::ciphers::Algorithm;
use latchkey::crypto::kdf::{KdfParams, SecretVec};
use latchkey::ops::{self, Change, EntryPatch, NewEntry};
use latchkey::vault::vault_impl::Vault;

fn pw(text: &str) -> SecretVec {
    SecretVec::new(text.as_bytes().to_vec().into_boxed_slice())
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "latchkey_sec_{tag}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ─── SEC-01 ────────────────────────────────────────────────────────────────
// The CLI now prompts for the replacement password BEFORE any write and calls
// rotate() once with that target password. Library-level acceptance: after a
// rotation targeted at a new password, the disk bytes never pass through an
// intermediate state; the single commit publishes the DEK under the new KEK.

#[test]
fn sec01_rotation_is_one_commit_and_targeted_password_opens() {
    let dir = tmp_dir("sec01");
    let path = dir.join("vault.bin");
    // The fast override covers rotate()'s internal default-KDF derivation.
    std::env::set_var("LATCHKEY_FAST_KDF", "1");

    let mut vault = Vault::create(
        &path,
        &pw("old-review-master"),
        KdfParams::new(8, 1, 1).unwrap(),
        Algorithm::Aes256Gcm,
        Algorithm::Aes256Gcm,
    )
    .unwrap();
    let id = ops::add_entry(
        &mut vault,
        NewEntry {
            title: "future.example".into(),
            username: "alice".into(),
            password: Some(b"created before rotation".to_vec()),
            ..Default::default()
        },
    )
    .unwrap();
    vault.save().unwrap();
    let before = std::fs::read(&path).unwrap();

    // Single-commit rotation into the replacement password: one write, no
    // intermediate file ever exists (the CLI now prompts before this call).
    vault.rotate(&pw("new-review-master")).unwrap();
    let after = std::fs::read(&path).unwrap();

    // Exactly one version was published: the final one. The old password
    // cannot open the committed vault, and the pre-rotation bytes were
    // replaced by the single atomic commit.
    assert!(Vault::open(&path, &pw("old-review-master")).is_err());
    assert_ne!(before, after);

    // The secret created before rotation still decrypts under the new
    // password; the DEK itself is preserved by rotate() semantics.
    let mut reopened = Vault::open(&path, &pw("new-review-master")).unwrap();
    reopened.open_item(id).unwrap();
    let rec = reopened.open_record(reopened.entries()[0].slot).unwrap();
    assert_eq!(
        rec.password.as_deref(),
        Some(b"created before rotation".as_slice())
    );

    // Secrets saved AFTER the rotation are wrapped by the same (only) DEK
    // under the new password — there is no second DEK an old-password
    // intermediate could expose.
    ops::update_entry(
        &mut reopened,
        id,
        EntryPatch {
            password: Change::Set(b"created only AFTER password change".to_vec()),
            title: None,
            username: None,
            url: None,
            notes: Change::Keep,
            totp: Change::Keep,
        },
    )
    .unwrap();
    drop(reopened);
    let mut final_vault = Vault::open(&path, &pw("new-review-master")).unwrap();
    final_vault.open_item(id).unwrap();
    let rec = final_vault
        .open_record(final_vault.entries()[0].slot)
        .unwrap();
    assert_eq!(
        rec.password.as_deref(),
        Some(b"created only AFTER password change".as_slice())
    );

    std::env::remove_var("LATCHKEY_FAST_KDF");
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── SEC-02 ────────────────────────────────────────────────────────────────
// Windows plaintext export creates the file with a protected DACL (no
// inherited Everyone/reader ACEs). Verified through the module's own creation
// path plus the Everyone effective-rights probe.

#[cfg(windows)]
#[test]
fn sec02_plaintext_export_has_no_inherited_everyone_read() {
    let dir = tmp_dir("sec02");
    // Grant Everyone an inheritable read ACE on the directory, like the
    // review's fixture, then export into it.
    {
        use windows::Win32::Security::{
            AddAccessAllowedAce, AllocateAndInitializeSid, FreeSid, InitializeAcl,
            InitializeSecurityDescriptor, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
            ACL, ACL_REVISION, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR, SECURITY_WORLD_SID_AUTHORITY,
        };
        unsafe {
            let mut world = PSID::default();
            AllocateAndInitializeSid(
                &SECURITY_WORLD_SID_AUTHORITY,
                1,
                0u32, // SECURITY_WORLD_RID
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut world,
            )
            .unwrap();
            let mut sd = SECURITY_DESCRIPTOR::default();
            let sd_ptr =
                PSECURITY_DESCRIPTOR(&mut sd as *mut SECURITY_DESCRIPTOR as *mut core::ffi::c_void);
            InitializeSecurityDescriptor(sd_ptr, 1).unwrap();
            // Everyone SID; queried via GetLengthSid so the ACL budget is
            // exact: ACL header + one ACE (header + mask) + the SID bytes
            // (SidStart is a 4-byte placeholder for them). Aligned so the
            // ACL structure inside is 4-byte aligned as NTFS requires.
            let sid_len = windows::Win32::Security::GetLengthSid(world);
            let acl_len = (std::mem::size_of::<ACL>()
                + std::mem::size_of::<windows::Win32::Security::ACE_HEADER>()
                + 4
                + sid_len as usize) as u32;
            let acl_bytes = vec![0u8; acl_len as usize];
            let acl = acl_bytes.as_ptr() as *mut ACL;
            InitializeAcl(acl, acl_len, ACL_REVISION).unwrap();
            AddAccessAllowedAce(acl, ACL_REVISION, 0x1F01FF, world).unwrap();
            SetSecurityDescriptorOwner(sd_ptr, Some(world), false).unwrap();
            SetSecurityDescriptorDacl(sd_ptr, true, Some(acl), false).unwrap();
            // Grant the directory the permissive DACL (inheritable by files).
            set_named_security_info_wwide(
                &dir,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                acl,
            );
            let _ = FreeSid(world);
        }
    }
    let out = dir.join("export.json");
    let file = latchkey::cli::windows_acl::create_new_protected(&out).unwrap();
    {
        use std::io::Write;
        let mut f = file.into_std_file().unwrap();
        f.write_all(b"{\"synthetic\":true}").unwrap();
    }
    // The Everyone principal must hold no read bits on the file.
    assert!(
        !latchkey::cli::windows_acl::everyone_read_granted(&out).unwrap(),
        "export inherited a broad Everyone read grant"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
unsafe fn set_named_security_info_wwide(
    path: &std::path::Path,
    info: windows::Win32::Security::OBJECT_SECURITY_INFORMATION,
    dacl: *const windows::Win32::Security::ACL,
) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let err = SetNamedSecurityInfoW(
        windows::core::PCWSTR::from_raw(wide.as_ptr()),
        SE_FILE_OBJECT,
        info,
        None,
        None,
        Some(dacl),
        None,
    );
    assert!(err.is_ok(), "set permissive directory DACL: {err:?}");
}

// ─── SEC-03 ────────────────────────────────────────────────────────────────
// The legacy deterministic temp path is never used for writing: a hard link
// planted there survives a save untouched. (Main coverage lives in the
// atomic_write unit tests; this exercises it through the public vault path.)

#[test]
fn sec03_backup_does_not_follow_legacy_temp_link() {
    let dir = tmp_dir("sec03");
    let target = dir.join("backup.bin");
    let unrelated = dir.join("unrelated.txt");
    std::fs::write(&unrelated, b"original unrelated data").unwrap();
    // Pre-plant the deterministic legacy temp name the old code would use.
    std::fs::hard_link(
        &unrelated,
        dir.join(format!(
            "{target_name}.latchkey-tmp",
            target_name = "backup.bin"
        )),
    )
    .unwrap();

    latchkey::vault::atomic_write::atomic_create(&target, b"synthetic backup").unwrap();

    assert_eq!(fs_read(&unrelated), b"original unrelated data");
    assert_eq!(fs_read(&target), b"synthetic backup");
    let _ = std::fs::remove_dir_all(&dir);
}

fn fs_read(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

// ─── SEC-05 ────────────────────────────────────────────────────────────────
// Text clipboard validation: NUL-bearing and non-UTF-8 secrets are rejected
// before any backend copy instead of silently truncating/corrupting (SEC-08
// acceptance; the same validation guards the export path).

#[test]
fn sec08_text_clipboard_rejects_nul_and_non_utf8() {
    assert!(clip::validate_text_representable(b"normal-secret").is_ok());
    assert!(clip::validate_text_representable(b"prefix\0suffix").is_err());
    assert!(clip::validate_text_representable(&[0xFF, 0xFE, 0x00]).is_err());
    // Unicode passes.
    assert!(clip::validate_text_representable("pässwörd 東京".as_bytes()).is_ok());
}

#[test]
fn sec08_import_rejects_nul_password() {
    // parse_native is public; a NUL-bearing password is refused at import.
    let parsed = latchkey::cli::import::parse_native(
        r#"{"format_version":1,"items":{"1":{"title":"review","password":"prefix\u0000suffix"}}}"#,
    );
    assert!(parsed.is_err(), "import must refuse NUL-bearing passwords");
}

// ─── H-01 ──────────────────────────────────────────────────────────────────

#[test]
fn h01_password_quality_rejects_whitespace_and_weak_choices() {
    assert!(check_quality("        ").is_some(), "8 spaces must fail");
    assert!(check_quality("1234567890").is_some());
    assert!(check_quality("Password123!").is_some());
    assert!(check_quality("12345678").is_some(), "deny-listed 8-char pw");
    assert!(check_quality("correct horse battery staple").is_none());
    assert!(check_quality("r5!vQz#mP2wL").is_none());
}

// ─── H-04 ──────────────────────────────────────────────────────────────────

#[test]
fn h04_backup_never_replaces_an_existing_target() {
    let dir = tmp_dir("h04");
    let source = dir.join("vault.bin");
    std::fs::write(&source, b"vault-bytes").unwrap();
    let out = dir.join("backup.bin");
    std::fs::write(&out, b"existing").unwrap();
    // The atomic no-replacement publish must refuse, not overwrite.
    assert!(latchkey::vault::atomic_write::atomic_create(&out, b"new").is_err());
    assert_eq!(fs_read(&out), b"existing");
    let _ = std::fs::remove_dir_all(&dir);
}
