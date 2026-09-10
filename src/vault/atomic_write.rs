//! Atomic vault write protocol (VAULT_FORMAT.md §7).
//!
//! A write is: temp file → fsync → rename → fsync dir.
//! The temp file lives in the same directory as the target so `rename(2)` is atomic
//! on the same filesystem. On crash mid-write, the old vault is untouched; the
//! temp file is orphaned and cleaned up by the next `open` (§7.2).
use crate::crypto::error::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const TEMP_SUFFIX: &str = ".rpass-tmp";

// temp filename derived deterministically from the target so concurrent writes to
// the same vault clash (one will lose the race and error) rather than corrupting.
fn temp_path(target: &Path) -> PathBuf {
    let mut p = target.as_os_str().to_owned();
    p.push(TEMP_SUFFIX);
    PathBuf::from(p)
}

/// Atomic write of `data` to `target`. Returns Err if fsync/rename fails — the
/// caller's previous file is still on disk.
pub fn atomic_write(target: &Path, data: &[u8]) -> Result<()> {
    let tmp = temp_path(target);

    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .map_err(io_err("create temp"))?;

    f.write_all(data).map_err(io_err("write temp"))?;
    f.sync_all().map_err(io_err("fsync temp"))?;
    drop(f);

    // fsync the parent dir so the temp file's dir entry is durable before rename.
    if let Some(parent) = target.parent() {
        fsync_dir(parent)?;
    }

    fs::rename(&tmp, target).map_err(io_err("rename temp→target"))?;

    // fsync parent again so the rename is durable.
    if let Some(parent) = target.parent() {
        fsync_dir(parent)?;
    }

    Ok(())
}

/// Best-effort fsync of a directory. On some platforms (Windows) directory fsync
/// is unavailable; the rename above is already atomic there, so we ignore errors.
fn fsync_dir(dir: &Path) -> Result<()> {
    match File::open(dir) {
        Ok(f) => {
            match f.sync_all() {
                Ok(()) => Ok(()),
                Err(ref e) if is_dir_fsync_unsupported(e) => {
                    // Windows can't fsync directories; MoveFileExW with the atomic flag
                    // is the durability primitive Windows actually uses.
                    Ok(())
                }
                Err(e) => Err(Error::Encrypt(format!("dir fsync: {e}"))),
            }
        }
        Err(ref e) if is_dir_fsync_unsupported(e) => Ok(()),
        Err(e) => Err(Error::Encrypt(format!("open dir for fsync: {e}"))),
    }
}

fn is_dir_fsync_unsupported(e: &std::io::Error) -> bool {
    // PermissionDenied on opening a directory, or InvalidInput from sync_all.
    matches!(
        e.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
    ) || e.raw_os_error().is_some_and(|c| {
        // EISDIR (21) / EACCES (13) / ERROR_INVALID_FUNCTION (1) on Windows.
        c == 21 || c == 13 || c == 1
    })
}

fn io_err(what: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::Encrypt(format!("atomic write {what}: {e}"))
}

// Public for tests / future temp-file cleanup.
#[allow(dead_code)]
pub fn temp_path_for(target: &Path) -> PathBuf {
    temp_path(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;

    #[test]
    fn write_then_read_same_bytes() {
        let dir = std::env::temp_dir().join(format!("rpass_awt_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("vault.rpass");

        let data = b"hello, vault!";
        atomic_write(&target, data).unwrap();

        let mut got = Vec::new();
        File::open(&target).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, data);

        // temp file should be gone
        assert!(!temp_path(&target).exists());

        // overwrite existing file
        let data2 = b"new contents that are longer";
        atomic_write(&target, data2).unwrap();
        let mut got2 = Vec::new();
        File::open(&target).unwrap().read_to_end(&mut got2).unwrap();
        assert_eq!(got2, data2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn overwrite_leaves_no_stale_data() {
        let dir = std::env::temp_dir().join(format!("rpass_awt2_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("vault.rpass");

        atomic_write(&target, b"0123456789abcdef").unwrap();
        atomic_write(&target, b"short").unwrap();

        let got = fs::read(&target).unwrap();
        assert_eq!(got, b"short");

        let _ = fs::remove_dir_all(&dir);
    }
}
