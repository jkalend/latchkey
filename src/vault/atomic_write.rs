//! Atomic vault write protocol (VAULT_FORMAT.md §7).
//!
//! A write is: temp file → fsync → rename → fsync dir.
//! The temp file lives in the same directory as the target so `rename(2)` is atomic
//! on the same filesystem. On crash mid-write, the old vault is untouched; the
//! deterministic temp path is safely overwritten by the next write.
use crate::crypto::error::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const TEMP_SUFFIX: &str = ".latchkey-tmp";

// temp filename derived deterministically from the target so concurrent writes to
// the same vault clash (one will lose the race and error) rather than corrupting.
fn temp_path(target: &Path) -> PathBuf {
    let mut p = target.as_os_str().to_owned();
    p.push(TEMP_SUFFIX);
    PathBuf::from(p)
}

/// Exclusive OS file lock held for the complete vault read/modify/write cycle.
pub struct WriteLock {
    _file: File,
}

pub fn acquire_write_lock(target: &Path) -> Result<WriteLock> {
    let path = lock_path(target);
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(false);
    #[cfg(unix)]
    opts.mode(0o600);
    let file = opts.open(&path).map_err(io_err("open vault write lock"))?;
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(io_err("secure vault write lock"))?;
    file.try_lock()
        .map_err(|e| Error::Encrypt(format!("atomic write acquire vault write lock: {e}")))?;
    Ok(WriteLock { _file: file })
}

/// Serialize a write, then atomically replace target.
pub fn atomic_write(target: &Path, data: &[u8]) -> Result<()> {
    let _lock = acquire_write_lock(target)?;
    atomic_write_locked(target, data)
}

/// Atomically replace target while the caller holds `WriteLock`.
pub fn atomic_write_locked(target: &Path, data: &[u8]) -> Result<()> {
    let tmp = temp_path(target);
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        // Owner-only from creation; set_permissions also repairs a stale
        // deterministic temp file created by an older, permissive build.
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(io_err("create temp"))?;
    #[cfg(unix)]
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(io_err("secure temp"))?;

    f.write_all(data).map_err(io_err("write temp"))?;
    f.sync_all().map_err(io_err("fsync temp"))?;
    drop(f);

    let parent = target.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent {
        fsync_dir(parent)?;
    }
    fs::rename(&tmp, target).map_err(io_err("rename temp→target"))?;
    if let Some(parent) = parent {
        fsync_dir(parent)?;
    }
    Ok(())
}

fn lock_path(target: &Path) -> PathBuf {
    let mut p = target.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
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
        let dir = std::env::temp_dir().join(format!("latchkey_awt_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("vault.latchkey");

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
        let dir = std::env::temp_dir().join(format!("latchkey_awt2_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("vault.latchkey");

        atomic_write(&target, b"0123456789abcdef").unwrap();
        atomic_write(&target, b"short").unwrap();

        let got = fs::read(&target).unwrap();
        assert_eq!(got, b"short");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_lock_is_rejected() {
        let dir = std::env::temp_dir().join(format!("latchkey_awt_lock_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("vault.latchkey");
        let lock = acquire_write_lock(&target).unwrap();
        assert!(atomic_write(&target, b"blocked").is_err());
        drop(lock);
        atomic_write(&target, b"allowed").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"allowed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn vault_and_lock_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("latchkey_awt_mode_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("vault.latchkey");
        atomic_write(&target, b"secret").unwrap();

        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(lock_path(&target))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
