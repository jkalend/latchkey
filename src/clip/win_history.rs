//! Windows Clipboard History probe (ADR-0003 §4).
//!
//! Reads HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory.
//! Returns None on any failure (non-Windows, registry unreadable) —
//! a failed probe must not block copying.

#[cfg(windows)]
pub fn query_enable_history() -> Option<bool> {
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};

    const SUBKEY: windows::core::PCWSTR = windows::core::w!("Software\\Microsoft\\Clipboard");
    const VALUE: windows::core::PCWSTR = windows::core::w!("EnableClipboardHistory");

    let mut data: u32 = 0;
    let mut len: u32 = std::mem::size_of::<u32>() as u32;

    let ret = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            SUBKEY,
            VALUE,
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut u32 as *mut std::ffi::c_void),
            Some(&mut len),
        )
    };

    if ret.is_ok() {
        Some(data != 0)
    } else {
        None
    }
}

#[cfg(not(windows))]
pub fn query_enable_history() -> Option<bool> {
    // On WSL a registry probe through interop is possible (reg.exe query) but
    // the interop hop is slow and flaky; for v1 we skip it and let the
    // Windows-side warning fire when the user runs the native binary.
    // Documented in ADR-0008 §3.
    None
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn probe_does_not_crash() {
        // We can't assert the value (machine-dependent), only that the probe
        // is safe to call and returns Option<bool>.
        let _ = super::query_enable_history();
    }
}
