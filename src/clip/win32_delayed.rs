//! Win32 delayed-render clipboard (ADR-0003 §3).
//!
//! Model: `SetClipboardData(CF_UNICODETEXT, NULL)` announces the format
//! without handing over data. A hidden message-only window (owned by a
//! dedicated thread) answers `WM_RENDERFORMAT` by rendering the secret on
//! demand. Two security properties fall out:
//!
//! - The secret never sits statically in the clipboard while the timer
//!   runs — a paste target receives it only when it actually asks.
//! - Process death clears the entry automatically: a dead owner cannot
//!   answer a render request, so the OS treats the format as empty. The
//!   `rpass copy` timeout is a *restore* timer, not the only thing
//!   standing between the secret and the clipboard.
//!
//! On timeout the window thread is told to close; destroying the window
//! drops clipboard ownership, and the pre-copy snapshot is restored (or
//! the clipboard emptied). `WM_RENDERALLFORMATS` deliberately renders
//! nothing — dropping the entry on exit is the desired behavior.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows::core::w;
use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetWindowLongPtrW,
    PeekMessageW, PostQuitMessage, RegisterClassW, SetWindowLongPtrW, TranslateMessage,
    GWLP_USERDATA, HWND_MESSAGE, MSG, PM_REMOVE, WINDOW_EX_STYLE, WINDOW_STYLE, WM_DESTROY,
    WM_RENDERALLFORMATS, WM_RENDERFORMAT, WNDCLASSW,
};

use crate::clip::error::{ClipError, Result};

use super::win32::{render_into_global, snapshot_best_effort};

// The windows-rs `SetClipboardData` wrapper maps a NULL return to Err — but
// the delayed-render announce passes NULL in and gets NULL back on SUCCESS,
// so the wrapper cannot represent it. Talk to user32 directly and
// disambiguate with GetLastError.
#[link(name = "user32")]
extern "system" {
    #[link_name = "SetClipboardData"]
    fn set_clipboard_data_raw(uformat: u32, hmem: *mut core::ffi::c_void)
        -> *mut core::ffi::c_void;
}
#[link(name = "kernel32")]
extern "system" {
    #[link_name = "SetLastError"]
    fn set_last_error(err: u32);
}

/// Announce CF_UNICODETEXT with delayed rendering (NULL data handle).
/// SAFETY: the clipboard must be open; the calling thread must own the
/// window that will answer WM_RENDERFORMAT.
unsafe fn announce_delayed() -> bool {
    unsafe {
        set_last_error(0);
        let h = set_clipboard_data_raw(CF_UNICODETEXT.0 as u32, std::ptr::null_mut());
        if !h.is_null() {
            return true; // unexpected, but not a failure
        }
        std::io::Error::last_os_error().raw_os_error() == Some(0)
    }
}

/// Messages to the window thread.
enum ToThread {
    /// Announce CF_UNICODETEXT (delayed) as the new clipboard owner.
    Announce,
    /// Destroy the window; stop answering render requests.
    Close,
}

/// Per-window state, owned by the render thread and reached from the window
/// proc via GWLP_USERDATA (same thread — window messages are delivered by
/// the pump below, never concurrently).
struct RenderState {
    /// The secret, zeroized on drop. Present between Announce and Close.
    secret: Option<zeroize::Zeroizing<Vec<u16>>>,
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_RENDERFORMAT => {
            // A paste target asked for the announced format. The clipboard is
            // held open by the requester; SetClipboardData here is how
            // delayed rendering hands the data over.
            unsafe {
                let state = userdata::<RenderState>(hwnd);
                if let Some(secret) = state.and_then(|s| s.secret.as_ref()) {
                    if let Ok(h) = render_into_global(secret) {
                        // On success the system owns the HGLOBAL.
                        let _ = SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(h.0)));
                    }
                }
            }
            LRESULT(0)
        }
        WM_RENDERALLFORMATS => {
            // We're exiting while still owning the clipboard. Render
            // NOTHING — dropping the entry is the point.
            unsafe {
                if OpenClipboard(Some(hwnd)).is_ok() {
                    let _ = EmptyClipboard();
                    let _ = CloseClipboard();
                }
            }
            LRESULT(0)
        }
        WM_DESTROY => unsafe {
            PostQuitMessage(0);
            LRESULT(0)
        },
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

unsafe fn set_userdata<T>(hwnd: HWND, ptr: Box<T>) {
    unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(ptr) as isize) };
}

/// SAFETY: caller must guarantee no other GWLP_USERDATA user exists for hwnd
/// and that the returned reference isn't held across a message that drops
/// the box (only thread teardown does, after the pump exits).
unsafe fn userdata<T>(hwnd: HWND) -> Option<&'static T> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
    if raw == 0 {
        None
    } else {
        Some(unsafe { &*(raw as *const T) })
    }
}

unsafe fn take_userdata<T>(hwnd: HWND) -> Option<Box<T>> {
    let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
    if raw == 0 {
        None
    } else {
        Some(unsafe { Box::from_raw(raw as *mut T) })
    }
}

/// Spawn the render thread and announce `secret` with delayed rendering.
/// Returns the control channel; `Close` (or dropping it) tears the window
/// down and stops render requests from being answered.
fn spawn_announcer(secret: &[u8]) -> Result<mpsc::Sender<ToThread>> {
    let (tx, rx) = mpsc::channel::<ToThread>();
    let secret_utf16: Vec<u16> = String::from_utf8_lossy(secret).encode_utf16().collect();
    let secret = zeroize::Zeroizing::new(secret_utf16);

    let announce_tx = tx.clone();
    std::thread::Builder::new()
        .name("rpass-clip-render".into())
        .spawn(move || unsafe {
            let class_name = w!("rpass_clip_render_wnd");
            let wc = WNDCLASSW {
                lpfnWndProc: Some(wnd_proc),
                lpszClassName: class_name,
                ..Default::default()
            };
            // Window classes are process-global: after the first copy the
            // class exists and RegisterClassW fails with
            // ERROR_CLASS_ALREADY_EXISTS. That's fine — the class points at
            // the same wnd_proc. Any other failure is fatal.
            if RegisterClassW(&wc) == 0 {
                const ERROR_CLASS_ALREADY_EXISTS: u32 = 1410;
                if std::io::Error::last_os_error().raw_os_error()
                    != Some(ERROR_CLASS_ALREADY_EXISTS as i32)
                {
                    return;
                }
            }
            let Ok(hwnd) = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class_name,
                w!(""),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE), // message-only: invisible, no z-order
                None,
                None,
                None,
            ) else {
                return;
            };

            let state = Box::new(RenderState { secret: None });
            set_userdata(hwnd, state);

            // The state box lives until teardown; keep a raw borrow of the
            // secret outside it so the pump can stage it in after Announce.
            let mut staged_secret = Some(secret);

            // Pump: dispatch window messages, poll the control channel.
            // PeekMessage with PM_REMOVE (non-blocking) + a short sleep keeps
            // control messages responsive on a quiet queue.
            'pump: loop {
                match rx.try_recv() {
                    Ok(ToThread::Announce) => {
                        // SAFETY: the raw pointer is the box we installed; on
                        // this thread, access is exclusive (the pump is the
                        // only reader/writer between messages).
                        let raw = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
                        if raw != 0 {
                            let st_mut = &mut *(raw as *mut RenderState);
                            st_mut.secret = staged_secret.take();
                        }
                        if OpenClipboard(Some(hwnd)).is_ok() {
                            let _ = EmptyClipboard();
                            // NULL handle = the delayed-render promise.
                            let ok = announce_delayed();
                            let _ = CloseClipboard();
                            if !ok {
                                break 'pump;
                            }
                        }
                    }
                    Ok(ToThread::Close) | Err(mpsc::TryRecvError::Disconnected) => break 'pump,
                    Err(mpsc::TryRecvError::Empty) => {}
                }

                let mut msg = MSG::default();
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    if msg.message == WM_DESTROY {
                        break 'pump;
                    }
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                std::thread::sleep(Duration::from_millis(10));
            }

            // Teardown: drop the secret, then the window (which drops
            // clipboard ownership — the promised format dies with it).
            if let Some(mut state) = take_userdata::<RenderState>(hwnd) {
                state.secret = None; // zeroize now, not on thread exit
                drop(state);
            }
            let _ = DestroyWindow(hwnd);
            // Keep the sender alive until teardown completes so a dropped
            // handle (TUI paths) doesn't kill the thread mid-announcement.
            drop(announce_tx);
        })
        .map_err(|e| ClipError::Other(format!("spawn render thread: {e}")))?;

    tx.send(ToThread::Announce)
        .map_err(|_| ClipError::Other("render thread died before announce".into()))?;
    Ok(tx)
}

/// Copy with delayed rendering, hold for `timeout_secs`, then stop answering
/// render requests and restore the pre-copy clipboard.
pub fn copy_and_hold(secret: &[u8], timeout_secs: u64) -> Result<()> {
    // Snapshot BEFORE announcing — the announce empties the clipboard.
    let restore = snapshot_best_effort();

    let ctl = spawn_announcer(secret)?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100).min(deadline - Instant::now()));
    }

    // Stop answering render requests; WM_RENDERALLFORMATS renders nothing.
    let _ = ctl.send(ToThread::Close);
    // Give the thread a moment to destroy the window before restoring.
    std::thread::sleep(Duration::from_millis(100));

    // Restore the pre-copy clipboard (or blank).
    super::win32::restore_clipboard(&restore);
    Ok(())
}

/// Immediate copy without delayed rendering — for the TUI, which manages
/// its own clear timer and needs data present right away.
pub fn copy_now(secret: &[u8]) -> Result<()> {
    super::win32::copy_now(secret)
}

/// Tests that use the REAL clipboard serialize on this lock — including the
/// sync-backend test in `win32.rs`, which shares the OS clipboard with us.
#[cfg(test)]
pub(crate) static CLIPBOARD_TEST_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn lock_clipboard() -> std::sync::MutexGuard<'static, ()> {
    CLIPBOARD_TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests {
    use super::lock_clipboard;

    /// Full pipeline through the REAL clipboard: announce delayed, ask the
    /// OS to render (snapshot reads through GetClipboardData, which forces
    /// the render), verify content, close, verify cleared.
    #[test]
    fn delayed_render_roundtrip_through_real_clipboard() {
        let _guard = lock_clipboard();
        // Save whatever the user had.
        let before = super::super::win32::snapshot_best_effort();

        let ctl = super::spawn_announcer(b"rpass-delayed-test-42").unwrap();
        // Let the thread announce.
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Reading the clipboard forces a WM_RENDERFORMAT round trip.
        let got = super::super::win32::snapshot_best_effort();
        assert_eq!(
            got.map(|g| String::from_utf16_lossy(&g)),
            Some("rpass-delayed-test-42".to_string()),
            "delayed render must serve the secret on request"
        );

        // Close and verify the clipboard no longer serves it.
        let _ = ctl.send(super::ToThread::Close);
        std::thread::sleep(std::time::Duration::from_millis(200));
        let after = super::super::win32::snapshot_best_effort();
        assert_ne!(
            after.map(|g| String::from_utf16_lossy(&g)),
            Some("rpass-delayed-test-42".to_string()),
            "closed render thread must stop serving the secret"
        );

        // Restore the user's clipboard.
        super::super::win32::restore_clipboard(&before);
    }

    /// A second copy after a first one closed: window classes are
    /// process-global and RegisterClassW returns ERROR_CLASS_ALREADY_EXISTS,
    /// which must not abort the second announce.
    #[test]
    fn second_announcer_after_close_still_works() {
        let _guard = lock_clipboard();
        let before = super::super::win32::snapshot_best_effort();
        let ctl1 = super::spawn_announcer(b"rpass-dup-1").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = ctl1.send(super::ToThread::Close);
        std::thread::sleep(std::time::Duration::from_millis(200));

        let ctl2 = super::spawn_announcer(b"rpass-dup-2").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let got = super::super::win32::snapshot_best_effort();
        assert_eq!(
            got.map(|g| String::from_utf16_lossy(&g)),
            Some("rpass-dup-2".to_string()),
            "second copy must still announce (class already registered)"
        );
        let _ = ctl2.send(super::ToThread::Close);
        std::thread::sleep(std::time::Duration::from_millis(100));
        super::super::win32::restore_clipboard(&before);
    }
}
