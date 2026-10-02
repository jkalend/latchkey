//! Native delayed rendering: one owner window/thread per copy.
//!
//! Snapshot and announce share a clipboard lock. Timeout/cancellation restores
//! the snapshot under that lock only while GetClipboardOwner is still our
//! window, BEFORE destroying it. This covers both rendered and unrendered
//! secrets, without forcing a render just to determine ownership. Replacement
//! content (even identical text) is never overwritten. WM_RENDERALLFORMATS
//! deliberately renders nothing; abrupt death after rendering remains a limit.

use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use windows::core::w;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{EmptyClipboard, GetClipboardOwner};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetWindowLongPtrW,
    PeekMessageW, RegisterClassW, SetWindowLongPtrW, TranslateMessage, GWLP_USERDATA, HWND_MESSAGE,
    MSG, PM_REMOVE, WINDOW_EX_STYLE, WINDOW_STYLE, WM_RENDERALLFORMATS, WM_RENDERFORMAT, WNDCLASSW,
};

use super::win32::{
    render_into_global, restore_open_clipboard, set_clipboard_hglobal, snapshot_open_clipboard,
    to_utf16, ClipboardLock,
};
use crate::clip::{Cancellation, ClipError, Result};

// NULL is success for a delayed announcement; windows-rs treats it as error.
#[link(name = "user32")]
extern "system" {
    #[link_name = "SetClipboardData"]
    fn set_clipboard_data_raw(
        format: u32,
        handle: *mut core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
}
#[link(name = "kernel32")]
extern "system" {
    #[link_name = "SetLastError"]
    fn set_last_error(err: u32);
}

unsafe fn announce_delayed() -> Result<()> {
    unsafe {
        set_last_error(0);
        let handle = set_clipboard_data_raw(CF_UNICODETEXT.0 as u32, std::ptr::null_mut());
        if !handle.is_null() || std::io::Error::last_os_error().raw_os_error() == Some(0) {
            Ok(())
        } else {
            Err(ClipError::Other(format!(
                "announce delayed clipboard: {}",
                std::io::Error::last_os_error()
            )))
        }
    }
}

struct RenderState {
    secret: zeroize::Zeroizing<Vec<u16>>,
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_RENDERFORMAT if wparam.0 == CF_UNICODETEXT.0 as usize => {
            // The paste requester holds the clipboard lock. Do not open it here.
            unsafe {
                let raw = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
                if raw != 0 {
                    let state = &*(raw as *const RenderState);
                    if let Ok(handle) = render_into_global(&state.secret) {
                        let _ = set_clipboard_hglobal(handle);
                    }
                }
            }
            LRESULT(0)
        }
        // Never empty here: restored rendered data must survive destruction,
        // and another process may have acquired ownership in the meantime.
        WM_RENDERALLFORMATS => LRESULT(0),
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

struct RenderWindow(HWND);

impl Drop for RenderWindow {
    fn drop(&mut self) {
        unsafe {
            // Detach FIRST: DestroyWindow can synchronously reenter wnd_proc.
            let raw = SetWindowLongPtrW(self.0, GWLP_USERDATA, 0);
            if raw != 0 {
                drop(Box::from_raw(raw as *mut RenderState));
            }
            let _ = DestroyWindow(self.0);
        }
    }
}

fn create_window(secret: zeroize::Zeroizing<Vec<u16>>) -> Result<RenderWindow> {
    // Classes are process-wide and remain registered after thread/window death.
    static CLASS: std::sync::LazyLock<std::result::Result<(), String>> =
        std::sync::LazyLock::new(|| unsafe {
            let class = WNDCLASSW {
                lpfnWndProc: Some(wnd_proc),
                lpszClassName: w!("latchkey_clip_render_wnd"),
                ..Default::default()
            };
            if RegisterClassW(&class) == 0 {
                Err(format!(
                    "register clipboard window: {}",
                    std::io::Error::last_os_error()
                ))
            } else {
                Ok(())
            }
        });
    if let Err(error) = &*CLASS {
        return Err(ClipError::Other(error.clone()));
    }
    unsafe {
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("latchkey_clip_render_wnd"),
            w!(""),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            None,
            None,
        )
        .map_err(|e| ClipError::Other(format!("create clipboard window: {e}")))?;
        SetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA,
            Box::into_raw(Box::new(RenderState { secret })) as isize,
        );
        Ok(RenderWindow(hwnd))
    }
}

fn dispatch_pending() {
    unsafe {
        let mut message = MSG::default();
        while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

fn restore_if_owner(hwnd: HWND, previous: Option<&[u16]>) -> Result<()> {
    // A busy paste client may be waiting for WM_RENDERFORMAT before releasing
    // its lock. Pump while waiting, and do not abandon a rendered secret.
    let _lock = loop {
        if let Ok(lock) = ClipboardLock::try_open(Some(hwnd)) {
            break lock;
        }
        dispatch_pending();
        std::thread::sleep(Duration::from_millis(10));
    };
    if unsafe { GetClipboardOwner() }.ok() == Some(hwnd) {
        restore_open_clipboard(previous)?;
    }
    Ok(())
}

struct Announcer {
    close: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<Result<()>>>,
}

impl Announcer {
    fn finish(&mut self) -> Result<()> {
        // A disconnection also requests cleanup, including unwinding callers.
        self.close.take();
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| ClipError::Other("render thread panicked".into()))?,
            None => Ok(()),
        }
    }
}

impl Drop for Announcer {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn spawn_announcer(secret: &[u8]) -> Result<Announcer> {
    let (close, requests) = mpsc::channel::<()>();
    let (ready, announced) = mpsc::channel::<Result<()>>();
    let secret = zeroize::Zeroizing::new(to_utf16(secret));
    let thread = std::thread::Builder::new()
        .name("latchkey-clip-render".into())
        .spawn(move || {
            let window = match create_window(secret) {
                Ok(window) => window,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return Ok(());
                }
            };
            let previous = match (|| {
                let _lock = ClipboardLock::open(Some(window.0))?;
                let previous = snapshot_open_clipboard()?.map(zeroize::Zeroizing::new);
                unsafe { EmptyClipboard() }
                    .map_err(|e| ClipError::Other(format!("empty clipboard: {e}")))?;
                if let Err(error) = unsafe { announce_delayed() } {
                    // Still under the same lock: failure cannot overwrite a
                    // user's concurrent replacement when restoring the snapshot.
                    restore_open_clipboard(previous.as_deref().map(|text| text.as_slice()))?;
                    return Err(error);
                }
                Ok(previous)
            })() {
                Ok(previous) => previous,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return Ok(());
                }
            };
            let _ = ready.send(Ok(()));
            loop {
                match requests.try_recv() {
                    Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                dispatch_pending();
                std::thread::sleep(Duration::from_millis(10));
            }
            // The window lives until restore completes (including unrendered
            // formats). Closing first destroys the only ownership evidence.
            restore_if_owner(window.0, previous.as_deref().map(|text| text.as_slice()))
        })
        .map_err(|e| ClipError::Other(format!("spawn render thread: {e}")))?;
    let mut announcer = Announcer {
        close: Some(close),
        thread: Some(thread),
    };
    match announced.recv() {
        Ok(Ok(())) => Ok(announcer),
        Ok(Err(error)) => {
            let _ = announcer.finish();
            Err(error)
        }
        Err(_) => {
            let _ = announcer.finish();
            Err(ClipError::Other("render thread died during setup".into()))
        }
    }
}

pub fn copy_and_hold(secret: &[u8], timeout_secs: u64) -> Result<()> {
    copy_and_hold_cancellable(secret, timeout_secs, &Cancellation::default())
}

pub fn copy_and_hold_cancellable(
    secret: &[u8],
    timeout_secs: u64,
    cancel: &Cancellation,
) -> Result<()> {
    crate::clip::validate_timeout(timeout_secs)?;
    // Install the native CLI console handler before entering the hold loop.
    let _ = crate::clip::ctrlc_flag();
    let mut announcer = spawn_announcer(secret)?;
    cancel.hold(timeout_secs);
    announcer.finish()
}

#[cfg(test)]
pub(crate) static CLIPBOARD_TEST_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

#[cfg(test)]
pub(crate) fn lock_clipboard() -> std::sync::MutexGuard<'static, ()> {
    CLIPBOARD_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests {
    use super::super::win32::{copy_now, snapshot_clipboard, PreserveClipboard};
    use super::*;

    fn assert_text(expected: &str) {
        assert_eq!(
            snapshot_clipboard()
                .unwrap()
                .map(|text| String::from_utf16_lossy(&text)),
            Some(expected.into())
        );
    }

    #[test]
    fn unrendered_copy_restores_previous_text_and_successive_copy_renders() {
        let _serial = lock_clipboard();
        let _restore = PreserveClipboard::new();
        copy_now(b"previous-text").unwrap();
        let mut first = spawn_announcer(b"first-secret").unwrap();
        // No GetClipboardData before close: this must not render the secret.
        first.finish().unwrap();
        assert_text("previous-text");
        let mut second = spawn_announcer(b"second-secret").unwrap();
        assert_text("second-secret");
        second.finish().unwrap();
        assert_text("previous-text");
    }

    #[test]
    fn rendered_copy_with_empty_previous_clipboard_is_cleared() {
        let _serial = lock_clipboard();
        let _restore = PreserveClipboard::new();
        super::super::win32::restore_clipboard(&None).unwrap();
        let mut copy = spawn_announcer(b"rendered-secret").unwrap();
        assert_text("rendered-secret");
        copy.finish().unwrap();
        assert_eq!(snapshot_clipboard().unwrap(), None);
    }

    #[test]
    fn user_replacement_including_identical_text_is_preserved() {
        let _serial = lock_clipboard();
        let _restore = PreserveClipboard::new();
        for replacement in [b"user-replacement".as_slice(), b"our-secret"] {
            copy_now(b"previous-text").unwrap();
            let mut copy = spawn_announcer(b"our-secret").unwrap();
            copy_now(replacement).unwrap();
            copy.finish().unwrap();
            assert_text(std::str::from_utf8(replacement).unwrap());
        }
    }

    #[test]
    fn cancellation_joins_real_backend_and_restores() {
        let _serial = lock_clipboard();
        let _restore = PreserveClipboard::new();
        copy_now(b"previous-text").unwrap();
        let owner = unsafe { GetClipboardOwner() }.ok();
        let task = crate::clip::ClipboardTask::start(
            zeroize::Zeroizing::new(b"cancel-secret".to_vec()),
            300,
        )
        .unwrap();
        // Poll only clipboard ownership, not GetClipboardData: cancellation
        // must restore even if the secret was never rendered.
        let before = std::time::Instant::now();
        while unsafe { GetClipboardOwner() }.ok() == owner {
            assert!(
                before.elapsed() < Duration::from_secs(5),
                "worker did not announce"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        task.cancel_and_finish().unwrap();
        assert_text("previous-text");
    }

    #[test]
    fn dropping_owned_worker_clears_rendered_secret() {
        let _serial = lock_clipboard();
        let _restore = PreserveClipboard::new();
        super::super::win32::restore_clipboard(&None).unwrap();
        let owner = unsafe { GetClipboardOwner() }.ok();
        let task = crate::clip::ClipboardTask::start(
            zeroize::Zeroizing::new(b"drop-secret".to_vec()),
            300,
        )
        .unwrap();
        let started = std::time::Instant::now();
        while unsafe { GetClipboardOwner() }.ok() == owner {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "worker did not announce"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_text("drop-secret");
        // Early return/unwind callers cannot accidentally detach cleanup.
        drop(task);
        assert_eq!(snapshot_clipboard().unwrap(), None);
    }
}
