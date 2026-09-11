use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClipError {
    /// Clipboard open failed (locked by another process, etc.).
    #[error("could not open the clipboard (it may be held by another application)")]
    Open,
    /// Platform backend unavailable (e.g. no wl-copy/xclip on plain Linux).
    #[error("no clipboard tool available: {0}")]
    NoBackend(String),
    /// The external clipboard tool exited nonzero / could not be spawned.
    #[error("clipboard tool `{tool}` failed: {detail}")]
    Tool { tool: &'static str, detail: String },
    /// Timeout out of the allowed range.
    #[error("clipboard timeout must be in [0, 300] seconds, got {0}")]
    Timeout(u64),
    /// Something else.
    #[error("clipboard error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ClipError>;
