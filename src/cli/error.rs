use thiserror::Error;

/// Exit codes (CLI_REFERENCE "Exit codes" table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success = 0,
    GenericFailure = 1,
    Usage = 2,
    VaultNotFound = 3,
    UserCancel = 4,
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),
    #[error("vault not found at {0} — run `rpass init` first (or pass --vault <path>)")]
    VaultNotFound(std::path::PathBuf),
    #[error("cancelled")]
    Cancelled,
    #[error("{0}")]
    Other(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => ExitCode::Usage as i32,
            CliError::VaultNotFound(_) => ExitCode::VaultNotFound as i32,
            CliError::Cancelled => ExitCode::UserCancel as i32,
            CliError::Other(_) => ExitCode::GenericFailure as i32,
        }
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
