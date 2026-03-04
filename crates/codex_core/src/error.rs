use core::fmt;

pub type CodexResult<T> = Result<T, CodexError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexError {
    InvalidInput(&'static str),
    ParseError(&'static str),
    IntegrityError(&'static str),
}

impl fmt::Display for CodexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodexError::InvalidInput(s) => write!(f, "InvalidInput: {s}"),
            CodexError::ParseError(s) => write!(f, "ParseError: {s}"),
            CodexError::IntegrityError(s) => write!(f, "IntegrityError: {s}"),
        }
    }
}

impl std::error::Error for CodexError {}
