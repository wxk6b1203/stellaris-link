use thiserror::Error;

#[derive(Debug, Error)]
pub enum NodeIdParseError {
    #[error("invalid hex: {0}")]
    Hex(String),
    #[error("expected 32 bytes, got {0}")]
    Length(usize),
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read {0}: {1}")]
    Io(String, String),
    #[error("failed to parse {0}: {1}")]
    Parse(String, String),
    #[error("invalid config: {0}")]
    Invalid(String),
}
