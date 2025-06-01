use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnyTlsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Invalid frame format")]
    InvalidFrame,
    
    #[error("Stream not found: {0}")]
    StreamNotFound(u32),
    
    #[error("Session closed")]
    SessionClosed,
    
    #[error("Stream closed")]
    StreamClosed,
    
    #[error("Invalid padding scheme")]
    InvalidPaddingScheme,
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u8, got: u8 },
    
    #[error("Timeout")]
    Timeout,
    
    #[error("TLS error: {0}")]
    Tls(String),
    
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AnyTlsError>; 