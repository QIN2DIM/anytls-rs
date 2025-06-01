pub mod config;
pub mod error;
pub mod frame;
pub mod padding;
pub mod session;
pub mod stream;

pub use config::{ClientConfig, ServerConfig, PROTOCOL_VERSION, PROGRAM_VERSION};
pub use error::{AnyTlsError, Result};
pub use frame::{Frame, CMD_SYN, CMD_PSH, CMD_FIN, CMD_SETTINGS, CMD_ALERT};
pub use padding::PaddingScheme;
pub use session::{Session, SessionStats, OnNewStream};
pub use stream::Stream;

// Re-export commonly used external types
pub use bytes::{Bytes, BytesMut};
pub use tokio::io::{AsyncReadExt, AsyncWriteExt}; 