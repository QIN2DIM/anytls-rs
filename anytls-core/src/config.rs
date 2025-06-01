use std::time::Duration;
use crate::padding::PaddingScheme;

pub const PROTOCOL_VERSION: u8 = 2;
pub const PROGRAM_VERSION: &str = "anytls-rust/0.1.0";

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub password: String,
    pub padding_scheme: PaddingScheme,
    pub idle_session_check_interval: Duration,
    pub idle_session_timeout: Duration,
    pub min_idle_sessions: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            password: String::new(),
            padding_scheme: PaddingScheme::default(),
            idle_session_check_interval: Duration::from_secs(30),
            idle_session_timeout: Duration::from_secs(60),
            min_idle_sessions: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub password: String,
    pub padding_scheme: PaddingScheme,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            password: String::new(),
            padding_scheme: PaddingScheme::default(),
        }
    }
}

/// Parse a string map from bytes (key=value format, one per line)
pub fn parse_string_map(data: &[u8]) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    
    if let Ok(s) = std::str::from_utf8(data) {
        for line in s.lines() {
            if let Some((key, value)) = line.split_once('=') {
                map.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    
    map
}

/// Serialize a string map to bytes
pub fn serialize_string_map(map: &std::collections::HashMap<String, String>) -> Vec<u8> {
    let mut lines = Vec::new();
    for (key, value) in map {
        lines.push(format!("{}={}", key, value));
    }
    lines.join("\n").into_bytes()
} 