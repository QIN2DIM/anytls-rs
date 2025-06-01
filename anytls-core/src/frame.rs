use bytes::{Buf, BufMut};
use std::io::Cursor;
use crate::error::Result;

// Protocol commands
pub const CMD_WASTE: u8 = 0;                   // Paddings
pub const CMD_SYN: u8 = 1;                     // Stream open
pub const CMD_PSH: u8 = 2;                     // Data push
pub const CMD_FIN: u8 = 3;                     // Stream close, a.k.a EOF mark
pub const CMD_SETTINGS: u8 = 4;                // Settings (Client send to Server)
pub const CMD_ALERT: u8 = 5;                   // Alert
pub const CMD_UPDATE_PADDING_SCHEME: u8 = 6;   // Update padding scheme

// Since version 2
pub const CMD_SYNACK: u8 = 7;                  // Server reports to the client that the stream has been opened
pub const CMD_HEART_REQUEST: u8 = 8;           // Keep alive command
pub const CMD_HEART_RESPONSE: u8 = 9;          // Keep alive command
pub const CMD_SERVER_SETTINGS: u8 = 10;        // Settings (Server send to client)

pub const HEADER_SIZE: usize = 1 + 4 + 2;      // cmd(1) + stream_id(4) + length(2)

#[derive(Debug, Clone)]
pub struct Frame {
    pub cmd: u8,
    pub stream_id: u32,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn new(cmd: u8, stream_id: u32) -> Self {
        Self {
            cmd,
            stream_id,
            data: Vec::new(),
        }
    }

    pub fn with_data(cmd: u8, stream_id: u32, data: Vec<u8>) -> Self {
        Self {
            cmd,
            stream_id,
            data,
        }
    }

    /// Parse a frame from bytes. Returns the frame and the number of bytes consumed.
    pub fn parse(buf: &[u8]) -> Result<Option<(Self, usize)>> {
        if buf.len() < HEADER_SIZE {
            return Ok(None);
        }

        let mut cursor = Cursor::new(buf);
        let cmd = cursor.get_u8();
        let stream_id = cursor.get_u32();
        let length = cursor.get_u16() as usize;

        let total_size = HEADER_SIZE + length;
        if buf.len() < total_size {
            return Ok(None);
        }

        let data = buf[HEADER_SIZE..total_size].to_vec();
        
        Ok(Some((
            Frame {
                cmd,
                stream_id,
                data,
            },
            total_size,
        )))
    }

    /// Serialize the frame to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.data.len());
        buf.put_u8(self.cmd);
        buf.put_u32(self.stream_id);
        buf.put_u16(self.data.len() as u16);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Get command name for debugging
    pub fn cmd_name(&self) -> &'static str {
        match self.cmd {
            CMD_WASTE => "WASTE",
            CMD_SYN => "SYN",
            CMD_PSH => "PSH",
            CMD_FIN => "FIN",
            CMD_SETTINGS => "SETTINGS",
            CMD_ALERT => "ALERT",
            CMD_UPDATE_PADDING_SCHEME => "UPDATE_PADDING_SCHEME",
            CMD_SYNACK => "SYNACK",
            CMD_HEART_REQUEST => "HEART_REQUEST",
            CMD_HEART_RESPONSE => "HEART_RESPONSE",
            CMD_SERVER_SETTINGS => "SERVER_SETTINGS",
            _ => "UNKNOWN",
        }
    }
} 