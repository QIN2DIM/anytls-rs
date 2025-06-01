use crate::config::{parse_string_map, serialize_string_map, PROGRAM_VERSION, PROTOCOL_VERSION};
use crate::error::{AnyTlsError, Result};
use crate::frame::{Frame, HEADER_SIZE, CMD_WASTE, CMD_SYN, CMD_PSH, CMD_FIN, CMD_SETTINGS, 
                  CMD_ALERT, CMD_UPDATE_PADDING_SCHEME, CMD_HEART_REQUEST, 
                  CMD_HEART_RESPONSE, CMD_SERVER_SETTINGS};
use crate::padding::{PaddingScheme, CHECK_MARK};
use crate::stream::Stream;
use bytes::{Bytes, BytesMut, BufMut};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, oneshot};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tracing::{debug, error, info, warn};

const FRAME_CHANNEL_SIZE: usize = 256;
const STREAM_CHANNEL_SIZE: usize = 256;

pub type OnNewStream = Box<dyn Fn(Stream) + Send + Sync>;

#[derive(Debug, Clone)]
pub struct SessionStats {
    pub created_at: Instant,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_streams: usize,
}

enum Connection {
    ClientTls(ClientTlsStream<TcpStream>),
    ServerTls(ServerTlsStream<TcpStream>),
}

pub struct Session {
    id: u64,
    is_client: bool,
    
    // Connection  
    conn: Arc<Mutex<Connection>>,
    
    // Streams
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Bytes>>>>,
    next_stream_id: Arc<Mutex<u32>>,
    
    // Frame writing
    frame_tx: mpsc::Sender<Frame>,
    frame_rx: Arc<Mutex<mpsc::Receiver<Frame>>>,
    
    // Padding
    padding_scheme: Arc<Mutex<PaddingScheme>>,
    pkt_counter: Arc<Mutex<u32>>,
    
    // Protocol state
    peer_version: Arc<Mutex<u8>>,
    received_settings: Arc<Mutex<bool>>,
    
    // Session state
    closed: Arc<Mutex<bool>>,
    close_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    
    // Stats
    stats: Arc<Mutex<SessionStats>>,
    
    // Server callback
    on_new_stream: Option<Arc<OnNewStream>>,
}

impl Session {
    /// Create a new client session
    pub async fn new_client(
        stream: ClientTlsStream<TcpStream>, 
        password: &str, 
        padding_scheme: PaddingScheme
    ) -> Result<Self> {
        let (frame_tx, frame_rx) = mpsc::channel(FRAME_CHANNEL_SIZE);
        let (close_tx, _close_rx) = oneshot::channel();
        
        let session = Self {
            id: rand::random(),
            is_client: true,
            conn: Arc::new(Mutex::new(Connection::ClientTls(stream))),
            streams: Arc::new(Mutex::new(HashMap::new())),
            next_stream_id: Arc::new(Mutex::new(1)),
            frame_tx,
            frame_rx: Arc::new(Mutex::new(frame_rx)),
            padding_scheme: Arc::new(Mutex::new(padding_scheme)),
            pkt_counter: Arc::new(Mutex::new(0)),
            peer_version: Arc::new(Mutex::new(0)),
            received_settings: Arc::new(Mutex::new(false)),
            closed: Arc::new(Mutex::new(false)),
            close_tx: Arc::new(Mutex::new(Some(close_tx))),
            stats: Arc::new(Mutex::new(SessionStats {
                created_at: Instant::now(),
                last_activity: Instant::now(),
                bytes_sent: 0,
                bytes_received: 0,
                active_streams: 0,
            })),
            on_new_stream: None,
        };
        
        // Send authentication
        session.authenticate(password).await?;
        
        Ok(session)
    }
    
    /// Create a new server session
    pub async fn new_server(
        stream: ServerTlsStream<TcpStream>, 
        expected_password: &str,
        padding_scheme: PaddingScheme,
        on_new_stream: OnNewStream,
    ) -> Result<Self> {
        let (frame_tx, frame_rx) = mpsc::channel(FRAME_CHANNEL_SIZE);
        let (close_tx, _close_rx) = oneshot::channel();
        
        let session = Self {
            id: rand::random(),
            is_client: false,
            conn: Arc::new(Mutex::new(Connection::ServerTls(stream))),
            streams: Arc::new(Mutex::new(HashMap::new())),
            next_stream_id: Arc::new(Mutex::new(1)),
            frame_tx,
            frame_rx: Arc::new(Mutex::new(frame_rx)),
            padding_scheme: Arc::new(Mutex::new(padding_scheme)),
            pkt_counter: Arc::new(Mutex::new(0)),
            peer_version: Arc::new(Mutex::new(0)),
            received_settings: Arc::new(Mutex::new(false)),
            closed: Arc::new(Mutex::new(false)),
            close_tx: Arc::new(Mutex::new(Some(close_tx))),
            stats: Arc::new(Mutex::new(SessionStats {
                created_at: Instant::now(),
                last_activity: Instant::now(),
                bytes_sent: 0,
                bytes_received: 0,
                active_streams: 0,
            })),
            on_new_stream: Some(Arc::new(on_new_stream)),
        };
        
        // Verify authentication
        session.verify_authentication(expected_password).await?;
        
        Ok(session)
    }
    
    pub fn id(&self) -> u64 {
        self.id
    }
    
    pub async fn is_closed(&self) -> bool {
        *self.closed.lock().await
    }
    
    pub async fn stats(&self) -> SessionStats {
        self.stats.lock().await.clone()
    }
    
    /// Close the session
    pub async fn close(&self) -> Result<()> {
        let mut closed = self.closed.lock().await;
        if *closed {
            return Ok(());
        }
        *closed = true;
        drop(closed);
        
        // Notify close
        if let Some(tx) = self.close_tx.lock().await.take() {
            let _ = tx.send(());
        }
        
        // Close all streams
        let streams = self.streams.lock().await;
        for (_, stream_tx) in streams.iter() {
            drop(stream_tx.clone());
        }
        drop(streams);
        
        Ok(())
    }
    
    /// Authenticate as client
    async fn authenticate(&self, password: &str) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let password_hash = hasher.finalize();
        
        // Get initial padding
        let padding_scheme = self.padding_scheme.lock().await;
        let padding_sizes = padding_scheme.generate_record_payload_sizes(0);
        let padding_len = padding_sizes.get(0).copied().unwrap_or(30) as usize;
        drop(padding_scheme);
        
        // Build authentication packet
        let mut auth_data = BytesMut::with_capacity(32 + 2 + padding_len);
        auth_data.extend_from_slice(&password_hash);
        auth_data.put_u16(padding_len as u16);
        auth_data.resize(32 + 2 + padding_len, 0);
        
        // Send authentication
        let mut conn = self.conn.lock().await;
        match &mut *conn {
            Connection::ClientTls(stream) => stream.write_all(&auth_data).await?,
            Connection::ServerTls(_) => return Err(AnyTlsError::Protocol("Invalid connection type".to_string())),
        };
        drop(conn);
        
        // Send settings
        let settings = HashMap::from([
            ("v".to_string(), PROTOCOL_VERSION.to_string()),
            ("client".to_string(), PROGRAM_VERSION.to_string()),
            ("padding-md5".to_string(), self.padding_scheme.lock().await.md5.clone()),
        ]);
        
        let frame = Frame::with_data(CMD_SETTINGS, 0, serialize_string_map(&settings));
        self.frame_tx.send(frame).await.map_err(|_| AnyTlsError::SessionClosed)?;
        
        Ok(())
    }
    
    /// Verify authentication as server
    async fn verify_authentication(&self, expected_password: &str) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(expected_password.as_bytes());
        let expected_hash = hasher.finalize();
        
        // Read authentication packet
        let mut conn = self.conn.lock().await;
        
        // Read password hash
        let mut password_hash = [0u8; 32];
        match &mut *conn {
            Connection::ServerTls(stream) => stream.read_exact(&mut password_hash).await?,
            Connection::ClientTls(_) => return Err(AnyTlsError::Protocol("Invalid connection type".to_string())),
        };
        
        if password_hash != expected_hash.as_slice() {
            return Err(AnyTlsError::AuthenticationFailed);
        }
        
        // Read padding length
        let mut padding_len_bytes = [0u8; 2];
        match &mut *conn {
            Connection::ServerTls(stream) => stream.read_exact(&mut padding_len_bytes).await?,
            Connection::ClientTls(_) => return Err(AnyTlsError::Protocol("Invalid connection type".to_string())),
        };
        let padding_len = u16::from_be_bytes(padding_len_bytes) as usize;
        
        // Read and discard padding
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            match &mut *conn {
                Connection::ServerTls(stream) => stream.read_exact(&mut padding).await?,
                Connection::ClientTls(_) => return Err(AnyTlsError::Protocol("Invalid connection type".to_string())),
            };
        }
        
        drop(conn);
        
        debug!("Authentication successful from client");
        Ok(())
    }
    
    /// Open a new stream (client only)
    pub async fn open_stream(&self) -> Result<Stream> {
        if !self.is_client {
            return Err(AnyTlsError::Protocol("Cannot open stream on server session".to_string()));
        }
        
        if self.is_closed().await {
            return Err(AnyTlsError::SessionClosed);
        }
        
        // Get next stream ID
        let mut next_id = self.next_stream_id.lock().await;
        let stream_id = *next_id;
        *next_id += 1;
        drop(next_id);
        
        // Create stream channel
        let (stream_tx, stream_rx) = mpsc::channel(STREAM_CHANNEL_SIZE);
        let (close_tx, close_rx) = oneshot::channel();
        
        // Register stream
        let mut streams = self.streams.lock().await;
        streams.insert(stream_id, stream_tx);
        drop(streams);
        
        // Send SYN frame
        let frame = Frame::new(CMD_SYN, stream_id);
        self.frame_tx.send(frame).await.map_err(|_| AnyTlsError::SessionClosed)?;
        
        // Update stats
        let mut stats = self.stats.lock().await;
        stats.active_streams += 1;
        drop(stats);
        
        // Create stream
        let stream = Stream::new(stream_id, stream_rx, self.frame_tx.clone(), close_tx);
        
        // Handle stream closure
        let streams = self.streams.clone();
        let stats = self.stats.clone();
        tokio::spawn(async move {
            let _ = close_rx.await;
            let mut streams = streams.lock().await;
            streams.remove(&stream_id);
            drop(streams);
            
            let mut stats = stats.lock().await;
            stats.active_streams = stats.active_streams.saturating_sub(1);
        });
        
        Ok(stream)
    }
    
    /// Run the session (spawns read and write tasks)
    pub fn run(self: Arc<Self>) {
        let self_read = self.clone();
        let self_write = self.clone();
        
        // Spawn read task
        tokio::spawn(async move {
            if let Err(e) = self_read.read_loop().await {
                error!("Session {} read loop error: {}", self_read.id, e);
            }
            let _ = self_read.close().await;
        });
        
        // Spawn write task
        tokio::spawn(async move {
            if let Err(e) = self_write.write_loop().await {
                error!("Session {} write loop error: {}", self_write.id, e);
            }
            let _ = self_write.close().await;
        });
    }
    
    /// Read loop - handles incoming frames
    async fn read_loop(&self) -> Result<()> {
        let mut header = [0u8; HEADER_SIZE];
        
        loop {
            if self.is_closed().await {
                return Ok(());
            }
            
            // Read frame header
            let mut conn = self.conn.lock().await;
            let read_result = match &mut *conn {
                Connection::ClientTls(stream) => stream.read_exact(&mut header).await,
                Connection::ServerTls(stream) => stream.read_exact(&mut header).await,
            };
            
            match read_result {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    drop(conn);
                    return Ok(());
                }
                Err(e) => {
                    drop(conn);
                    return Err(e.into());
                }
            }
            
            // Parse header
            let cmd = header[0];
            let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let length = u16::from_be_bytes([header[5], header[6]]) as usize;
            
            // Read frame data if any
            let mut data = vec![0u8; length];
            if length > 0 {
                match &mut *conn {
                    Connection::ClientTls(stream) => stream.read_exact(&mut data).await?,
                    Connection::ServerTls(stream) => stream.read_exact(&mut data).await?,
                };
            }
            drop(conn);
            
            // Update stats
            let mut stats = self.stats.lock().await;
            stats.last_activity = Instant::now();
            stats.bytes_received += (HEADER_SIZE + length) as u64;
            drop(stats);
            
            // Handle frame
            match cmd {
                CMD_PSH => {
                    let streams = self.streams.lock().await;
                    if let Some(stream_tx) = streams.get(&stream_id) {
                        let _ = stream_tx.send(Bytes::from(data)).await;
                    }
                }
                
                CMD_SYN => {
                    if self.is_client {
                        warn!("Client received SYN frame");
                        continue;
                    }
                    
                    let received_settings = *self.received_settings.lock().await;
                    if !received_settings {
                        let frame = Frame::with_data(CMD_ALERT, 0, b"client did not send its settings".to_vec());
                        let _ = self.frame_tx.send(frame).await;
                        return Err(AnyTlsError::Protocol("Client did not send settings".to_string()));
                    }
                    
                    // Create new stream for server
                    let (stream_tx, stream_rx) = mpsc::channel(STREAM_CHANNEL_SIZE);
                    let (close_tx, close_rx) = oneshot::channel();
                    
                    let mut streams = self.streams.lock().await;
                    streams.insert(stream_id, stream_tx);
                    drop(streams);
                    
                    let stream = Stream::new(stream_id, stream_rx, self.frame_tx.clone(), close_tx);
                    
                    // Update stats
                    let mut stats = self.stats.lock().await;
                    stats.active_streams += 1;
                    drop(stats);
                    
                    // Handle stream closure
                    let streams = self.streams.clone();
                    let stats = self.stats.clone();
                    tokio::spawn(async move {
                        let _ = close_rx.await;
                        let mut streams = streams.lock().await;
                        streams.remove(&stream_id);
                        drop(streams);
                        
                        let mut stats = stats.lock().await;
                        stats.active_streams = stats.active_streams.saturating_sub(1);
                    });
                    
                    // Call on_new_stream callback
                    if let Some(callback) = &self.on_new_stream {
                        callback(stream);
                    }
                }
                
                CMD_FIN => {
                    let mut streams = self.streams.lock().await;
                    if let Some(stream_tx) = streams.remove(&stream_id) {
                        drop(stream_tx);
                    }
                }
                
                CMD_SETTINGS => {
                    if self.is_client {
                        warn!("Client received SETTINGS frame");
                        continue;
                    }
                    
                    *self.received_settings.lock().await = true;
                    let settings = parse_string_map(&data);
                    
                    // Check padding scheme
                    if let Some(client_md5) = settings.get("padding-md5") {
                        let padding_scheme = self.padding_scheme.lock().await;
                        if client_md5 != &padding_scheme.md5 {
                            // Send update padding scheme
                            let frame = Frame::with_data(
                                CMD_UPDATE_PADDING_SCHEME, 
                                0, 
                                padding_scheme.raw_scheme.clone()
                            );
                            let _ = self.frame_tx.send(frame).await;
                        }
                    }
                    
                    // Check client version
                    if let Some(v_str) = settings.get("v") {
                        if let Ok(v) = v_str.parse::<u8>() {
                            if v >= 2 {
                                *self.peer_version.lock().await = v;
                                
                                // Send server settings
                                let server_settings = HashMap::from([
                                    ("v".to_string(), PROTOCOL_VERSION.to_string()),
                                ]);
                                let frame = Frame::with_data(
                                    CMD_SERVER_SETTINGS, 
                                    0, 
                                    serialize_string_map(&server_settings)
                                );
                                let _ = self.frame_tx.send(frame).await;
                            }
                        }
                    }
                }
                
                CMD_ALERT => {
                    if self.is_client {
                        error!("[Alert from server] {}", String::from_utf8_lossy(&data));
                    }
                    return Err(AnyTlsError::Protocol(format!("Alert: {}", String::from_utf8_lossy(&data))));
                }
                
                CMD_UPDATE_PADDING_SCHEME => {
                    if self.is_client {
                        if let Ok(new_scheme) = std::str::from_utf8(&data).unwrap().parse::<PaddingScheme>() {
                            info!("Updated padding scheme: {}", new_scheme.md5);
                            *self.padding_scheme.lock().await = new_scheme;
                        } else {
                            warn!("Failed to parse padding scheme update");
                        }
                    }
                }
                
                CMD_HEART_REQUEST => {
                    let frame = Frame::new(CMD_HEART_RESPONSE, stream_id);
                    let _ = self.frame_tx.send(frame).await;
                }
                
                CMD_HEART_RESPONSE => {
                    // TODO: Handle heart response for keepalive
                }
                
                CMD_SERVER_SETTINGS => {
                    if !self.is_client {
                        warn!("Server received SERVER_SETTINGS frame");
                        continue;
                    }
                    
                    let settings = parse_string_map(&data);
                    if let Some(v_str) = settings.get("v") {
                        if let Ok(v) = v_str.parse::<u8>() {
                            *self.peer_version.lock().await = v;
                        }
                    }
                }
                
                _ => {
                    debug!("Unknown command: {}", cmd);
                }
            }
        }
    }
    
    /// Write loop - handles outgoing frames with padding
    async fn write_loop(&self) -> Result<()> {
        let mut frame_rx = self.frame_rx.lock().await;
        let mut buffered_data = BytesMut::new();
        let mut buffering = self.is_client; // Client starts with buffering
        
        loop {
            tokio::select! {
                Some(frame) = frame_rx.recv() => {
                    let frame_data = frame.serialize();
                    
                    if buffering && frame.cmd == CMD_SETTINGS {
                        // Buffer the settings frame
                        buffered_data.extend_from_slice(&frame_data);
                        continue;
                    }
                    
                    // If we have buffered data, prepend it
                    let data_to_write = if !buffered_data.is_empty() {
                        buffering = false;
                        let mut combined = buffered_data.clone();
                        combined.extend_from_slice(&frame_data);
                        buffered_data.clear();
                        combined.freeze()
                    } else {
                        Bytes::from(frame_data)
                    };
                    
                    // Apply padding if needed
                    let pkt_counter = {
                        let mut counter = self.pkt_counter.lock().await;
                        let current = *counter;
                        *counter += 1;
                        current
                    };
                    
                    let write_data = if pkt_counter < self.padding_scheme.lock().await.stop {
                        self.apply_padding(data_to_write, pkt_counter).await?
                    } else {
                        data_to_write
                    };
                    
                    // Write to connection
                    let mut conn = self.conn.lock().await;
                    match &mut *conn {
                        Connection::ClientTls(stream) => stream.write_all(&write_data).await?,
                        Connection::ServerTls(stream) => stream.write_all(&write_data).await?,
                    };
                    drop(conn);
                    
                    // Update stats
                    let mut stats = self.stats.lock().await;
                    stats.last_activity = Instant::now();
                    stats.bytes_sent += write_data.len() as u64;
                }
                
                else => {
                    return Ok(());
                }
            }
        }
    }
    
    /// Apply padding to data according to padding scheme
    async fn apply_padding(&self, data: Bytes, pkt: u32) -> Result<Bytes> {
        let padding_scheme = self.padding_scheme.lock().await;
        let pkt_sizes = padding_scheme.generate_record_payload_sizes(pkt);
        drop(padding_scheme);
        
        let mut result = BytesMut::new();
        let mut data_offset = 0;
        
        for size in pkt_sizes {
            let remaining = data.len() - data_offset;
            
            if size == CHECK_MARK {
                if remaining == 0 {
                    break;
                } else {
                    continue;
                }
            }
            
            let size = size as usize;
            
            if remaining > size {
                // This packet is all payload
                result.extend_from_slice(&data[data_offset..data_offset + size]);
                data_offset += size;
            } else if remaining > 0 {
                // This packet contains padding and the last part of payload
                result.extend_from_slice(&data[data_offset..]);
                data_offset = data.len();
                
                let padding_len = size - remaining;
                if padding_len > HEADER_SIZE {
                    // Add waste frame
                    let waste_frame = Frame::with_data(CMD_WASTE, 0, vec![0u8; padding_len - HEADER_SIZE]);
                    result.extend_from_slice(&waste_frame.serialize());
                }
            } else {
                // This packet is all padding
                if size > HEADER_SIZE {
                    let waste_frame = Frame::with_data(CMD_WASTE, 0, vec![0u8; size - HEADER_SIZE]);
                    result.extend_from_slice(&waste_frame.serialize());
                }
            }
        }
        
        // Write any remaining data
        if data_offset < data.len() {
            result.extend_from_slice(&data[data_offset..]);
        }
        
        Ok(result.freeze())
    }
} 