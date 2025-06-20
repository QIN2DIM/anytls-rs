use anyhow::{Context, Result};
use anytls_core::{PaddingScheme, Session, PROGRAM_VERSION};
use bytes::{BufMut, BytesMut};
use clap::Parser;
use rustls::pki_types::ServerName;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, error};

#[derive(Parser, Debug)]
#[command(author, version, about = "AnyTLS client", long_about = None)]
struct Args {
    /// Local HTTP/SOCKS5 mixed listen address
    #[arg(short = 'l', long, default_value = "127.0.0.1:1080")]
    listen: String,
    
    /// Server address
    #[arg(short = 's', long)]
    server: String,
    
    /// Server Name Indication (SNI)
    #[arg(long, default_value = "")]
    sni: String,
    
    /// Skip TLS certificate verification (insecure)
    #[arg(long, default_value = "false")]
    insecure: bool,
    
    /// Password
    #[arg(short = 'p', long)]
    password: String,
    
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Clone)]
struct SessionManager {
    server_addr: String,
    password: String,
    tls_config: Arc<rustls::ClientConfig>,
    padding_scheme: Arc<Mutex<PaddingScheme>>,
    idle_sessions: Arc<Mutex<VecDeque<Arc<Session>>>>,
    session_counter: Arc<Mutex<u64>>,
    server_name: String,
}

impl SessionManager {
    fn new(server_addr: String, password: String, tls_config: Arc<rustls::ClientConfig>, server_name: String) -> Self {
        Self {
            server_addr,
            password,
            tls_config,
            padding_scheme: Arc::new(Mutex::new(PaddingScheme::default())),
            idle_sessions: Arc::new(Mutex::new(VecDeque::new())),
            session_counter: Arc::new(Mutex::new(0)),
            server_name,
        }
    }
    
    async fn get_or_create_session(&self) -> Result<Arc<Session>> {
        // Try to get an idle session
        let mut idle = self.idle_sessions.lock().await;
        if let Some(session) = idle.pop_front() {
            if !session.is_closed().await {
                drop(idle);
                return Ok(session);
            }
        }
        drop(idle);
        
        // Create new session
        self.create_session().await
    }
    
    async fn create_session(&self) -> Result<Arc<Session>> {
        // Connect to server
        let tcp = TcpStream::connect(&self.server_addr).await
            .context("Failed to connect to server")?;
        
        // TLS handshake
        let connector = TlsConnector::from(self.tls_config.clone());
        let dnsname = ServerName::try_from(self.server_name.clone())
            .map_err(|_| anyhow::anyhow!("Invalid server name"))?;
        let tls_stream = connector.connect(dnsname, tcp).await
            .context("TLS handshake failed")?;
        
        // Create session
        let padding_scheme = self.padding_scheme.lock().await.clone();
        let session = Session::new_client(tls_stream, &self.password, padding_scheme).await
            .context("Failed to create session")?;
        
        let session = Arc::new(session);
        
        // Start session
        session.clone().run();
        
        // Update counter
        let mut counter = self.session_counter.lock().await;
        *counter += 1;
        
        info!("Created new session #{}", *counter);
        
        Ok(session)
    }
    
    async fn return_session(&self, session: Arc<Session>) {
        if !session.is_closed().await {
            let mut idle = self.idle_sessions.lock().await;
            idle.push_back(session);
        }
    }
    
    async fn cleanup_idle_sessions(&self, timeout: Duration, min_sessions: usize) {
        let mut idle = self.idle_sessions.lock().await;
        let mut to_remove = Vec::new();
        
        let now = Instant::now();
        let mut kept = 0;
        
        for (i, session) in idle.iter().enumerate() {
            let stats = session.stats().await;
            
            if kept < min_sessions {
                kept += 1;
                continue;
            }
            
            if now.duration_since(stats.last_activity) > timeout || session.is_closed().await {
                to_remove.push(i);
            }
        }
        
        // Remove in reverse order to maintain indices
        for i in to_remove.into_iter().rev() {
            if let Some(session) = idle.remove(i) {
                let _ = session.close().await;
            }
        }
    }
}

async fn handle_socks5_connection(
    mut stream: TcpStream,
    session_manager: Arc<SessionManager>,
) -> Result<()> {
    // SOCKS5 greeting
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    
    if buf[0] != 0x05 {
        return Err(anyhow::anyhow!("Not SOCKS5"));
    }
    
    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    
    // No authentication required
    stream.write_all(&[0x05, 0x00]).await?;
    
    // Read connect request
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    
    if header[0] != 0x05 || header[1] != 0x01 {
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
        return Err(anyhow::anyhow!("Only CONNECT is supported"));
    }
    
    // Parse destination address
    let dest_addr = match header[3] {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            format!("{}:{}", std::net::Ipv4Addr::from(addr), u16::from_be_bytes(port))
        }
        0x03 => {
            // Domain
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            format!("{}:{}", String::from_utf8_lossy(&domain), u16::from_be_bytes(port))
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            format!("[{}]:{}", std::net::Ipv6Addr::from(addr), u16::from_be_bytes(port))
        }
        _ => {
            stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
            return Err(anyhow::anyhow!("Unsupported address type"));
        }
    };
    
    debug!("SOCKS5 connection to {}", dest_addr);
    
    // Get session and open stream
    let session = match session_manager.get_or_create_session().await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get/create session: {}", e);
            // Send connection refused error to client
            stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
            return Err(e);
        }
    };
    
    let mut anytls_stream = match session.open_stream().await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to open stream: {}", e);
            // Send general failure error to client
            stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
            session_manager.return_session(session).await;
            return Err(e.into());
        }
    };
    
    // Send destination address in SOCKS format
    let mut dest_data = BytesMut::new();
    if let Ok(addr) = dest_addr.parse::<SocketAddr>() {
        match addr {
            SocketAddr::V4(v4) => {
                dest_data.put_u8(0x01);
                dest_data.put_slice(&v4.ip().octets());
                dest_data.put_u16(v4.port());
            }
            SocketAddr::V6(v6) => {
                dest_data.put_u8(0x04);
                dest_data.put_slice(&v6.ip().octets());
                dest_data.put_u16(v6.port());
            }
        }
    } else {
        // Try to parse as domain:port
        if let Some((domain, port)) = dest_addr.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                dest_data.put_u8(0x03);
                dest_data.put_u8(domain.len() as u8);
                dest_data.put_slice(domain.as_bytes());
                dest_data.put_u16(port);
            } else {
                return Err(anyhow::anyhow!("Invalid destination format"));
            }
        } else {
            return Err(anyhow::anyhow!("Invalid destination format"));
        }
    }
    
    // Send destination address to server
    if let Err(e) = anytls_stream.write_all(&dest_data).await {
        error!("Failed to send destination address: {}", e);
        // Send general failure error to client
        stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
        session_manager.return_session(session).await;
        return Err(e.into());
    }
    
    debug!("Sent destination address to server, starting proxy");
    
    // Send success response
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
    
    // Proxy data
    let (mut stream_read, mut stream_write) = stream.into_split();
    let (mut anytls_read, mut anytls_write) = tokio::io::split(anytls_stream);
    
    let client_to_server = tokio::spawn(async move {
        match tokio::io::copy(&mut stream_read, &mut anytls_write).await {
            Ok(bytes) => {
                debug!("Client to server copy completed: {} bytes", bytes);
            }
            Err(e) => {
                debug!("Client to server copy error: {}", e);
            }
        }
    });
    
    let server_to_client = tokio::spawn(async move {
        match tokio::io::copy(&mut anytls_read, &mut stream_write).await {
            Ok(bytes) => {
                debug!("Server to client copy completed: {} bytes", bytes);
            }
            Err(e) => {
                debug!("Server to client copy error: {}", e);
            }
        }
    });
    
    // Wait for both tasks to complete
    let _ = tokio::join!(client_to_server, server_to_client);
    
    debug!("SOCKS5 connection completed for {}", dest_addr);
    session_manager.return_session(session).await;
    
    Ok(())
}

/// Detect protocol type from first byte
async fn detect_protocol(stream: &mut TcpStream) -> Result<u8> {
    let mut buf = [0u8; 1];
    stream.peek(&mut buf).await?;
    Ok(buf[0])
}

/// Parse HTTP CONNECT request
async fn parse_http_connect(stream: &mut TcpStream) -> Result<String> {
    let mut buffer = Vec::new();
    let mut temp_buf = [0u8; 1];
    
    // Read until we find \r\n\r\n
    loop {
        stream.read_exact(&mut temp_buf).await?;
        buffer.push(temp_buf[0]);
        
        if buffer.len() >= 4 && &buffer[buffer.len()-4..] == b"\r\n\r\n" {
            break;
        }
        
        if buffer.len() > 8192 {
            return Err(anyhow::anyhow!("HTTP header too large"));
        }
    }
    
    let request = String::from_utf8_lossy(&buffer);
    let lines: Vec<&str> = request.lines().collect();
    
    if lines.is_empty() {
        return Err(anyhow::anyhow!("Empty HTTP request"));
    }
    
    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "CONNECT" {
        return Err(anyhow::anyhow!("Not a CONNECT request"));
    }
    
    Ok(parts[1].to_string())
}

/// Handle HTTP CONNECT proxy
async fn handle_http_connect(
    mut stream: TcpStream,
    session_manager: Arc<SessionManager>,
) -> Result<()> {
    // Parse CONNECT request
    let dest_addr = parse_http_connect(&mut stream).await?;
    
    debug!("HTTP CONNECT to {}", dest_addr);
    
    // Get session and open stream
    let session = match session_manager.get_or_create_session().await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get/create session: {}", e);
            let error_response = format!(
                "HTTP/1.1 502 Bad Gateway\r\n\
                Content-Length: 0\r\n\
                Connection: close\r\n\r\n"
            );
            let _ = stream.write_all(error_response.as_bytes()).await;
            return Err(e);
        }
    };
    
    let mut anytls_stream = match session.open_stream().await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to open stream: {}", e);
            let error_response = format!(
                "HTTP/1.1 503 Service Unavailable\r\n\
                Content-Length: 0\r\n\
                Connection: close\r\n\r\n"
            );
            let _ = stream.write_all(error_response.as_bytes()).await;
            session_manager.return_session(session).await;
            return Err(e.into());
        }
    };
    
    // Send destination address in SOCKS format
    let mut dest_data = BytesMut::new();
    if let Ok(addr) = dest_addr.parse::<SocketAddr>() {
        match addr {
            SocketAddr::V4(v4) => {
                dest_data.put_u8(0x01);
                dest_data.put_slice(&v4.ip().octets());
                dest_data.put_u16(v4.port());
            }
            SocketAddr::V6(v6) => {
                dest_data.put_u8(0x04);
                dest_data.put_slice(&v6.ip().octets());
                dest_data.put_u16(v6.port());
            }
        }
    } else {
        // Try to parse as domain:port
        if let Some((domain, port)) = dest_addr.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                dest_data.put_u8(0x03);
                dest_data.put_u8(domain.len() as u8);
                dest_data.put_slice(domain.as_bytes());
                dest_data.put_u16(port);
            } else {
                return Err(anyhow::anyhow!("Invalid destination format"));
            }
        } else {
            return Err(anyhow::anyhow!("Invalid destination format"));
        }
    }
    
    // Send destination address to server
    if let Err(e) = anytls_stream.write_all(&dest_data).await {
        error!("Failed to send destination address: {}", e);
        let error_response = format!(
            "HTTP/1.1 503 Service Unavailable\r\n\
            Content-Length: 0\r\n\
            Connection: close\r\n\r\n"
        );
        let _ = stream.write_all(error_response.as_bytes()).await;
        session_manager.return_session(session).await;
        return Err(e.into());
    }
    
    debug!("Sent destination address to server, starting proxy");
    
    // Send 200 Connection Established
    let success_response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    stream.write_all(success_response.as_bytes()).await?;
    
    // Proxy data
    let (mut stream_read, mut stream_write) = stream.into_split();
    let (mut anytls_read, mut anytls_write) = tokio::io::split(anytls_stream);
    
    let client_to_server = tokio::spawn(async move {
        match tokio::io::copy(&mut stream_read, &mut anytls_write).await {
            Ok(bytes) => {
                debug!("Client to server copy completed: {} bytes", bytes);
            }
            Err(e) => {
                debug!("Client to server copy error: {}", e);
            }
        }
    });
    
    let server_to_client = tokio::spawn(async move {
        match tokio::io::copy(&mut anytls_read, &mut stream_write).await {
            Ok(bytes) => {
                debug!("Server to client copy completed: {} bytes", bytes);
            }
            Err(e) => {
                debug!("Server to client copy error: {}", e);
            }
        }
    });
    
    // Wait for both tasks to complete
    let _ = tokio::join!(client_to_server, server_to_client);
    
    debug!("HTTP CONNECT completed for {}", dest_addr);
    session_manager.return_session(session).await;
    
    Ok(())
}

/// Handle incoming connection with protocol detection
async fn handle_connection(
    mut stream: TcpStream,
    session_manager: Arc<SessionManager>,
) -> Result<()> {
    // Detect protocol by first byte
    let first_byte = detect_protocol(&mut stream).await?;
    
    match first_byte {
        0x05 => {
            // SOCKS5 protocol
            debug!("Detected SOCKS5 protocol");
            handle_socks5_connection(stream, session_manager).await
        }
        b'C' | b'c' => {
            // Likely HTTP CONNECT
            debug!("Detected HTTP protocol");
            handle_http_connect(stream, session_manager).await
        }
        _ => {
            debug!("Unknown protocol, first byte: 0x{:02x}", first_byte);
            Err(anyhow::anyhow!("Unsupported protocol"))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Setup logging
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));
    
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
    
    info!("[Client] {}", PROGRAM_VERSION);
    info!("[Client] HTTP/SOCKS5 {} => {}", args.listen, args.server);
    
    // Determine SNI hostname
    let server_name = if !args.sni.is_empty() {
        // Use provided SNI
        info!("[Client] Using SNI: {}", args.sni);
        args.sni.clone()
    } else {
        // Extract hostname from server address
        let hostname = args.server.split(':').next().unwrap_or("localhost").to_string();
        info!("[Client] Using server hostname as SNI: {}", hostname);
        hostname
    };
    
    // Setup TLS configuration
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
    );
    
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    // Check if SNI is an IP address (which means we should skip verification)
    let is_ip = server_name.parse::<std::net::IpAddr>().is_ok();
    if is_ip || args.insecure {
        if is_ip {
            info!("[Client] SNI is an IP address, skipping certificate verification");
        } else if args.insecure {
            info!("[Client] Insecure mode enabled, skipping certificate verification");
        }
        
        // Create a custom certificate verifier that accepts any certificate
        #[derive(Debug)]
        struct InsecureVerifier;
        
        impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer,
                _intermediates: &[rustls::pki_types::CertificateDer],
                _server_name: &rustls::pki_types::ServerName,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA512,
                    rustls::SignatureScheme::ED25519,
                ]
            }
        }
        
        tls_config.dangerous()
            .set_certificate_verifier(Arc::new(InsecureVerifier));
    }
    
    let tls_config = Arc::new(tls_config);
    
    // Create session manager with SNI info
    let session_manager = Arc::new(SessionManager::new(
        args.server.clone(),
        args.password.clone(),
        tls_config,
        server_name,
    ));
    
    // Start cleanup task
    let cleanup_manager = session_manager.clone();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            cleanup_manager.cleanup_idle_sessions(Duration::from_secs(60), 5).await;
        }
    });
    
    // Listen for connections
    let listener = TcpListener::bind(&args.listen).await
        .context("Failed to bind listener")?;
    
    info!("HTTP/SOCKS5 mixed proxy server listening on {}", args.listen);
    
    loop {
        let (stream, addr) = listener.accept().await?;
        let session_manager = session_manager.clone();
        
        tokio::spawn(async move {
            debug!("New connection from {}", addr);
            if let Err(e) = handle_connection(stream, session_manager).await {
                debug!("Connection error: {}", e);
            }
        });
    }
} 