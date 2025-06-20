use anyhow::{Context, Result};
use anytls_core::{PaddingScheme, Session, Stream, PROGRAM_VERSION};
use clap::Parser;
use rcgen::{generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{debug, error, info};
use std::time::Duration;
use std::fs::File;
use std::io::BufReader;

#[derive(Parser, Debug)]
#[command(author, version, about = "AnyTLS server", long_about = None)]
struct Args {
    /// Server listen address
    #[arg(short = 'l', long, default_value = "0.0.0.0:8443")]
    listen: String,
    
    /// Password
    #[arg(short = 'p', long)]
    password: String,
    
    /// Padding scheme file
    #[arg(long)]
    padding_scheme: Option<String>,
    
    /// Certificate file path (PEM format)
    #[arg(long)]
    certificate: Option<String>,
    
    /// Private key file path (PEM format)
    #[arg(long)]
    private_key: Option<String>,
    
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Generate a self-signed certificate
fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let subject_alt_names = vec!["localhost".to_string()];
    let certified_key = generate_simple_self_signed(subject_alt_names)?;
    let cert_der = CertificateDer::from(certified_key.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(certified_key.key_pair.serialize_der().into());
    
    Ok((
        vec![cert_der],
        key_der,
    ))
}

/// Load certificate chain and private key from files
fn load_certs_and_key(cert_path: &str, key_path: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Load certificate chain
    let cert_file = File::open(cert_path)
        .context(format!("Failed to open certificate file: {}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;
    
    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in {}", cert_path));
    }
    
    // Load private key
    let key_file = File::open(key_path)
        .context(format!("Failed to open private key file: {}", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    
    // Try different private key formats
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to parse private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;
    
    Ok((certs, key))
}

async fn handle_stream(mut stream: Stream) -> Result<()> {
    // Add a small delay to ensure the destination address data has been processed
    // This is a workaround for the race condition between stream creation and data arrival
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    
    // Read destination address (SOCKS format)
    let atyp = match stream.read_u8().await {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to read address type: {}", e);
            return Err(e.into());
        }
    };
    
    let dest_addr = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let port = stream.read_u16().await?;
            format!("{}:{}", std::net::Ipv4Addr::from(addr), port)
        }
        0x03 => {
            // Domain
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            format!("{}:{}", String::from_utf8_lossy(&domain), port)
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let port = stream.read_u16().await?;
            format!("[{}]:{}", std::net::Ipv6Addr::from(addr), port)
        }
        _ => {
            error!("Unsupported address type: {}", atyp);
            return Err(anyhow::anyhow!("Unsupported address type: {}", atyp));
        }
    };
    
    debug!("Proxying to {}", dest_addr);
    
    // Check for UDP-over-TCP
    if dest_addr.contains("udp-over-tcp.arpa") {
        // TODO: Implement UDP-over-TCP support
        error!("UDP-over-TCP not yet implemented");
        return Err(anyhow::anyhow!("UDP-over-TCP not yet implemented"));
    }
    
    // Connect to destination with timeout
    let connect_timeout = Duration::from_secs(30);
    let dest_stream = match tokio::time::timeout(connect_timeout, TcpStream::connect(&dest_addr)).await {
        Ok(Ok(s)) => {
            debug!("Successfully connected to {}", dest_addr);
            s
        }
        Ok(Err(e)) => {
            error!("Failed to connect to {}: {}", dest_addr, e);
            // Explicitly close the stream to notify the client
            drop(stream);
            return Err(anyhow::anyhow!("Failed to connect to {}: {}", dest_addr, e));
        }
        Err(_) => {
            error!("Connection to {} timed out", dest_addr);
            // Explicitly close the stream to notify the client
            drop(stream);
            return Err(anyhow::anyhow!("Connection to {} timed out", dest_addr));
        }
    };
    
    debug!("Starting data proxy for {}", dest_addr);
    
    // Split streams
    let (mut stream_read, mut stream_write) = tokio::io::split(stream);
    let (mut dest_read, mut dest_write) = dest_stream.into_split();
    
    // Proxy data bidirectionally
    let client_to_dest = tokio::spawn(async move {
        match tokio::io::copy(&mut stream_read, &mut dest_write).await {
            Ok(bytes) => {
                debug!("Client to destination copy completed: {} bytes", bytes);
            }
            Err(e) => {
                debug!("Client to destination copy error: {}", e);
            }
        }
    });
    
    let dest_to_client = tokio::spawn(async move {
        match tokio::io::copy(&mut dest_read, &mut stream_write).await {
            Ok(bytes) => {
                debug!("Destination to client copy completed: {} bytes", bytes);
            }
            Err(e) => {
                debug!("Destination to client copy error: {}", e);
            }
        }
    });
    
    // Wait for either direction to complete
    tokio::select! {
        _ = client_to_dest => {
            debug!("Client to destination copy finished for {}", dest_addr);
        }
        _ = dest_to_client => {
            debug!("Destination to client copy finished for {}", dest_addr);
        }
    }
    
    debug!("Stream handling completed for {}", dest_addr);
    Ok(())
}

async fn handle_connection(
    stream: TlsStream<TcpStream>,
    expected_password: &str,
    padding_scheme: PaddingScheme,
) -> Result<()> {
    let peer_addr = stream.get_ref().0.peer_addr()?;
    debug!("New connection from {}", peer_addr);
    
    // Create session with authentication
    let session = Session::new_server(
        stream,
        expected_password,
        padding_scheme,
        Box::new(|stream| {
            tokio::spawn(async move {
                if let Err(e) = handle_stream(stream).await {
                    // Only log the error, don't propagate it to avoid closing the entire session
                    error!("Stream handling error: {}", e);
                }
            });
        }),
    ).await?;
    
    // Run session
    let session_arc = Arc::new(session);
    session_arc.clone().run();
    
    // Keep the connection alive until the session is closed
    while !session_arc.is_closed().await {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    
    Ok(())
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
    
    info!("[Server] {}", PROGRAM_VERSION);
    info!("[Server] Listening TCP {}", args.listen);
    
    // Load padding scheme if provided
    let padding_scheme = if let Some(path) = args.padding_scheme {
        let content = tokio::fs::read_to_string(&path).await
            .context("Failed to read padding scheme file")?;
        content.parse::<PaddingScheme>()
            .context("Failed to parse padding scheme")?
    } else {
        PaddingScheme::default()
    };
    
    if padding_scheme.md5 != PaddingScheme::default().md5 {
        info!("Loaded custom padding scheme: {}", padding_scheme.md5);
    }
    
    // Load certificate and private key if provided
    let (cert_chain, key_der) = if let (Some(cert_path), Some(key_path)) = (args.certificate.as_ref(), args.private_key.as_ref()) {
        info!("Loading certificate from {} and private key from {}", cert_path, key_path);
        load_certs_and_key(cert_path, key_path)
            .context("Failed to load certificate and private key")?
    } else if args.certificate.is_some() || args.private_key.is_some() {
        return Err(anyhow::anyhow!("Both certificate and private-key must be provided together"));
    } else {
        info!("No certificate provided, generating self-signed certificate");
        generate_self_signed_cert()
            .context("Failed to generate self-signed certificate")?
    };
    
    // Setup TLS configuration
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .context("Failed to create TLS config")?;
    
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    
    // Listen for connections
    let listener = TcpListener::bind(&args.listen).await
        .context("Failed to bind listener")?;
    
    info!("Server listening on {}", args.listen);
    
    loop {
        let (stream, addr) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let password = args.password.clone();
        let padding = padding_scheme.clone();
        
        tokio::spawn(async move {
            debug!("Accepted connection from {}", addr);
            
            // TLS handshake
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("TLS handshake failed from {}: {}", addr, e);
                    return;
                }
            };
            
            // Handle connection
            if let Err(e) = handle_connection(tls_stream, &password, padding).await {
                debug!("Connection handling error from {}: {}", addr, e);
            }
        });
    }
} 