# Test setup script for AnyTLS-RS (Windows PowerShell)

Write-Host "=== AnyTLS-RS Test Setup ===" -ForegroundColor Green

# Generate test certificates
Write-Host "`n1. Generating test certificates..." -ForegroundColor Yellow

# Create test-certs directory
if (!(Test-Path "test-certs")) {
    New-Item -ItemType Directory -Path "test-certs" | Out-Null
}

Set-Location test-certs

# Generate private key
Write-Host "Generating private key..."
& openssl genrsa -out server.key 2048

# Generate certificate request
Write-Host "Generating certificate request..."
& openssl req -new -key server.key -out server.csr -subj "/C=US/ST=Test/L=Test/O=AnyTLS/CN=anytls.example.com"

# Generate self-signed certificate (365 days)
Write-Host "Generating self-signed certificate..."
& openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

Write-Host "Certificates generated in test-certs/" -ForegroundColor Green
Set-Location ..

Write-Host "`n2. Example commands:" -ForegroundColor Yellow

Write-Host "`nStart server with custom certificate:" -ForegroundColor Cyan
Write-Host "  cargo run --bin anytls-server -- -l 0.0.0.0:8443 -p testpass --certificate test-certs\server.crt --private-key test-certs\server.key"

Write-Host "`nStart server with self-signed certificate:" -ForegroundColor Cyan
Write-Host "  cargo run --bin anytls-server -- -l 0.0.0.0:8443 -p testpass"

Write-Host "`nStart client with custom SNI:" -ForegroundColor Cyan
Write-Host "  cargo run --bin anytls-client -- -l 127.0.0.1:1080 -s localhost:8443 -p testpass --sni anytls.example.com"

Write-Host "`nStart client with insecure mode (skip cert verification):" -ForegroundColor Cyan
Write-Host "  cargo run --bin anytls-client -- -l 127.0.0.1:1080 -s localhost:8443 -p testpass --insecure"

Write-Host "`n3. Test the proxy:" -ForegroundColor Yellow

Write-Host "`nTest SOCKS5:" -ForegroundColor Cyan
Write-Host "  curl --socks5 127.0.0.1:1080 https://httpbin.org/ip"

Write-Host "`nTest HTTP CONNECT:" -ForegroundColor Cyan
Write-Host "  curl --proxy http://127.0.0.1:1080 https://httpbin.org/ip"

Write-Host "`n" 