#!/bin/bash

# Test setup script for AnyTLS-RS

echo "=== AnyTLS-RS Test Setup ==="

# Generate test certificates
echo "1. Generating test certificates..."
mkdir -p test-certs
cd test-certs

# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate request
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=Test/L=Test/O=AnyTLS/CN=anytls.example.com"

# Generate self-signed certificate (365 days)
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

echo "Certificates generated in test-certs/"
cd ..

echo ""
echo "2. Example commands:"
echo ""
echo "Start server with custom certificate:"
echo "  cargo run --bin anytls-server -- -l 0.0.0.0:8443 -p testpass --certificate test-certs/server.crt --private-key test-certs/server.key"
echo ""
echo "Start server with self-signed certificate:"
echo "  cargo run --bin anytls-server -- -l 0.0.0.0:8443 -p testpass"
echo ""
echo "Start client with custom SNI:"
echo "  cargo run --bin anytls-client -- -l 127.0.0.1:1080 -s localhost:8443 -p testpass --sni anytls.example.com"
echo ""
echo "Start client with insecure mode (skip cert verification):"
echo "  cargo run --bin anytls-client -- -l 127.0.0.1:1080 -s localhost:8443 -p testpass --insecure"
echo ""
echo "3. Test the proxy:"
echo ""
echo "Test SOCKS5:"
echo "  curl --socks5 127.0.0.1:1080 https://httpbin.org/ip"
echo ""
echo "Test HTTP CONNECT:"
echo "  curl --proxy http://127.0.0.1:1080 https://httpbin.org/ip"
echo "" 