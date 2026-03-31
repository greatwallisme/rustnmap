#!/bin/sh
# Generate self-signed SSL certificate for RustNmap test range
set -e

SSL_DIR="$(cd "$(dirname "$0")" && pwd)"

# Generate RSA key and certificate with SAN
openssl req -x509 -newkey rsa:2048 \
    -keyout "${SSL_DIR}/server.key" \
    -out "${SSL_DIR}/server.crt" \
    -days 3650 -nodes \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=RustNmap Test/OU=Testing/CN=test.rustnmap.local" \
    -addext "subjectAltName=DNS:test.rustnmap.local,DNS:*.rustnmap.local,IP:172.28.0.3"

# Also generate ECDSA certificate
openssl ecparam -genkey -name prime256v1 | \
    openssl ec -out "${SSL_DIR}/server-ec.key" 2>/dev/null

openssl req -x509 -new -key "${SSL_DIR}/server-ec.key" \
    -out "${SSL_DIR}/server-ec.crt" -days 3650 -nodes \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=RustNmap Test/OU=Testing-ECDSA/CN=test.rustnmap.local" \
    -addext "subjectAltName=DNS:test.rustnmap.local,DNS:*.rustnmap.local,IP:172.28.0.3"

echo "SSL certificates generated in ${SSL_DIR}/"
ls -la "${SSL_DIR}/"
