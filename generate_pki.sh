#!/usr/bin/env bash
set -euo pipefail

# 1. Clean and setup staging directories
rm -rf pki_staging
mkdir -p pki_staging/root-ca pki_staging/server pki_staging/client

# Create a temporary unified extensions config file
cat << 'EOF' > extensions.cnf
[ root_ca_ext ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ server_ext ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ client_ext ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

echo "=== 1. Generating Strict-Compliant Root CA ==="
openssl genrsa -out pki_staging/root-ca/root-ca.key 2048
openssl req -new -x509 -days 3650 \
  -key pki_staging/root-ca/root-ca.key \
  -out pki_staging/root-ca/root-ca.crt \
  -subj "/C=US/O=BifrostDev/CN=Bifrost Unified Local Root CA" \
  -config extensions.cnf -extensions root_ca_ext

echo "=== 2. Generating Login Server Assets ==="
openssl genrsa -out pki_staging/server/server.key 2048
openssl req -new -key pki_staging/server/server.key \
  -out pki_staging/server/server.csr \
  -subj "/C=US/O=BifrostDev/CN=localhost"

openssl x509 -req -in pki_staging/server/server.csr \
  -CA pki_staging/root-ca/root-ca.crt \
  -CAkey pki_staging/root-ca/root-ca.key \
  -CAcreateserial \
  -out pki_staging/server/server.crt \
  -days 730 \
  -extfile extensions.cnf -extensions server_ext
rm -f pki_staging/root-ca/root-ca.srl

# Bundle server chain
cat pki_staging/server/server.crt pki_staging/root-ca/root-ca.crt > pki_staging/server/server-chain.pem

echo "=== 3. Generating Bifrost Client Assets ==="
openssl genrsa -out pki_staging/client/bifrost.key 2048
openssl req -new -key pki_staging/client/bifrost.key \
  -out pki_staging/client/bifrost.csr \
  -subj "/C=US/O=BifrostDev/CN=Bifrost Terminal Client"

openssl x509 -req -in pki_staging/client/bifrost.csr \
  -CA pki_staging/root-ca/root-ca.crt \
  -CAkey pki_staging/root-ca/root-ca.key \
  -CAcreateserial \
  -out pki_staging/client/bifrost.crt \
  -days 730 \
  -extfile extensions.cnf -extensions client_ext

# Bundle client chain
cat pki_staging/client/bifrost.crt pki_staging/root-ca/root-ca.crt > pki_staging/client/bifrost-chain.pem

# Clean up configuration file
rm -f extensions.cnf pki_staging/root-ca/root-ca.srl pki_staging/server/server.csr pki_staging/client/bifrost.csr

echo "=== PKI Generation Complete! ==="