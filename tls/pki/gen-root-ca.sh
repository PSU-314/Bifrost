#!/bin/bash
# gen-root-ca.sh — Step 1 of 4
# Run this ONCE. If you re-run it, you MUST re-run all four scripts in order.
set -e

mkdir -p root-ca
chmod 700 root-ca

openssl genpkey -algorithm ED25519 \
  -out root-ca/root-ca.key
chmod 600 root-ca/root-ca.key

cat > /tmp/root-ca.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:TRUE
keyUsage               = critical, digitalSignature, keyCertSign, cRLSign
EOF

openssl req -new -x509 \
  -key root-ca/root-ca.key \
  -sha256 \
  -days 7300 \
  -subj "/C=IN/O=Aufer/CN=Aufer Root CA" \
  -extensions v3_ca \
  -config /tmp/root-ca.cnf \
  -out root-ca/root-ca.crt

echo "[OK] Root CA"
echo "     Key : root-ca/root-ca.key"
echo "     Cert: root-ca/root-ca.crt"
echo ""
echo "Verify:"
openssl x509 -in root-ca/root-ca.crt -noout -text \
  | grep -E "(Subject:|Issuer:|CA:|keyCertSign)"
