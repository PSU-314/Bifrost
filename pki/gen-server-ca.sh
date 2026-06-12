#!/bin/bash
# gen-server-ca.sh — Step 3 of 4
set -e

mkdir -p server

if [ ! -f intermediate-ca/intermediate-ca.crt ] || \
   [ ! -f intermediate-ca/intermediate-ca.key ]; then
  echo "ERROR: Intermediate CA not found. Run gen-intermediate-ca.sh first." >&2
  exit 1
fi

openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out server/server.key
chmod 600 server/server.key

openssl req -new \
  -key server/server.key \
  -subj "/C=US/O=MyOrg/CN=localhost" \
  -out server/server.csr

cat > /tmp/server.cnf << 'EOF'
[v3_server]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
basicConstraints       = critical,CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = DNS:localhost, IP:127.0.0.1
EOF

openssl x509 -req \
  -in server/server.csr \
  -CA intermediate-ca/intermediate-ca.crt \
  -CAkey intermediate-ca/intermediate-ca.key \
  -CAcreateserial \
  -days 397 \
  -extensions v3_server \
  -extfile /tmp/server.cnf \
  -out server/server.crt

# Build chain: leaf + intermediate (root is NOT included)
# The server sends this chain during the TLS handshake so clients can
# walk the full path without external fetches.
cat server/server.crt intermediate-ca/intermediate-ca.crt \
  > server/server-chain.pem

echo "Verify server → intermediate → root:"
openssl verify \
  -CAfile root-ca/root-ca.crt \
  -untrusted intermediate-ca/intermediate-ca.crt \
  server/server.crt

# ── Consistency check ────────────────────────────────────────────────────────
# The AKID of the server cert must equal the SKID of the intermediate cert.
# A mismatch means this cert was signed by a different intermediate key.
INTER_SKID=$(openssl x509 -in intermediate-ca/intermediate-ca.crt -noout -text \
  | grep -A1 "Subject Key Identifier" | tail -1 | tr -d ' ')
SERVER_AKID=$(openssl x509 -in server/server.crt -noout -text \
  | grep -A1 "Authority Key Identifier" | tail -1 | tr -d ' ')

if [ "$SERVER_AKID" != "$INTER_SKID" ]; then
  echo ""
  echo "ERROR: AKID mismatch!" >&2
  echo "  server.crt AKID    : $SERVER_AKID" >&2
  echo "  intermediate SKID  : $INTER_SKID" >&2
  echo "  Re-run gen-intermediate-ca.sh then this script." >&2
  exit 1
fi

echo "[OK] Server cert"
echo "     Leaf  : server/server.crt"
echo "     Chain : server/server-chain.pem  (leaf + intermediate)"
echo "     Key   : server/server.key"
echo "     AKID == intermediate SKID: $INTER_SKID"
