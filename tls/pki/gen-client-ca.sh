#!/bin/bash
# gen-client-ca.sh — Step 4 of 4
#
# KEY FIX: This script now produces client/client-chain.pem in addition to
# client/client.crt. The chain file (leaf + intermediate) is what you must
# pass to openssl s_client -cert and to SSL_CTX_use_certificate_chain_file()
# in your C++ code.
#
# Why: the server's CAfile only contains the root CA. When the client sends
# just client.crt, the server receives a leaf cert whose issuer is
# "InterOrg Intermediate CA" — but it has no way to verify that issuer
# unless the client also sends the intermediate cert in the TLS handshake.
set -e

mkdir -p client

if [ ! -f intermediate-ca/intermediate-ca.crt ] || \
   [ ! -f intermediate-ca/intermediate-ca.key ]; then
  echo "ERROR: Intermediate CA not found. Run gen-intermediate-ca.sh first." >&2
  exit 1
fi

openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out client/client.key
chmod 600 client/client.key

openssl req -new \
  -key client/client.key \
  -subj "/C=US/O=MyOrg/CN=Bifrost" \
  -out client/client.csr

cat > /tmp/client.cnf << 'EOF'
[v3_client]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
basicConstraints       = critical,CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
EOF

openssl x509 -req \
  -in client/client.csr \
  -CA intermediate-ca/intermediate-ca.crt \
  -CAkey intermediate-ca/intermediate-ca.key \
  -CAcreateserial \
  -days 397 \
  -extensions v3_client \
  -extfile /tmp/client.cnf \
  -out client/client.crt

# Build client chain: leaf + intermediate
# Use this (not client.crt alone) everywhere:
#   openssl s_client -cert client/client-chain.pem
#   SSL_CTX_use_certificate_chain_file(ctx, "client/client-chain.pem")
cat client/client.crt intermediate-ca/intermediate-ca.crt \
  > client/client-chain.pem

echo "Verify client → intermediate → root:"
openssl verify \
  -CAfile root-ca/root-ca.crt \
  -untrusted intermediate-ca/intermediate-ca.crt \
  client/client.crt

# ── Consistency check ────────────────────────────────────────────────────────
INTER_SKID=$(openssl x509 -in intermediate-ca/intermediate-ca.crt -noout -text \
  | grep -A1 "Subject Key Identifier" | tail -1 | tr -d ' ')
CLIENT_AKID=$(openssl x509 -in client/client.crt -noout -text \
  | grep -A1 "Authority Key Identifier" | tail -1 | tr -d ' ')

if [ "$CLIENT_AKID" != "$INTER_SKID" ]; then
  echo ""
  echo "ERROR: AKID mismatch!" >&2
  echo "  client.crt AKID   : $CLIENT_AKID" >&2
  echo "  intermediate SKID : $INTER_SKID" >&2
  echo "  Re-run gen-intermediate-ca.sh then this script." >&2
  exit 1
fi

echo "[OK] Client cert"
echo "     Leaf  : client/client.crt"
echo "     Chain : client/client-chain.pem  (leaf + intermediate)"
echo "     Key   : client/client.key"
echo "     AKID == intermediate SKID: $INTER_SKID"
