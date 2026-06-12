#!/bin/bash
# gen-intermediate-ca.sh — Step 2 of 4
#
# WARNING: If you re-run this script, the intermediate key changes.
# You MUST then re-run gen-server-ca.sh AND gen-client-ca.sh immediately
# after — otherwise the server and client certs will have an AKID that
# points to the old (now nonexistent) intermediate key, breaking the chain.
#
# Root cause of "unable to get local issuer certificate":
#   client.crt  →  AKID: <old intermediate SKID>   (doesn't exist anymore)
#   intermediate-ca.crt → SKID: <new intermediate SKID>
#   Verifier cannot find the issuer → verification fails.
set -e

mkdir -p intermediate-ca
chmod 700 intermediate-ca

if [ ! -f root-ca/root-ca.crt ] || [ ! -f root-ca/root-ca.key ]; then
  echo "ERROR: Root CA not found. Run gen-root-ca.sh first." >&2
  exit 1
fi

openssl genpkey -algorithm ED25519 \
  -out intermediate-ca/intermediate-ca.key
chmod 600 intermediate-ca/intermediate-ca.key

openssl req -new \
  -key intermediate-ca/intermediate-ca.key \
  -subj "/C=US/O=InterOrg/CN=InterOrg Intermediate CA" \
  -out intermediate-ca/intermediate-ca.csr

cat > /tmp/intermediate-ca.cnf << 'EOF'
[v3_intermediate_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:TRUE,pathlen:0
keyUsage               = critical, digitalSignature, keyCertSign, cRLSign
EOF

openssl x509 -req \
  -in intermediate-ca/intermediate-ca.csr \
  -CA root-ca/root-ca.crt \
  -CAkey root-ca/root-ca.key \
  -CAcreateserial \
  -days 3650 \
  -extensions v3_intermediate_ca \
  -extfile /tmp/intermediate-ca.cnf \
  -out intermediate-ca/intermediate-ca.crt

echo "Verify intermediate → root:"
openssl verify -CAfile root-ca/root-ca.crt intermediate-ca/intermediate-ca.crt

SKID=$(openssl x509 -in intermediate-ca/intermediate-ca.crt -noout -text \
  | grep -A1 "Subject Key Identifier" | tail -1 | tr -d ' ')
echo "[OK] Intermediate CA  SKID: $SKID"
echo ""
echo "IMPORTANT: Now run gen-server-ca.sh and gen-client-ca.sh to re-sign"
echo "           all leaf certs against this new intermediate key."
