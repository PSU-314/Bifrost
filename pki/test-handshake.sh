#!/bin/bash

# NOTE: This script is faulty

set -e

# ── Pre-flight: verify PKI consistency ─────────────────────────────────────
echo "=== Pre-flight AKID consistency check ==="

INTER_SKID=$(openssl x509 -in intermediate-ca/intermediate-ca.crt -noout -text \
  | grep -A1 "Subject Key Identifier" | tail -1 | tr -d ' ')
SERVER_AKID=$(openssl x509 -in server/server.crt -noout -text \
  | grep -A1 "Authority Key Identifier" | tail -1 | tr -d ' ')
CLIENT_AKID=$(openssl x509 -in client/client.crt -noout -text \
  | grep -A1 "Authority Key Identifier" | tail -1 | tr -d ' ')

echo "Intermediate SKID : $INTER_SKID"
echo "Server AKID       : $SERVER_AKID"
echo "Client AKID       : $CLIENT_AKID"

if [ "$SERVER_AKID" != "$INTER_SKID" ]; then
  echo ""
  echo "FATAL: server.crt was signed by a different intermediate." >&2
  echo "Re-run gen-intermediate-ca.sh, then gen-server-ca.sh, then gen-client-ca.sh." >&2
  exit 1
fi
if [ "$CLIENT_AKID" != "$INTER_SKID" ]; then
  echo ""
  echo "FATAL: client.crt was signed by a different intermediate." >&2
  echo "Re-run gen-intermediate-ca.sh, then gen-server-ca.sh, then gen-client-ca.sh." >&2
  exit 1
fi
echo "All AKID values consistent."

# ── Build chain files if missing ────────────────────────────────────────────
if [ ! -f server/server-chain.pem ]; then
  cat server/server.crt intermediate-ca/intermediate-ca.crt \
    > server/server-chain.pem
  echo "Built server/server-chain.pem"
fi

if [ ! -f client/client-chain.pem ]; then
  cat client/client.crt intermediate-ca/intermediate-ca.crt \
    > client/client-chain.pem
  echo "Built client/client-chain.pem"
fi

# ── Full chain verification ──────────────────────────────────────────────────
echo ""
echo "=== Chain verification ==="
openssl verify \
  -CAfile root-ca/root-ca.crt \
  -untrusted intermediate-ca/intermediate-ca.crt \
  server/server.crt
openssl verify \
  -CAfile root-ca/root-ca.crt \
  -untrusted intermediate-ca/intermediate-ca.crt \
  client/client.crt

# ── Start server ────────────────────────────────────────────────────────────
echo ""
echo "=== Starting s_server ==="
echo "Command:"
echo "  openssl s_server \\"
echo "    -cert       server/server.crt \\"
echo "    -cert_chain intermediate-ca/intermediate-ca.crt \\"
echo "    -key        server/server.key \\"
echo "    -CAfile     root-ca/root-ca.crt \\"
echo "    -Verify 2 \\"
echo "    -port 8443 \\"
echo "    -tls1_2"
echo ""

openssl s_server \
  -cert       server/server.crt \
  -cert_chain intermediate-ca/intermediate-ca.crt \
  -key        server/server.key \
  -CAfile     root-ca/root-ca.crt \
  -Verify 2 \
  -port 8443 \
  -tls1_3 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"
sleep 1

# ── Run client ───────────────────────────────────────────────────────────────
echo ""
echo "=== Running s_client ==="
echo "Command:"
echo "  openssl s_client \\"
echo "    -connect localhost:8443 \\"
echo "    -CAfile  root-ca/root-ca.crt \\"
echo "    -cert    client/client-chain.pem \\"
echo "    -key     client/client.key \\"
echo "    -tls1_2"
echo ""

echo "PING" | openssl s_client \
  -connect  localhost:8443 \
  -CAfile   root-ca/root-ca.crt \
  -cert     client/client-chain.pem \
  -key      client/client.key \
  -tls1_3   \
  -verify_return_error \
  -brief

CLIENT_EXIT=$?

kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
if [ $CLIENT_EXIT -eq 0 ]; then
  echo "SUCCESS: mTLS handshake completed cleanly."
else
  echo "FAILED: client exited with code $CLIENT_EXIT"
fi
