#!/usr/bin/env bash
set -euo pipefail

KEM_GROUP=${QUIC_KEM_GROUP:-mlkem768}
SERVER_HOST=${QUIC_SERVER_HOST:-quic-server}
SERVER_PORT=${QUIC_SERVER_PORT:-4433}
N_RUNS=${N_RUNS:-1000}
WARMUP=${WARMUP_RUNS:-50}
CERT_DIR=${CERT_DIR:-/certs}
RESULTS_DIR=${RESULTS_DIR:-/results}
OUTPUT_LABEL=${OUTPUT_LABEL:-quic_${KEM_GROUP}}

# Generate OpenSSL config with desired KEM group
cat > /tmp/openssl_quic.cnf <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf  = ssl_sect

[provider_sect]
default      = default_sect
oqsprovider  = oqs_sect

[default_sect]
activate = 1

[oqs_sect]
activate = 1
module   = /opt/openssl/lib64/ossl-modules/oqsprovider.so

[ssl_sect]
system_default = ssl_default_sect

[ssl_default_sect]
Groups = ${KEM_GROUP}
EOF

export OPENSSL_CONF=/tmp/openssl_quic.cnf

# Wait for server readiness (UDP port check via netcat)
echo "[quic-client] Waiting for QUIC server at ${SERVER_HOST}:${SERVER_PORT}..."
for i in $(seq 1 30); do
    if nc -zu "${SERVER_HOST}" "${SERVER_PORT}" 2>/dev/null; then
        echo "[quic-client] Server reachable."
        break
    fi
    sleep 1
done

exec /app/quic-client \
    --host    "${SERVER_HOST}" \
    --port    "${SERVER_PORT}" \
    --runs    "${N_RUNS}" \
    --warmup  "${WARMUP}" \
    --ca-cert "${CERT_DIR}/ca.crt" \
    --output  "${RESULTS_DIR}/${OUTPUT_LABEL}.log" \
    "$@"
