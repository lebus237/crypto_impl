#!/usr/bin/env bash
set -euo pipefail

KEM_GROUP=${TLS_KEM_GROUP:-mlkem768}
SIG_ALG=${TLS_SIG_ALG:-mldsa65}
SERVER_HOST=${TLS_SERVER_HOST:-tls-server}
SERVER_PORT=${TLS_SERVER_PORT:-4433}
N_RUNS=${N_RUNS:-1000}
WARMUP=${WARMUP_RUNS:-50}
CERT_DIR=${CERT_DIR:-/certs}
RESULTS_DIR=${RESULTS_DIR:-/results}
OUTPUT_LABEL=${OUTPUT_LABEL:-tls_${KEM_GROUP}}

# Wait for server readiness
echo "[tls-client] Waiting for TLS server at ${SERVER_HOST}:${SERVER_PORT}..."
for i in $(seq 1 30); do
    if /opt/openssl/bin/openssl s_client \
        -connect "${SERVER_HOST}:${SERVER_PORT}" \
        -brief < /dev/null 2>/dev/null | grep -q "CONNECTION ESTABLISHED"; then
        echo "[tls-client] Server ready."
        break
    fi
    sleep 1
done

exec /app/tls-client \
    --host    "${SERVER_HOST}" \
    --port    "${SERVER_PORT}" \
    --kem     "${KEM_GROUP}" \
    --sig     "${SIG_ALG}" \
    --runs    "${N_RUNS}" \
    --warmup  "${WARMUP}" \
    --ca-cert "${CERT_DIR}/ca.crt" \
    --output  "${RESULTS_DIR}/${OUTPUT_LABEL}.log" \
    "$@"
