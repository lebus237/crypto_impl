#!/usr/bin/env bash
set -euo pipefail

CERT_DIR=${CERT_DIR:-/certs}
SIG_ALG=${TLS_SIG_ALG:-mldsa65}

# Generate certificates if missing
if [[ ! -f "${CERT_DIR}/server.crt" ]]; then
    echo "[tls-server] Generating certificates for sig_alg=${SIG_ALG}"
    mkdir -p "${CERT_DIR}"
    /src/certs/gen_certs.sh "${SIG_ALG}" "${CERT_DIR}"
fi

echo "[tls-server] Starting TLS server on port ${TLS_PORT:-4433}"
exec /app/tls-server \
    --port "${TLS_PORT:-4433}" \
    --cert "${CERT_DIR}/server.crt" \
    --key  "${CERT_DIR}/server.key" \
    "$@"
