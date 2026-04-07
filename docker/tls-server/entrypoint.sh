#!/usr/bin/env bash
set -euo pipefail

CERT_DIR=${CERT_DIR:-/certs}
SIG_ALG=${TLS_SIG_ALG:-mldsa65}
KEM_GROUP=${TLS_KEM_GROUP:-mlkem768}

# Generate certificates if missing
if [[ ! -f "${CERT_DIR}/server.crt" ]]; then
    echo "[tls-server] Generating certificates for sig_alg=${SIG_ALG}"
    mkdir -p "${CERT_DIR}"
    /src/certs/gen_certs.sh "${SIG_ALG}" "${CERT_DIR}"
fi

# Build groups list: PQC KEM first, then classical fallbacks so that the
# healthcheck (which uses default openssl s_client groups) also succeeds.
TLS_GROUPS="${KEM_GROUP}:X25519:P-256:P-384"

echo "[tls-server] Starting TLS server on port ${TLS_PORT:-4433} (groups=${TLS_GROUPS})"
exec /app/tls-server \
    --port "${TLS_PORT:-4433}" \
    --cert "${CERT_DIR}/server.crt" \
    --key  "${CERT_DIR}/server.key" \
    --kem  "${TLS_GROUPS}" \
    "$@"
