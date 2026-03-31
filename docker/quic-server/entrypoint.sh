#!/usr/bin/env bash
set -euo pipefail

CERT_DIR=${CERT_DIR:-/certs}
SIG_ALG=${QUIC_SIG_ALG:-mldsa65}
KEM_GROUP=${QUIC_KEM_GROUP:-mlkem768}

# Generate certificates if missing
if [[ ! -f "${CERT_DIR}/server.crt" ]]; then
    echo "[quic-server] Generating certificates for sig_alg=${SIG_ALG}"
    mkdir -p "${CERT_DIR}"
    /src/certs/gen_certs.sh "${SIG_ALG}" "${CERT_DIR}"
fi

# Generate OpenSSL config with desired KEM group for MsQuic TLS backend
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

echo "[quic-server] Starting QUIC server (KEM=${KEM_GROUP}, port=${QUIC_PORT:-4433})"
exec /app/quic-server \
    --port "${QUIC_PORT:-4433}" \
    --cert "${CERT_DIR}/server.crt" \
    --key  "${CERT_DIR}/server.key" \
    "$@"
