#!/usr/bin/env bash
# =============================================================================
# gen_certs.sh — Generate a CA and server X.509 certificate for a given
#                post-quantum (or classical) signature algorithm using an
#                OQS-enabled OpenSSL installation.
#
# Usage:
#   gen_certs.sh <sig_alg> [output_dir]
#
# Arguments:
#   sig_alg     OQS-Provider algorithm name, e.g.:
#                 mldsa44, mldsa65, mldsa87          (ML-DSA / Dilithium)
#                 falcon512, falcon1024               (FN-DSA / Falcon)
#                 sphincssha2128fsimple, ...          (SLH-DSA / SPHINCS+)
#                 p256, p384, p521                   (classical ECDSA)
#   output_dir  Directory to write keys and certs    (default: /certs)
#
# Produces in <output_dir>/:
#   ca.key       — CA private key (PEM)
#   ca.crt       — CA self-signed certificate (PEM)
#   ca.srl       — CA serial number file
#   server.key   — Server private key (PEM)
#   server.csr   — Server certificate signing request (PEM)
#   server.crt   — Server certificate signed by the CA (PEM)
#
# Environment variables:
#   OPENSSL_BIN  Path to the openssl binary (default: /opt/openssl/bin/openssl)
#   DAYS_CA      Validity period for the CA certificate in days  (default: 3650)
#   DAYS_CERT    Validity period for the server certificate      (default: 365)
# =============================================================================
set -euo pipefail

# ── Arguments ────────────────────────────────────────────────────────────────
SIG_ALG="${1:-mldsa65}"
OUT_DIR="${2:-/certs}"

# ── Configuration ────────────────────────────────────────────────────────────
DAYS_CA="${DAYS_CA:-3650}"
DAYS_CERT="${DAYS_CERT:-365}"

# Locate the OQS-enabled openssl binary.
# Search order:
#   1. OPENSSL_BIN environment variable (explicit override)
#   2. /opt/openssl/bin/openssl         (Docker image installation path)
#   3. System PATH
if [[ -n "${OPENSSL_BIN:-}" && -x "${OPENSSL_BIN}" ]]; then
    OPENSSL="${OPENSSL_BIN}"
elif [[ -x "/opt/openssl/bin/openssl" ]]; then
    OPENSSL="/opt/openssl/bin/openssl"
else
    OPENSSL="$(command -v openssl)"
fi

echo "============================================================"
echo " gen_certs.sh"
echo "  sig_alg   : ${SIG_ALG}"
echo "  out_dir   : ${OUT_DIR}"
echo "  openssl   : ${OPENSSL}"
echo "  openssl v : $(${OPENSSL} version 2>/dev/null || echo 'unknown')"
echo "============================================================"

# ── Validate openssl binary ───────────────────────────────────────────────────
if [[ ! -x "${OPENSSL}" ]]; then
    echo "[error] openssl binary not found or not executable: ${OPENSSL}" >&2
    exit 1
fi

# ── Verify the algorithm is available ────────────────────────────────────────
# OQS-Provider must be loaded for PQC algorithms.
if ! "${OPENSSL}" genpkey -algorithm "${SIG_ALG}" -help > /dev/null 2>&1; then
    echo "[warn] Algorithm '${SIG_ALG}' may not be available in this OpenSSL build." >&2
    echo "       Ensure OQS-Provider is installed and OPENSSL_CONF is configured." >&2
fi

# ── Create output directory ───────────────────────────────────────────────────
mkdir -p "${OUT_DIR}"
chmod 700 "${OUT_DIR}"

# ── Shared OpenSSL options ────────────────────────────────────────────────────
# -nodes: do not encrypt private keys (not needed for benchmarking containers)
GENPKEY_OPTS="-algorithm ${SIG_ALG}"

# ── Subject name components ───────────────────────────────────────────────────
CA_SUBJ="/C=ES/ST=Malaga/O=PQC-Eval/OU=Research/CN=PQC-Test-CA-${SIG_ALG}"
SRV_SUBJ="/C=ES/ST=Malaga/O=PQC-Eval/OU=Server/CN=pqc-eval-server"

# =============================================================================
# STEP 1 — Generate CA private key
# =============================================================================
echo ""
echo "[1/5] Generating CA private key (${SIG_ALG})..."
"${OPENSSL}" genpkey \
    ${GENPKEY_OPTS} \
    -out "${OUT_DIR}/ca.key"

echo "      → ${OUT_DIR}/ca.key"

# =============================================================================
# STEP 2 — Generate CA self-signed certificate
# =============================================================================
echo ""
echo "[2/5] Generating CA self-signed certificate (valid ${DAYS_CA} days)..."
"${OPENSSL}" req \
    -new \
    -x509 \
    -key    "${OUT_DIR}/ca.key" \
    -out    "${OUT_DIR}/ca.crt" \
    -days   "${DAYS_CA}" \
    -subj   "${CA_SUBJ}" \
    -addext "basicConstraints=critical,CA:true,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

echo "      → ${OUT_DIR}/ca.crt"

# =============================================================================
# STEP 3 — Generate server private key
# =============================================================================
echo ""
echo "[3/5] Generating server private key (${SIG_ALG})..."
"${OPENSSL}" genpkey \
    ${GENPKEY_OPTS} \
    -out "${OUT_DIR}/server.key"

chmod 600 "${OUT_DIR}/server.key"
echo "      → ${OUT_DIR}/server.key"

# =============================================================================
# STEP 4 — Generate server Certificate Signing Request (CSR)
# =============================================================================
echo ""
echo "[4/5] Generating server CSR..."
"${OPENSSL}" req \
    -new \
    -key  "${OUT_DIR}/server.key" \
    -out  "${OUT_DIR}/server.csr" \
    -subj "${SRV_SUBJ}"

echo "      → ${OUT_DIR}/server.csr"

# =============================================================================
# STEP 5 — Sign the server certificate with the CA
#
# The SAN (Subject Alternative Name) extension is required by modern TLS
# clients. We include DNS names for all container hostnames used in
# docker-compose, plus localhost/127.0.0.1
# =============================================================================
echo ""
echo "[5/5] Signing server certificate with CA (valid ${DAYS_CERT} days)..."

# Write a temporary v3 extensions file for the server cert
EXT_FILE="$(mktemp /tmp/server_ext.XXXXXX.cnf)"
cat > "${EXT_FILE}" <<'EXTEOF'
[server_ext]
basicConstraints       = CA:false
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName         = @alt_names

[alt_names]
DNS.1 = pqc-eval-server
DNS.2 = tls-server
DNS.3 = quic-server
DNS.4 = localhost
IP.1  = 127.0.0.1
IP.2  = 172.28.0.10
IP.3  = 172.28.0.20
EXTEOF

"${OPENSSL}" x509 \
    -req \
    -in       "${OUT_DIR}/server.csr" \
    -CA       "${OUT_DIR}/ca.crt" \
    -CAkey    "${OUT_DIR}/ca.key" \
    -CAcreateserial \
    -out      "${OUT_DIR}/server.crt" \
    -days     "${DAYS_CERT}" \
    -extfile  "${EXT_FILE}" \
    -extensions server_ext

rm -f "${EXT_FILE}"
echo "      → ${OUT_DIR}/server.crt"

# =============================================================================
# VERIFICATION — confirm the chain is valid before the containers start
# =============================================================================
echo ""
echo "[verify] Verifying certificate chain..."
"${OPENSSL}" verify \
    -CAfile "${OUT_DIR}/ca.crt" \
    "${OUT_DIR}/server.crt"

echo ""
echo "[verify] Certificate details:"
"${OPENSSL}" x509 \
    -in      "${OUT_DIR}/server.crt" \
    -noout \
    -subject \
    -issuer  \
    -dates   \
    -ext     subjectAltName \
    2>/dev/null || true

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo "============================================================"
echo " Certificate generation complete"
echo "  Algorithm : ${SIG_ALG}"
echo "  CA cert   : ${OUT_DIR}/ca.crt"
echo "  Server key: ${OUT_DIR}/server.key"
echo "  Server crt: ${OUT_DIR}/server.crt"
echo "============================================================"
