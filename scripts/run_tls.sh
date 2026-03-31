#!/usr/bin/env bash
# =============================================================================
# run_tls.sh — Run a single TLS 1.3 evaluation scenario.
#
# Launches the tls-client container against an already-running tls-server,
# waits for completion, then copies the timing log from the Docker volume
# to the host results directory.
#
# Usage:
#   run_tls.sh <kem_group> <network_label> <output_file> \
#              [sig_alg] [n_runs] [warmup_runs]
#
# Arguments:
#   kem_group      OQS-Provider KEM name, e.g. "mlkem768" or "x25519_mlkem768"
#   network_label  One of: ideal | low_loss | medium_loss | high_loss
#   output_file    Absolute path on the HOST where the CSV log will be written
#   sig_alg        Signature algorithm for the server cert (default: mldsa65)
#   n_runs         Number of measured handshakes           (default: 1000)
#   warmup_runs    Number of discarded warm-up runs        (default: 50)
#
# Environment variables (optional overrides):
#   TLS_SERVER_HOST   Hostname of the TLS server container (default: tls-server)
#   TLS_SERVER_PORT   Port of the TLS server               (default: 4433)
#   COMPOSE_FILE      Path to docker-compose.yml           (default: auto-detect)
# =============================================================================
set -euo pipefail

# ── Arguments ─────────────────────────────────────────────────────────────────
KEM_GROUP="${1:?Usage: run_tls.sh <kem_group> <network_label> <output_file> [sig_alg] [n_runs] [warmup]}"
NET_LABEL="${2:?Missing network_label argument}"
OUTPUT_FILE="${3:?Missing output_file argument}"
SIG_ALG="${4:-mldsa65}"
N_RUNS="${5:-1000}"
WARMUP="${6:-50}"

# ── Configuration ─────────────────────────────────────────────────────────────
TLS_SERVER_HOST="${TLS_SERVER_HOST:-tls-server}"
TLS_SERVER_PORT="${TLS_SERVER_PORT:-4433}"

# Resolve the project root (two levels up from this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Docker Compose file
COMPOSE_FILE="${COMPOSE_FILE:-${PROJECT_ROOT}/docker-compose.yml}"

# Label used for the output file inside the container volume
OUTPUT_LABEL="tls_${KEM_GROUP}_${NET_LABEL}"

# ── Logging helpers ────────────────────────────────────────────────────────────
log()  { echo "[run_tls]  $*"; }
warn() { echo "[run_tls]  WARN: $*" >&2; }
err()  { echo "[run_tls]  ERROR: $*" >&2; }

# ── Pre-flight: verify the server is reachable ────────────────────────────────
log "Checking TLS server connectivity (${TLS_SERVER_HOST}:${TLS_SERVER_PORT})..."

SERVER_READY=false
for attempt in $(seq 1 15); do
    if docker exec tls-server \
        /opt/openssl/bin/openssl s_client \
            -connect "${TLS_SERVER_HOST}:${TLS_SERVER_PORT}" \
            -brief \
            < /dev/null 2>/dev/null \
        | grep -q "CONNECTION ESTABLISHED"; then
        SERVER_READY=true
        log "Server is ready (attempt ${attempt})."
        break
    fi
    sleep 2
done

if [[ "${SERVER_READY}" == "false" ]]; then
    warn "Could not verify server readiness — proceeding anyway."
fi

# ── Banner ────────────────────────────────────────────────────────────────────
log "────────────────────────────────────────────────────────────"
log " protocol : TLS 1.3 (OpenSSL)"
log " kem      : ${KEM_GROUP}"
log " sig_alg  : ${SIG_ALG}"
log " network  : ${NET_LABEL}"
log " runs     : ${N_RUNS} (+${WARMUP} warmup)"
log " output   : ${OUTPUT_FILE}"
log "────────────────────────────────────────────────────────────"

# ── Run the TLS client container ──────────────────────────────────────────────
#
# We use `docker compose run --rm` so the client container is ephemeral.
# All environment variables are passed explicitly to ensure deterministic
# configuration regardless of any .env file present in the project root.
#
START_TIME=$(date +%s%3N)   # milliseconds

docker compose \
    --file "${COMPOSE_FILE}" \
    run \
    --rm \
    --no-deps \
    -e TLS_KEM_GROUP="${KEM_GROUP}" \
    -e TLS_SIG_ALG="${SIG_ALG}" \
    -e TLS_SERVER_HOST="${TLS_SERVER_HOST}" \
    -e TLS_SERVER_PORT="${TLS_SERVER_PORT}" \
    -e N_RUNS="${N_RUNS}" \
    -e WARMUP_RUNS="${WARMUP}" \
    -e OUTPUT_LABEL="${OUTPUT_LABEL}" \
    -e CERT_DIR="/certs" \
    -e RESULTS_DIR="/results" \
    tls-client

CLIENT_EXIT=$?
END_TIME=$(date +%s%3N)
ELAPSED_MS=$(( END_TIME - START_TIME ))

# ── Copy result from Docker volume to host output path ───────────────────────
#
# The client writes its CSV to /results/<OUTPUT_LABEL>.log inside the
# named volume "pqc-eval_results". We extract it via a temporary alpine
# container that mounts the volume.
#
HOST_OUT_DIR="$(dirname "${OUTPUT_FILE}")"
mkdir -p "${HOST_OUT_DIR}"

log "Copying results from Docker volume to ${OUTPUT_FILE}..."

COPY_EXIT=0
docker run \
    --rm \
    -v pqc-eval_results:/vol_results:ro \
    -v "${HOST_OUT_DIR}:/host_out" \
    alpine:latest \
    sh -c "cp /vol_results/${OUTPUT_LABEL}.log /host_out/ 2>/dev/null && \
           echo 'copy ok'" \
    || COPY_EXIT=$?

if [[ ${COPY_EXIT} -ne 0 ]]; then
    warn "Could not copy log from volume — the file may still be in the volume."
    warn "Manual extraction: docker run --rm -v pqc-eval_results:/v alpine cat /v/${OUTPUT_LABEL}.log"
fi

# ── Validate the output file ──────────────────────────────────────────────────
ACTUAL_OUTPUT="${HOST_OUT_DIR}/${OUTPUT_LABEL}.log"

if [[ -f "${ACTUAL_OUTPUT}" ]]; then
    ROW_COUNT=$(( $(wc -l < "${ACTUAL_OUTPUT}") - 1 ))   # subtract header
    log "Output: ${ACTUAL_OUTPUT}  (${ROW_COUNT} data rows)"

    # Warn if significantly fewer rows than expected
    MIN_EXPECTED=$(( N_RUNS * 80 / 100 ))   # allow up to 20% failures
    if [[ ${ROW_COUNT} -lt ${MIN_EXPECTED} ]]; then
        warn "Only ${ROW_COUNT}/${N_RUNS} rows written — possible high failure rate."
    fi
else
    warn "Output file not found at ${ACTUAL_OUTPUT}"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
if [[ ${CLIENT_EXIT} -eq 0 ]]; then
    log "Scenario PASSED  (elapsed: ${ELAPSED_MS} ms)"
else
    warn "Scenario finished with exit code ${CLIENT_EXIT}  (elapsed: ${ELAPSED_MS} ms)"
fi

exit ${CLIENT_EXIT}
