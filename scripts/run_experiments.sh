#!/usr/bin/env bash
# =============================================================================
# run_experiments.sh — Master orchestrator for all PQC evaluation scenarios.
#
# Iterates over every combination of:
#   protocol  × KEM group  × network condition
# and runs the corresponding benchmark client, collecting timing logs and
# optional packet captures for each scenario.
#
# Usage:
#   ./scripts/run_experiments.sh [OPTIONS]
#
# Options:
#   --protocol  tls|quic|both   Protocols to evaluate    (default: both)
#   --network   ideal|all|NAME  Network condition filter  (default: all)
#   --kem       NAME            Run only this KEM         (default: all)
#   --runs      N               Handshakes per scenario   (default: 1000)
#   --warmup    N               Warm-up runs (discarded)  (default: 50)
#   --sig       ALG             Signature algorithm       (default: mldsa65)
#   --no-pcap                   Skip packet capture
#   --dry-run                   Print commands, don't run them
#   --help                      Show this message
#
# Environment variables (override defaults without flags):
#   SIG_ALG, N_RUNS, WARMUP_RUNS, RESULTS_DIR
# =============================================================================
set -euo pipefail

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Default values ────────────────────────────────────────────────────────────
PROTOCOLS="${PROTOCOL:-both}"
NETWORK_FILTER="${NETWORK_CONDITION:-all}"
KEM_FILTER=""
DRY_RUN=false
NO_PCAP=false
SIG_ALG="${SIG_ALG:-mldsa65}"
N_RUNS="${N_RUNS:-1000}"
WARMUP_RUNS="${WARMUP_RUNS:-50}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RESULTS_DIR="${RESULTS_DIR:-${PROJECT_ROOT}/results/raw/${TIMESTAMP}}"

# ── Parse command-line arguments ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --protocol) PROTOCOLS="$2";       shift 2 ;;
        --network)  NETWORK_FILTER="$2";  shift 2 ;;
        --kem)      KEM_FILTER="$2";      shift 2 ;;
        --runs)     N_RUNS="$2";          shift 2 ;;
        --warmup)   WARMUP_RUNS="$2";     shift 2 ;;
        --sig)      SIG_ALG="$2";         shift 2 ;;
        --no-pcap)  NO_PCAP=true;         shift   ;;
        --dry-run)  DRY_RUN=true;         shift   ;;
        --help)
            sed -n '3,24p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "[error] Unknown argument: $1" >&2
            echo "        Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

# ── KEM catalogue ─────────────────────────────────────────────────────────────
TRADITIONAL_KEMS=(
    "p256"
    "x25519"
    "p384"
    "x448"
    "p521"
)

HYBRID_KEMS=(
    "x25519_mlkem512"
    "secp256r1_mlkem512"
    "x25519_mlkem768"
    "secp384r1_mlkem768"
    "x448_mlkem768"
    "x25519_mlkem1024"
    "secp521r1_mlkem1024"
)

PQ_KEMS=(
    "mlkem512"
    "mlkem768"
    "mlkem1024"
    "hqc128"
    "hqc192"
    "hqc256"
)

ALL_KEMS=("${TRADITIONAL_KEMS[@]}" "${HYBRID_KEMS[@]}" "${PQ_KEMS[@]}")

# Apply KEM filter if specified
if [[ -n "${KEM_FILTER}" ]]; then
    ALL_KEMS=("${KEM_FILTER}")
fi

# ── Network condition catalogue ───────────────────────────────────────────────
declare -A NET_DELAY=(
    [ideal]=0
    [low_loss]=20
    [medium_loss]=50
    [high_loss]=100
)
declare -A NET_JITTER=(
    [ideal]=0
    [low_loss]=2
    [medium_loss]=5
    [high_loss]=10
)
declare -A NET_LOSS=(
    [ideal]=0
    [low_loss]=0.1
    [medium_loss]=1
    [high_loss]=5
)

if [[ "${NETWORK_FILTER}" == "all" ]]; then
    NETWORKS=("ideal" "low_loss" "medium_loss" "high_loss")
else
    NETWORKS=("${NETWORK_FILTER}")
fi

# ── Protocol list ─────────────────────────────────────────────────────────────
if [[ "${PROTOCOLS}" == "both" ]]; then
    PROTO_LIST=("tls" "quic")
else
    PROTO_LIST=("${PROTOCOLS}")
fi

# ── Pre-flight checks ─────────────────────────────────────────────────────────
if [[ "${DRY_RUN}" == "false" ]]; then
    if ! command -v docker &>/dev/null; then
        echo "[error] docker is not installed or not in PATH" >&2
        exit 1
    fi
    if ! docker compose version &>/dev/null; then
        echo "[error] Docker Compose V2 (docker compose) is required" >&2
        exit 1
    fi
fi

# ── Setup results directory ───────────────────────────────────────────────────
mkdir -p "${RESULTS_DIR}"

# Write experiment metadata
cat > "${RESULTS_DIR}/metadata.json" <<METADATA
{
  "timestamp":       "${TIMESTAMP}",
  "protocols":       $(printf '"%s",' "${PROTO_LIST[@]}" | sed 's/,$//' | sed 's/^/[/;s/$/]/'),
  "networks":        $(printf '"%s",' "${NETWORKS[@]}"   | sed 's/,$//' | sed 's/^/[/;s/$/]/'),
  "n_kems":          ${#ALL_KEMS[@]},
  "n_runs":          ${N_RUNS},
  "warmup_runs":     ${WARMUP_RUNS},
  "sig_alg":         "${SIG_ALG}",
  "results_dir":     "${RESULTS_DIR}"
}
METADATA

# ── Print run plan ────────────────────────────────────────────────────────────
TOTAL_SCENARIOS=$(( ${#PROTO_LIST[@]} * ${#ALL_KEMS[@]} * ${#NETWORKS[@]} ))
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          PQC Handshake Evaluation — Experiment Run          ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  %-24s : %-33s║\n" "Timestamp"   "${TIMESTAMP}"
printf "║  %-24s : %-33s║\n" "Protocols"   "${PROTO_LIST[*]}"
printf "║  %-24s : %-33s║\n" "Networks"    "${NETWORKS[*]}"
printf "║  %-24s : %-33s║\n" "KEMs"        "${#ALL_KEMS[@]} configured"
printf "║  %-24s : %-33s║\n" "Runs/scenario" "${N_RUNS} (+${WARMUP_RUNS} warmup)"
printf "║  %-24s : %-33s║\n" "Signature alg" "${SIG_ALG}"
printf "║  %-24s : %-33s║\n" "Total scenarios" "${TOTAL_SCENARIOS}"
printf "║  %-24s : %-33s║\n" "Results dir"  "$(basename "${RESULTS_DIR}")"
printf "║  %-24s : %-33s║\n" "Dry-run"      "${DRY_RUN}"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Utility: run or echo a command ───────────────────────────────────────────
run_cmd() {
    if [[ "${DRY_RUN}" == "true" ]]; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

# ── Utility: wait for a container to become healthy ──────────────────────────
wait_for_healthy() {
    local container="$1"
    local max_wait="${2:-60}"
    local waited=0

    echo -n "[wait] Waiting for ${container} to become healthy"
    while [[ ${waited} -lt ${max_wait} ]]; do
        local status
        status="$(docker inspect --format='{{.State.Health.Status}}' \
                  "${container}" 2>/dev/null || echo "missing")"
        if [[ "${status}" == "healthy" ]]; then
            echo " ✓"
            return 0
        fi
        echo -n "."
        sleep 2
        waited=$(( waited + 2 ))
    done

    echo " ✗ (timeout after ${max_wait}s)"
    return 1
}

# ── Utility: stop all pumba instances ────────────────────────────────────────
stop_pumba() {
    docker rm -f pumba 2>/dev/null || true
}

# ── Counters ─────────────────────────────────────────────────────────────────
CURRENT=0
PASS=0
FAIL=0

# ── Per-scenario runner ───────────────────────────────────────────────────────
run_scenario() {
    local proto="$1"
    local kem="$2"
    local net="$3"

    CURRENT=$(( CURRENT + 1 ))
    local label="${proto}_${kem}_${net}"
    local log_file="${RESULTS_DIR}/${label}.log"
    local pcap_file="${RESULTS_DIR}/${label}.pcapng"

    printf "\n── [%3d/%3d] %-52s ──\n" \
        "${CURRENT}" "${TOTAL_SCENARIOS}" "${label}"

    if [[ "${DRY_RUN}" == "true" ]]; then
        echo "[dry-run] Would run scenario: proto=${proto} kem=${kem} net=${net}"
        echo "[dry-run] Output: ${log_file}"
        PASS=$(( PASS + 1 ))
        return 0
    fi

    # ── Apply network conditions via Pumba ────────────────────────────────
    stop_pumba
    if [[ "${net}" != "ideal" ]]; then
        local delay="${NET_DELAY[${net}]}"
        local jitter="${NET_JITTER[${net}]}"
        local loss="${NET_LOSS[${net}]}"

        echo "[net] Applying conditions: delay=${delay}ms jitter=${jitter}ms loss=${loss}%"
        "${SCRIPT_DIR}/apply_network.sh" \
            "${proto}-client" \
            "${delay}" \
            "${jitter}" \
            "${loss}"
        # Allow Pumba 2s to install the tc qdisc rules
        sleep 2
    fi

    # ── Start packet capture ───────────────────────────────────────────────
    local pcap_pid=""
    if [[ "${NO_PCAP}" == "false" ]]; then
        "${SCRIPT_DIR}/collect_pcaps.sh" "${proto}-client" "${pcap_file}" &
        pcap_pid=$!
        sleep 1
    fi

    # ── Run the benchmark ──────────────────────────────────────────────────
    local exit_code=0
    if [[ "${proto}" == "tls" ]]; then
        "${SCRIPT_DIR}/run_tls.sh" \
            "${kem}" "${net}" "${log_file}" \
            "${SIG_ALG}" "${N_RUNS}" "${WARMUP_RUNS}" \
            || exit_code=$?
    else
        "${SCRIPT_DIR}/run_quic.sh" \
            "${kem}" "${net}" "${log_file}" \
            "${SIG_ALG}" "${N_RUNS}" "${WARMUP_RUNS}" \
            || exit_code=$?
    fi

    # ── Stop packet capture ────────────────────────────────────────────────
    if [[ -n "${pcap_pid}" ]]; then
        kill "${pcap_pid}" 2>/dev/null || true
        wait "${pcap_pid}"  2>/dev/null || true
    fi

    # ── Remove network emulation ───────────────────────────────────────────
    if [[ "${net}" != "ideal" ]]; then
        stop_pumba
        sleep 1
    fi

    # ── Log outcome ────────────────────────────────────────────────────────
    if [[ ${exit_code} -eq 0 ]]; then
        echo "[ok] ${label} → ${log_file}"
        PASS=$(( PASS + 1 ))
    else
        echo "[warn] ${label} finished with exit code ${exit_code}" >&2
        FAIL=$(( FAIL + 1 ))
    fi
}

# ── Main experiment loop ──────────────────────────────────────────────────────
START_TIME=$(date +%s)

for proto in "${PROTO_LIST[@]}"; do

    # Build images if needed (no-op if already built)
    echo ""
    echo "[setup] Ensuring ${proto} images are built..."
    run_cmd docker compose build "${proto}-server" "${proto}-client" 2>/dev/null || true

    for net in "${NETWORKS[@]}"; do

        # Start the server fresh for each network condition
        echo ""
        echo "[setup] Starting ${proto}-server (sig=${SIG_ALG}, net=${net})..."

        if [[ "${DRY_RUN}" == "false" ]]; then
            # Bring down any existing server first
            docker compose stop "${proto}-server" 2>/dev/null || true
            docker compose rm -f "${proto}-server" 2>/dev/null || true

            # Start server with the correct signature algorithm
            SIG_ALG="${SIG_ALG}" \
            KEM_GROUP="mlkem768" \
                docker compose up -d "${proto}-server"

            # Wait for healthy state
            wait_for_healthy "${proto}-server" 60 || {
                echo "[error] ${proto}-server failed to become healthy — skipping ${net}" >&2
                continue
            }
        fi

        # Iterate over all KEMs for this protocol × network combination
        for kem in "${ALL_KEMS[@]}"; do
            run_scenario "${proto}" "${kem}" "${net}"
        done

        # Shut down the server between network conditions to release resources
        if [[ "${DRY_RUN}" == "false" ]]; then
            echo ""
            echo "[teardown] Stopping ${proto}-server after ${net} scenarios..."
            docker compose stop "${proto}-server" 2>/dev/null || true
        fi

    done   # networks
done   # protocols

# ── Final report ──────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$(( END_TIME - START_TIME ))
HH=$(( ELAPSED / 3600 ))
MM=$(( (ELAPSED % 3600) / 60 ))
SS=$(( ELAPSED % 60 ))

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  Experiment Run Complete                     ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  %-24s : %-33s║\n" "Total scenarios"  "${TOTAL_SCENARIOS}"
printf "║  %-24s : %-33s║\n" "Passed"           "${PASS}"
printf "║  %-24s : %-33s║\n" "Failed"           "${FAIL}"
printf "║  %-24s : %02d:%02d:%02d%-25s║\n" "Elapsed time"  "${HH}" "${MM}" "${SS}" ""
printf "║  %-24s : %-33s║\n" "Results dir"      "${RESULTS_DIR}"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps — run the analysis pipeline:"
echo ""
echo "  cd ${PROJECT_ROOT}"
echo "  python3 analysis/parse_results.py --raw-dir ${RESULTS_DIR}"
echo "  python3 analysis/statistics.py"
echo "  python3 analysis/plot_results.py"
echo "  python3 analysis/report.py"
echo ""

# Return non-zero if any scenario failed
[[ ${FAIL} -eq 0 ]]
