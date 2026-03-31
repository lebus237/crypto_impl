#!/usr/bin/env bash
# =============================================================================
# collect_pcaps.sh — Capture packets at the Docker container network interface.
#
# Supports two capture backends (tried in order):
#
#   1. EdgeShark (preferred)
#      EdgeShark exposes a streaming HTTP endpoint that delivers a live pcap
#      feed for any container. It is the cleanest solution because it operates
#      at the container's virtual Ethernet interface without requiring root
#      privileges on the host beyond Docker socket access.
#      See: https://github.com/siemens/edgeshark
#
#   2. nsenter + tcpdump (fallback)
#      If EdgeShark is unavailable, we enter the container's network namespace
#      using `nsenter` and run `tcpdump` directly on the container's eth0.
#      Requires: tcpdump on the host, and the ability to nsenter (root or
#      CAP_SYS_PTRACE + CAP_NET_ADMIN).
#
# Usage:
#   collect_pcaps.sh <container_name> <output_pcapng_file>
#
# Arguments:
#   container_name      Name of the Docker container whose traffic to capture
#   output_pcapng_file  Absolute path on the host where the pcapng will be saved
#
# The script runs until it receives SIGTERM or SIGINT (i.e. the caller is
# responsible for killing it when the scenario ends).
#
# Example:
#   collect_pcaps.sh tls-client /results/raw/tls_mlkem768_ideal.pcapng &
#   PCAP_PID=$!
#   # ... run scenario ...
#   kill $PCAP_PID
#
# Environment variables:
#   EDGESHARK_HOST   EdgeShark API host       (default: localhost)
#   EDGESHARK_PORT   EdgeShark API port       (default: 5001)
#   CAPTURE_FILTER   BPF filter string        (default: "tcp or udp port 4433")
#   CAPTURE_SNAPLEN  Snapshot length in bytes (default: 0 = full packet)
# =============================================================================
set -euo pipefail

# ── Arguments ─────────────────────────────────────────────────────────────────
CONTAINER="${1:?Usage: collect_pcaps.sh <container_name> <output_pcapng_file>}"
OUTPUT_FILE="${2:?Missing output_pcapng_file argument}"

# ── Configuration ─────────────────────────────────────────────────────────────
EDGESHARK_HOST="${EDGESHARK_HOST:-localhost}"
EDGESHARK_PORT="${EDGESHARK_PORT:-5001}"
CAPTURE_FILTER="${CAPTURE_FILTER:-tcp or udp port 4433}"
CAPTURE_SNAPLEN="${CAPTURE_SNAPLEN:-0}"

# ── Logging helpers ────────────────────────────────────────────────────────────
log()  { echo "[collect_pcaps] $*"; }
warn() { echo "[collect_pcaps] WARN: $*" >&2; }
err()  { echo "[collect_pcaps] ERROR: $*" >&2; }

# ── Ensure the output directory exists ───────────────────────────────────────
mkdir -p "$(dirname "${OUTPUT_FILE}")"

# ── Signal handler: clean up on exit ─────────────────────────────────────────
CHILD_PID=""

cleanup() {
    if [[ -n "${CHILD_PID}" ]]; then
        kill "${CHILD_PID}" 2>/dev/null || true
        wait "${CHILD_PID}"  2>/dev/null || true
    fi
    log "Capture stopped. Output: ${OUTPUT_FILE}"
    if [[ -f "${OUTPUT_FILE}" ]]; then
        SIZE_BYTES="$(wc -c < "${OUTPUT_FILE}" | tr -d ' ')"
        log "File size: ${SIZE_BYTES} bytes"
    else
        warn "Output file was not created."
    fi
}

trap cleanup EXIT SIGTERM SIGINT

# ── Validate that the target container is running ────────────────────────────
CONTAINER_STATUS="$(docker inspect \
    --format='{{.State.Status}}' \
    "${CONTAINER}" 2>/dev/null || echo "missing")"

if [[ "${CONTAINER_STATUS}" != "running" ]]; then
    err "Target container '${CONTAINER}' is not running (status: ${CONTAINER_STATUS})."
    exit 1
fi

# =============================================================================
# BACKEND 1 — EdgeShark
# =============================================================================
# EdgeShark exposes GET /capture/<container-name>/ which streams a raw pcap
# feed. We pipe it through tshark to convert to pcapng and write to disk.
#
# EdgeShark API reference:
#   GET http://<host>:<port>/capture/<container>/
#   Optional query params: ?fmt=pcapng&filter=<bpf>
# =============================================================================

try_edgeshark() {
    local api_base="http://${EDGESHARK_HOST}:${EDGESHARK_PORT}"

    log "Probing EdgeShark at ${api_base}..."

    # Quick connectivity test (2 second timeout)
    if ! curl \
            --silent \
            --fail \
            --max-time 2 \
            "${api_base}/" \
            > /dev/null 2>&1; then
        log "EdgeShark not available at ${api_base}."
        return 1
    fi

    log "EdgeShark detected — using streaming capture backend."
    log "Container : ${CONTAINER}"
    log "Filter    : ${CAPTURE_FILTER}"
    log "Output    : ${OUTPUT_FILE}"

    # Build the capture URL.
    # EdgeShark accepts URL-encoded BPF filters via the `filter` query param.
    ENCODED_FILTER="$(python3 -c \
        "import urllib.parse, sys; print(urllib.parse.quote(sys.argv[1]))" \
        "${CAPTURE_FILTER}" 2>/dev/null \
        || echo "${CAPTURE_FILTER// /%20}")"

    CAPTURE_URL="${api_base}/capture/${CONTAINER}/?filter=${ENCODED_FILTER}"

    # Stream from EdgeShark into tshark, which writes pcapng to the output file.
    # tshark -r - reads from stdin; -w writes pcapng; -F pcapng forces the format.
    curl \
        --silent \
        --no-buffer \
        --max-time 0 \
        "${CAPTURE_URL}" \
    | tshark \
        -r - \
        -w "${OUTPUT_FILE}" \
        -F pcapng \
        -s "${CAPTURE_SNAPLEN}" \
        2>/dev/null &

    CHILD_PID=$!
    log "EdgeShark capture running (PID: ${CHILD_PID})"
    wait "${CHILD_PID}" || true
    CHILD_PID=""
    return 0
}

# =============================================================================
# BACKEND 2 — nsenter + tcpdump
# =============================================================================
# Enters the container's network namespace via nsenter and runs tcpdump
# directly on its network interface. Output is written as pcapng via
# tcpdump's -w flag (pcap format) and optionally converted by tshark.
# =============================================================================

try_nsenter_tcpdump() {
    log "Falling back to nsenter + tcpdump backend."

    # Verify required tools are available
    for tool in nsenter tcpdump; do
        if ! command -v "${tool}" &>/dev/null; then
            err "'${tool}' is not available on the host PATH."
            err "Install it with: apt-get install ${tool}"
            return 1
        fi
    done

    # Get the PID of the first process in the container (PID 1 in the netns)
    CONTAINER_PID="$(docker inspect \
        --format='{{.State.Pid}}' \
        "${CONTAINER}" 2>/dev/null)"

    if [[ -z "${CONTAINER_PID}" || "${CONTAINER_PID}" == "0" ]]; then
        err "Cannot determine PID for container '${CONTAINER}'."
        return 1
    fi

    log "Container PID (network namespace): ${CONTAINER_PID}"

    # Discover the primary network interface inside the container.
    # We look for the first interface whose name starts with eth, ens, or veth.
    IFACE="$(nsenter \
        --target "${CONTAINER_PID}" \
        --net \
        -- ip -o link show \
        | awk -F': ' '
            /[0-9]+: (eth|ens|veth)[^:]*:/ {
                gsub(/@.*/, "", $2);
                print $2;
                exit
            }
        ')"

    # Default to eth0 if discovery failed
    IFACE="${IFACE:-eth0}"
    log "Capturing on interface: ${IFACE}"
    log "BPF filter: ${CAPTURE_FILTER}"
    log "Output    : ${OUTPUT_FILE}"

    # Determine output format.
    # If tshark is available, capture in pcap and convert to pcapng on the fly.
    # Otherwise write pcap directly (tshark can still read it later).
    if command -v tshark &>/dev/null; then
        # Pipe tcpdump's pcap stream through tshark for pcapng conversion
        nsenter \
            --target "${CONTAINER_PID}" \
            --net \
            -- tcpdump \
                -i "${IFACE}" \
                -s "${CAPTURE_SNAPLEN}" \
                -U \
                -w - \
                "${CAPTURE_FILTER}" \
                2>/dev/null \
        | tshark \
            -r - \
            -w "${OUTPUT_FILE}" \
            -F pcapng \
            2>/dev/null &
    else
        warn "tshark not available — writing pcap format (not pcapng)."
        # Write as .pcap even if the output filename says .pcapng;
        # tshark and Wireshark can read both.
        nsenter \
            --target "${CONTAINER_PID}" \
            --net \
            -- tcpdump \
                -i "${IFACE}" \
                -s "${CAPTURE_SNAPLEN}" \
                -U \
                -w "${OUTPUT_FILE}" \
                "${CAPTURE_FILTER}" \
                2>/dev/null &
    fi

    CHILD_PID=$!
    log "tcpdump capture running (PID: ${CHILD_PID})"
    wait "${CHILD_PID}" || true
    CHILD_PID=""
    return 0
}

# =============================================================================
# BACKEND 3 — Docker SDK via a sidecar tcpdump container
# =============================================================================
# If neither EdgeShark nor nsenter+tcpdump works (e.g. insufficient privileges),
# we run a privileged sidecar container that shares the target's network
# namespace and runs tcpdump inside it.
# =============================================================================

try_sidecar_tcpdump() {
    log "Falling back to privileged sidecar tcpdump container."
    log "Container : ${CONTAINER}"
    log "Filter    : ${CAPTURE_FILTER}"
    log "Output    : ${OUTPUT_FILE}"

    OUTPUT_DIR="$(dirname "${OUTPUT_FILE}")"
    OUTPUT_BASENAME="$(basename "${OUTPUT_FILE}")"

    docker run \
        --rm \
        --network "container:${CONTAINER}" \
        --cap-add NET_ADMIN \
        --cap-add NET_RAW \
        -v "${OUTPUT_DIR}:/cap_out" \
        nicolaka/netshoot:latest \
        tcpdump \
            -i any \
            -s "${CAPTURE_SNAPLEN}" \
            -U \
            -w "/cap_out/${OUTPUT_BASENAME}" \
            "${CAPTURE_FILTER}" \
            2>/dev/null &

    CHILD_PID=$!
    log "Sidecar tcpdump running (PID: ${CHILD_PID})"
    wait "${CHILD_PID}" || true
    CHILD_PID=""
    return 0
}

# =============================================================================
# Try backends in preference order
# =============================================================================

log "Starting packet capture for container '${CONTAINER}'..."
log "Output: ${OUTPUT_FILE}"

if try_edgeshark; then
    :   # Success — cleanup will run on EXIT
elif try_nsenter_tcpdump; then
    :   # Success — cleanup will run on EXIT
else
    warn "EdgeShark and nsenter+tcpdump both failed."
    warn "Attempting privileged sidecar container as last resort..."
    try_sidecar_tcpdump || {
        err "All capture backends failed. No packet capture will be available."
        exit 1
    }
fi
