#!/usr/bin/env bash
# =============================================================================
# apply_network.sh — Apply tc-netem network conditions to a Docker container
#                    via Pumba.
#
# Pumba uses the Linux traffic control (tc) subsystem with the netem queuing
# discipline to emulate delay, jitter, and packet loss at the container
# network interface level. This produces realistic, reproducible network
# conditions without modifying the host network stack globally.
#
# Usage:
#   apply_network.sh <container_name> <delay_ms> <jitter_ms> <loss_pct>
#
# Arguments:
#   container_name   Name of the Docker container to target
#   delay_ms         One-way propagation delay in milliseconds  (0 = no delay)
#   jitter_ms        Delay jitter in milliseconds               (0 = no jitter)
#   loss_pct         Packet loss percentage                     (0 = no loss)
#
# Examples:
#   apply_network.sh tls-client 0  0  0       # ideal — no emulation
#   apply_network.sh tls-client 20 2  0.1     # low loss
#   apply_network.sh tls-client 50 5  1.0     # medium loss
#   apply_network.sh tls-client 100 10 5.0    # high loss
#
# Notes:
#   - Requires the Docker socket to be accessible (/var/run/docker.sock).
#   - Pumba starts as a background Docker container named "pumba".
#   - Call this script again or run `docker rm -f pumba` to remove conditions.
#   - The netem rules are applied to the container's outbound traffic (egress).
#     Since TCP/QUIC is bidirectional, this effectively degrades the connection
#     in a way that impacts RTT and retransmission behaviour.
#   - Duration is set to 24h; the Pumba container is killed externally by the
#     orchestration script when the scenario ends.
#
# Dependencies:
#   - docker (with access to /var/run/docker.sock)
#   - gaiaadm/pumba image (pulled automatically if not cached)
#   - gaiaadm/tc image    (used by Pumba to install tc inside the target netns)
# =============================================================================
set -euo pipefail

# ── Arguments ─────────────────────────────────────────────────────────────────
CONTAINER="${1:?Usage: apply_network.sh <container> <delay_ms> <jitter_ms> <loss_pct>}"
DELAY_MS="${2:-0}"
JITTER_MS="${3:-0}"
LOSS_PCT="${4:-0}"

# ── Logging helpers ────────────────────────────────────────────────────────────
log()  { echo "[apply_network] $*"; }
warn() { echo "[apply_network] WARN: $*" >&2; }
err()  { echo "[apply_network] ERROR: $*" >&2; exit 1; }

# ── Short-circuit for ideal conditions ────────────────────────────────────────
# If all parameters are zero, there is nothing to configure. Return immediately
# so the orchestration script does not start an unnecessary Pumba container.
if [[ "${DELAY_MS}" == "0" && "${JITTER_MS}" == "0" && \
      "${LOSS_PCT}" == "0" ]]; then
    log "Ideal network conditions requested — no emulation applied."
    exit 0
fi

# ── Validate that the target container is running ────────────────────────────
CONTAINER_STATUS="$(docker inspect \
    --format='{{.State.Status}}' \
    "${CONTAINER}" 2>/dev/null || echo "missing")"

if [[ "${CONTAINER_STATUS}" != "running" ]]; then
    warn "Target container '${CONTAINER}' is not running (status: ${CONTAINER_STATUS})."
    warn "Network conditions cannot be applied to a non-running container."
    exit 1
fi

# ── Remove any pre-existing Pumba instance ────────────────────────────────────
# Ensures only one set of network conditions is active at a time.
if docker inspect pumba &>/dev/null 2>&1; then
    log "Removing existing Pumba container..."
    docker rm -f pumba 2>/dev/null || true
    sleep 1
fi

# ── Configuration ─────────────────────────────────────────────────────────────
PUMBA_IMAGE="${PUMBA_IMAGE:-gaiaadm/pumba:latest}"
TC_IMAGE="${TC_IMAGE:-gaiaadm/tc:latest}"

# Duration is long enough to cover any experiment; it is killed explicitly
# by the orchestration script via `docker rm -f pumba`.
DURATION="${PUMBA_DURATION:-24h}"

# ── Banner ────────────────────────────────────────────────────────────────────
log "─────────────────────────────────────────────────────────────"
log " Target container : ${CONTAINER}"
log " Delay            : ${DELAY_MS} ms"
log " Jitter           : ${JITTER_MS} ms  (normal distribution)"
log " Packet loss      : ${LOSS_PCT} %"
log " Duration         : ${DURATION}"
log " Pumba image      : ${PUMBA_IMAGE}"
log " tc image         : ${TC_IMAGE}"
log "─────────────────────────────────────────────────────────────"

# ── Build Pumba command ───────────────────────────────────────────────────────
#
# Pumba netem sub-command structure:
#   pumba netem [netem-options] delay [delay-options] loss [loss-options] TARGET
#
# We always pass both delay and loss sub-commands. Pumba accepts a loss
# percentage of 0, which is a no-op, so this is safe even when only one
# dimension is non-zero.
#
PUMBA_CMD=(
    netem
        --duration    "${DURATION}"
        --tc-image    "${TC_IMAGE}"
    delay
        --time        "${DELAY_MS}"
        --jitter      "${JITTER_MS}"
        --distribution normal
    loss
        --percent     "${LOSS_PCT}"
    "${CONTAINER}"
)

# ── Start Pumba as a detached background container ────────────────────────────
log "Starting Pumba container..."

docker run \
    --detach \
    --name pumba \
    --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "${PUMBA_IMAGE}" \
    "${PUMBA_CMD[@]}"

PUMBA_CID="$(docker inspect --format='{{.Id}}' pumba 2>/dev/null || echo "unknown")"
log "Pumba started (container ID: ${PUMBA_CID:0:12})"

# ── Allow Pumba time to install tc rules ──────────────────────────────────────
# Pumba needs a moment to enter the container's network namespace and call
# `tc qdisc add`. A 2-second sleep is sufficient on modern hardware.
log "Waiting 2 s for tc rules to be installed..."
sleep 2

# ── Verify the rules were applied ────────────────────────────────────────────
# We check the container is still running (Pumba exits immediately on error).
PUMBA_STATUS="$(docker inspect \
    --format='{{.State.Status}}' pumba 2>/dev/null || echo "missing")"

if [[ "${PUMBA_STATUS}" != "running" ]]; then
    warn "Pumba container exited unexpectedly (status: ${PUMBA_STATUS})."
    warn "tc rules may not have been applied. Check Pumba logs:"
    warn "  docker logs pumba"
    exit 1
fi

log "Network conditions active. To remove:"
log "  docker rm -f pumba"
log ""
log "Done."
