# Usage Manual — PQC TLS/QUIC Handshake Performance Evaluation Framework

> **Reference implementation of:**
> Montenegro, J.A., Rios, R., Bonilla, J. *"Comparative analysis of post-quantum handshake
> performance in QUIC and TLS protocols"* — Computer Networks 275 (2026) 111957.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Project Layout](#2-project-layout)
3. [First-Time Setup](#3-first-time-setup)
   - 3.1 [Build the base image](#31-build-the-base-image)
   - 3.2 [Build all service images](#32-build-all-service-images)
   - 3.3 [Install Python analysis dependencies](#33-install-python-analysis-dependencies)
   - 3.4 [Verify the installation](#34-verify-the-installation)
4. [Certificate Management](#4-certificate-management)
   - 4.1 [Automatic generation](#41-automatic-generation)
   - 4.2 [Manual generation](#42-manual-generation)
   - 4.3 [Available signature algorithms](#43-available-signature-algorithms)
5. [Running a Single Scenario](#5-running-a-single-scenario)
   - 5.1 [TLS scenario](#51-tls-scenario)
   - 5.2 [QUIC scenario](#52-quic-scenario)
   - 5.3 [Environment variable reference](#53-environment-variable-reference)
6. [Running the Full Evaluation Suite](#6-running-the-full-evaluation-suite)
   - 6.1 [Full suite](#61-full-suite)
   - 6.2 [Filtering by protocol](#62-filtering-by-protocol)
   - 6.3 [Filtering by network condition](#63-filtering-by-network-condition)
   - 6.4 [Filtering by KEM](#64-filtering-by-kem)
   - 6.5 [Dry run](#65-dry-run)
   - 6.6 [All flags at a glance](#66-all-flags-at-a-glance)
7. [Network Condition Emulation](#7-network-condition-emulation)
   - 7.1 [How Pumba works](#71-how-pumba-works)
   - 7.2 [Applying conditions manually](#72-applying-conditions-manually)
   - 7.3 [Removing conditions](#73-removing-conditions)
   - 7.4 [Predefined condition profiles](#74-predefined-condition-profiles)
8. [Packet Capture](#8-packet-capture)
   - 8.1 [EdgeShark (preferred)](#81-edgeshark-preferred)
   - 8.2 [nsenter + tcpdump (fallback)](#82-nsenter--tcpdump-fallback)
   - 8.3 [Manual capture](#83-manual-capture)
9. [Analysis Pipeline](#9-analysis-pipeline)
   - 9.1 [Step 1 — Parse timing logs](#91-step-1--parse-timing-logs)
   - 9.2 [Step 2 — Parse pcap files](#92-step-2--parse-pcap-files)
   - 9.3 [Step 3 — Statistical analysis](#93-step-3--statistical-analysis)
   - 9.4 [Step 4 — Generate plots](#94-step-4--generate-plots)
   - 9.5 [Step 5 — Generate report](#95-step-5--generate-report)
   - 9.6 [Running the full pipeline in one shot](#96-running-the-full-pipeline-in-one-shot)
10. [Understanding the Results](#10-understanding-the-results)
    - 10.1 [Timing log format](#101-timing-log-format)
    - 10.2 [Combined CSV columns](#102-combined-csv-columns)
    - 10.3 [Statistics summary columns](#103-statistics-summary-columns)
    - 10.4 [TLS vs QUIC comparison columns](#104-tls-vs-quic-comparison-columns)
    - 10.5 [Generated plots](#105-generated-plots)
11. [Evaluated KEMs and Algorithms](#11-evaluated-kems-and-algorithms)
    - 11.1 [Traditional KEMs](#111-traditional-kems)
    - 11.2 [Hybrid KEMs](#112-hybrid-kems)
    - 11.3 [Post-quantum KEMs](#113-post-quantum-kems)
    - 11.4 [Signature algorithms](#114-signature-algorithms)
12. [Extending the Framework](#12-extending-the-framework)
    - 12.1 [Adding a new KEM](#121-adding-a-new-kem)
    - 12.2 [Adding a new signature algorithm](#122-adding-a-new-signature-algorithm)
    - 12.3 [Adding a new network condition](#123-adding-a-new-network-condition)
    - 12.4 [Changing the number of runs](#124-changing-the-number-of-runs)
13. [Troubleshooting](#13-troubleshooting)
    - 13.1 [Build failures](#131-build-failures)
    - 13.2 [Runtime errors](#132-runtime-errors)
    - 13.3 [Analysis errors](#133-analysis-errors)
    - 13.4 [Diagnostic commands](#134-diagnostic-commands)
14. [Reproduction Checklist](#14-reproduction-checklist)

---

## 1. System Requirements

### Mandatory

| Requirement | Minimum version | Notes |
|---|---|---|
| **Linux** (host OS) | kernel ≥ 5.4 | Required for Pumba's `tc netem`; WSL2 works for development but **not** for network emulation |
| **Docker Engine** | 24.0 | Must be running as a service (`systemctl status docker`) |
| **Docker Compose V2** | 2.20 | Invoked as `docker compose` (not `docker-compose`) |
| **Python** | 3.11 | For the analysis pipeline; 3.12 is also tested |
| **Free disk space** | 25 GB | Build artefacts for all images |
| **Free RAM** | 4 GB | For parallel container operation |

### Optional but recommended

| Tool | Purpose |
|---|---|
| [EdgeShark](https://github.com/siemens/edgeshark) | Container-level packet capture (see §8.1) |
| `tshark` | Packet analysis; `apt install tshark` |
| `wireshark` | Interactive pcap inspection |
| `jq` | Pretty-print `metadata.json` run reports |

### Checking prerequisites

```bash
# Docker
docker --version          # Docker version 24.x.x
docker compose version    # Docker Compose version v2.x.x

# Python
python3 --version         # Python 3.11.x

# Kernel (for Pumba tc netem)
uname -r                  # 5.4 or later

# Available disk
df -h /var/lib/docker     # need ≥ 25 GB free
```

---

## 2. Project Layout

```
bruno/
├── docker/                 Docker build contexts
│   ├── base/               Shared base image (liboqs + OpenSSL + OQS-Provider)
│   ├── tls-server/         TLS 1.3 server container
│   ├── tls-client/         TLS 1.3 client container
│   ├── quic-server/        QUIC server container (MsQuic)
│   └── quic-client/        QUIC client container (MsQuic)
├── src/
│   ├── tls/                C source: OpenSSL TLS server + client
│   ├── quic/               C source: MsQuic QUIC server + client
│   └── certs/              Certificate generation script
├── scripts/                Bash orchestration scripts
├── analysis/               Python analysis pipeline
├── configs/
│   └── scenarios.yaml      Complete experiment configuration
├── results/
│   ├── raw/                Raw timing logs (.log) + packet captures (.pcapng)
│   ├── csv/                Processed CSV datasets
│   └── plots/              Generated figures (.png)
├── docs/
│   ├── article.html        Source article
│   └── USAGE.md            This file
├── docker-compose.yml
└── README.md
```

All commands in this manual are run from the **`bruno/`** directory unless noted otherwise.

```bash
cd /path/to/bruno
```

---

## 3. First-Time Setup

### 3.1 Build the base image

The base image compiles three components from source. **This takes 15–25 minutes** on the first run; subsequent builds are cached.

```bash
docker compose build base
```

What it builds:

| Component | Version | Install prefix |
|---|---|---|
| liboqs | 0.11.0 | `/opt/oqs` |
| OpenSSL | 3.3.2 | `/opt/openssl` |
| OQS-Provider | 0.7.0 | `/opt/openssl` (as a provider module) |

Progress is verbose by default. To suppress:

```bash
docker compose build base --quiet
```

### 3.2 Build all service images

After the base image is ready, build the four service images. Each one compiles its C source inside the container and copies the resulting binary to `/app/`.

```bash
docker compose build
```

This builds: `pqc-tls-server`, `pqc-tls-client`, `pqc-quic-server`, `pqc-quic-client`.

The QUIC images also compile MsQuic 2.4.4 from source linked against the OQS-enabled OpenSSL. **Allow an extra 10–15 minutes** for the first QUIC build.

To build a specific image only:

```bash
docker compose build tls-server
docker compose build quic-client
```

To rebuild from scratch (ignoring the layer cache):

```bash
docker compose build --no-cache
```

### 3.3 Install Python analysis dependencies

```bash
pip install -r analysis/requirements.txt
```

Or inside a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r analysis/requirements.txt
```

Dependencies installed:

| Package | Purpose |
|---|---|
| `numpy ≥ 1.26` | Numerical operations |
| `pandas ≥ 2.2` | CSV ingestion and transformation |
| `scipy ≥ 1.13` | Statistical tests (Shapiro-Wilk, Levene, Welch) |
| `matplotlib ≥ 3.9` | Plot rendering |
| `seaborn ≥ 0.13` | Statistical visualisations |
| `pyshark ≥ 0.6` | Pcap parsing (wraps tshark) |
| `pyyaml ≥ 6.0` | Scenario configuration parsing |

### 3.4 Verify the installation

Run a quick smoke test: 50 TLS handshakes with ML-KEM-768 under ideal conditions.

```bash
KEM_GROUP=mlkem768 \
N_RUNS=50 \
WARMUP_RUNS=5 \
docker compose --profile tls up --abort-on-container-exit --remove-orphans
```

Expected output (abridged):

```
tls-server  | [tls-server] ready — listening on port 4433
tls-client  | [tls-client] host=tls-server port=4433 kem=mlkem768 sig=mldsa65 runs=50 warmup=5
tls-client  | [tls-client] done — success=50 fail=0 total_measured=50
tls-client exited with code 0
```

The result file is inside the `pqc-eval_results` Docker volume. Extract it:

```bash
docker run --rm \
  -v pqc-eval_results:/vol \
  alpine \
  head -5 /vol/tls_mlkem768_ideal.log
```

Expected:

```
run,latency_us,timestamp_us
0,1842,1700000000000000
1,1791,1700000000001842
...
```

---

## 4. Certificate Management

### 4.1 Automatic generation

Certificates are generated automatically the **first time** a server container starts, if `/certs/server.crt` does not exist in the `pqc-eval_certs` Docker volume. The signature algorithm is controlled by the `TLS_SIG_ALG` / `QUIC_SIG_ALG` environment variable (default: `mldsa65`).

You do not need to generate certificates manually for a standard run.

### 4.2 Manual generation

To pre-generate certificates for a specific algorithm:

```bash
# Generate ML-DSA65 certificates (default)
docker run --rm \
  -v pqc-eval_certs:/certs \
  pqc-tls-server:latest \
  /src/certs/gen_certs.sh mldsa65 /certs

# Generate Falcon-512 certificates
docker run --rm \
  -v pqc-eval_certs:/certs \
  pqc-tls-server:latest \
  /src/certs/gen_certs.sh falcon512 /certs
```

To regenerate certificates (deletes the existing volume first):

```bash
docker volume rm pqc-eval_certs
docker run --rm \
  -v pqc-eval_certs:/certs \
  pqc-tls-server:latest \
  /src/certs/gen_certs.sh mldsa65 /certs
```

To inspect a generated certificate:

```bash
docker run --rm \
  -v pqc-eval_certs:/certs \
  pqc-tls-server:latest \
  /opt/openssl/bin/openssl x509 \
    -in /certs/server.crt \
    -noout -subject -issuer -dates -text \
  2>/dev/null | head -30
```

### 4.3 Available signature algorithms

List all PQC signature algorithms available in this build:

```bash
docker run --rm pqc-base:latest \
  openssl list -signature-algorithms -provider oqsprovider 2>/dev/null \
  | grep -v "^Provided"
```

Key algorithms tested in the paper:

| OQS Name | Standard | NIST Level | Family |
|---|---|---|---|
| `mldsa44` | FIPS 204 | II | ML-DSA (Dilithium) |
| `mldsa65` | FIPS 204 | III | ML-DSA (Dilithium) — **default** |
| `mldsa87` | FIPS 204 | V | ML-DSA (Dilithium) |
| `falcon512` | In process | I | FN-DSA (Falcon) |
| `falcon1024` | In process | V | FN-DSA (Falcon) |
| `sphincssha2128fsimple` | FIPS 205 | I | SLH-DSA fast |
| `sphincssha2128ssimple` | FIPS 205 | I | SLH-DSA small |

---

## 5. Running a Single Scenario

A "scenario" is one combination of **protocol × KEM group × network condition**.

### 5.1 TLS scenario

**Step 1 — Start the TLS server** (leave it running in the background):

```bash
SIG_ALG=mldsa65 docker compose up -d tls-server
```

Wait for it to be healthy:

```bash
docker compose ps tls-server
# Should show: "healthy"
```

**Step 2 — Run the TLS client** for a specific KEM:

```bash
TLS_KEM_GROUP=mlkem768 \
TLS_SIG_ALG=mldsa65 \
N_RUNS=1000 \
WARMUP_RUNS=50 \
OUTPUT_LABEL=tls_mlkem768_ideal \
NET_CONDITION=ideal \
  docker compose --profile tls run --rm tls-client
```

**Step 3 — Retrieve the result:**

```bash
docker run --rm \
  -v pqc-eval_results:/vol \
  -v "$(pwd)/results/raw:/out" \
  alpine \
  cp /vol/tls_mlkem768_ideal.log /out/
```

**Step 4 — Stop the server:**

```bash
docker compose stop tls-server
```

### 5.2 QUIC scenario

**Step 1 — Start the QUIC server** with the matching KEM group:

```bash
QUIC_KEM_GROUP=mlkem768 \
QUIC_SIG_ALG=mldsa65 \
  docker compose up -d quic-server
```

Give it 3–4 seconds to initialise (QUIC startup is slightly slower than TLS):

```bash
sleep 4 && docker logs quic-server | tail -3
# Should show: [quic-server] ready — listening on UDP port 4433
```

**Step 2 — Run the QUIC client:**

```bash
QUIC_KEM_GROUP=mlkem768 \
N_RUNS=1000 \
WARMUP_RUNS=50 \
OUTPUT_LABEL=quic_mlkem768_ideal \
NET_CONDITION=ideal \
  docker compose --profile quic run --rm quic-client
```

**Step 3 — Retrieve and stop:** same as TLS above, substituting `quic-server`.

### 5.3 Environment variable reference

These variables are read by the Docker entrypoint scripts and passed to the benchmark binaries.

| Variable | Applies to | Default | Description |
|---|---|---|---|
| `TLS_KEM_GROUP` | TLS client | `mlkem768` | KEM group for key exchange (OpenSSL group name) |
| `TLS_SIG_ALG` | TLS server/client | `mldsa65` | Signature algorithm for the server certificate |
| `TLS_SERVER_HOST` | TLS client | `tls-server` | Hostname of the TLS server container |
| `TLS_SERVER_PORT` | TLS server/client | `4433` | TCP port |
| `QUIC_KEM_GROUP` | QUIC server/client | `mlkem768` | KEM group (written to `OPENSSL_CONF` Groups directive) |
| `QUIC_SIG_ALG` | QUIC server/client | `mldsa65` | Signature algorithm for the server certificate |
| `QUIC_SERVER_HOST` | QUIC client | `quic-server` | Hostname of the QUIC server container |
| `QUIC_SERVER_PORT` | QUIC server/client | `4433` | UDP port |
| `N_RUNS` | Both clients | `1000` | Number of measured handshakes |
| `WARMUP_RUNS` | Both clients | `50` | Warm-up handshakes (discarded from output) |
| `OUTPUT_LABEL` | Both clients | derived | Stem of the output CSV filename |
| `CERT_DIR` | All containers | `/certs` | Path to the certificate directory |
| `RESULTS_DIR` | Both clients | `/results` | Path where the CSV is written inside the container |
| `SIG_ALG` | Server entrypoints | `mldsa65` | Shorthand for both TLS and QUIC server sig alg |

---

## 6. Running the Full Evaluation Suite

The master orchestration script iterates every combination of
**protocol × KEM × network condition** automatically.

### 6.1 Full suite

```bash
chmod +x scripts/*.sh
./scripts/run_experiments.sh
```

This runs **all 18 KEMs × 2 protocols × 4 network conditions = 144 scenarios**, each with 1000 measured handshakes. **Estimated total time: 6–10 hours** depending on hardware.

Results are saved to `results/raw/<YYYYMMDD_HHMMSS>/`.

### 6.2 Filtering by protocol

```bash
# TLS only
./scripts/run_experiments.sh --protocol tls

# QUIC only
./scripts/run_experiments.sh --protocol quic
```

### 6.3 Filtering by network condition

```bash
# Ideal conditions only (fastest; isolates cryptographic cost)
./scripts/run_experiments.sh --network ideal

# Medium loss only
./scripts/run_experiments.sh --network medium_loss

# All lossy conditions but not ideal
# (run three times manually, or modify the script)
./scripts/run_experiments.sh --network low_loss
./scripts/run_experiments.sh --network medium_loss
./scripts/run_experiments.sh --network high_loss
```

### 6.4 Filtering by KEM

```bash
# Single KEM, all protocols, all network conditions
./scripts/run_experiments.sh --kem mlkem768

# Single KEM, TLS only, ideal network
./scripts/run_experiments.sh --kem x25519_mlkem768 --protocol tls --network ideal
```

### 6.5 Dry run

Print every command that would be executed without running anything:

```bash
./scripts/run_experiments.sh --dry-run
```

Use this to verify your filter combination before committing to a long run.

### 6.6 All flags at a glance

```
Usage: run_experiments.sh [OPTIONS]

  --protocol  tls|quic|both   Protocols to evaluate    (default: both)
  --network   LABEL|all       Network condition filter  (default: all)
  --kem       NAME            Run a single KEM          (default: all 18)
  --runs      N               Handshakes per scenario   (default: 1000)
  --warmup    N               Warm-up runs (discarded)  (default: 50)
  --sig       ALG             Signature algorithm       (default: mldsa65)
  --no-pcap                   Skip packet capture
  --dry-run                   Print commands, don't run
  --help                      Show this message

Environment variables (alternative to flags):
  PROTOCOL, NETWORK_CONDITION, N_RUNS, WARMUP_RUNS, SIG_ALG, RESULTS_DIR
```

**Common invocation patterns:**

```bash
# Reproduce the paper's ideal-network results (~45 min)
./scripts/run_experiments.sh --network ideal

# Quick validation: Level III KEMs only under all conditions (~1 h)
for kem in p384 x448 x25519_mlkem768 secp384r1_mlkem768 x448_mlkem768 mlkem768 hqc192; do
  ./scripts/run_experiments.sh --kem "$kem"
done

# High-performance run: 100 measurements per scenario for a preview
./scripts/run_experiments.sh --runs 100 --warmup 10 --network ideal
```

---

## 7. Network Condition Emulation

### 7.1 How Pumba works

[Pumba](https://github.com/alexei-led/pumba) uses the Linux Traffic Control
subsystem (`tc netem`) to inject delay, jitter, and packet loss at the
**container's virtual Ethernet interface**. Only the targeted container
(the client) is affected; the server sees clean traffic.

The effect is asymmetric emulation: the client's outgoing packets are delayed
and some are dropped before they reach the server, and the server's responses
are not affected. This models the most common real-world scenario (a client
on a degraded link).

### 7.2 Applying conditions manually

```bash
# Syntax: apply_network.sh <container> <delay_ms> <jitter_ms> <loss_pct>

# Low loss profile
./scripts/apply_network.sh tls-client 20 2 0.1

# Medium loss profile
./scripts/apply_network.sh tls-client 50 5 1.0

# High loss profile
./scripts/apply_network.sh tls-client 100 10 5.0

# Custom profile: 200 ms delay, 20 ms jitter, 3% loss
./scripts/apply_network.sh tls-client 200 20 3.0
```

The Pumba container runs in the background and remains active until killed.

### 7.3 Removing conditions

```bash
docker rm -f pumba
```

Or via the orchestration script which removes Pumba automatically between
scenarios.

### 7.4 Predefined condition profiles

These match the `network_conditions` section of `configs/scenarios.yaml`:

| Label | Delay | Jitter | Loss | Representative scenario |
|---|---|---|---|---|
| `ideal` | 0 ms | 0 ms | 0 % | Loopback; isolates cryptographic cost |
| `low_loss` | 20 ms | 2 ms | 0.1 % | Good home broadband or office LAN |
| `medium_loss` | 50 ms | 5 ms | 1 % | Mobile 4G or moderate congestion |
| `high_loss` | 100 ms | 10 ms | 5 % | Satellite link or heavily congested Wi-Fi |

---

## 8. Packet Capture

Packet captures let you measure **bandwidth overhead per handshake**
(total bytes and packet counts) independently of the timing measurements.
They also serve as ground-truth verification that the correct handshake
message sequence is being exchanged.

### 8.1 EdgeShark (preferred)

EdgeShark runs as a sidecar service and exposes an HTTP streaming endpoint
that delivers live pcap feeds for any container.

**Install EdgeShark:**

```bash
# Pull and run the EdgeShark stack (one-time setup)
curl -sL https://github.com/siemens/edgeshark/releases/latest/download/docker-compose.yaml \
  | docker compose -f - up -d
```

**Verify it is running:**

```bash
curl -sf http://localhost:5001/ && echo "EdgeShark is ready"
```

**Capture during a scenario** (EdgeShark is used automatically by
`collect_pcaps.sh` when available):

```bash
./scripts/collect_pcaps.sh tls-client results/raw/tls_mlkem768_ideal.pcapng &
PCAP_PID=$!

# Run your scenario here...

kill $PCAP_PID
```

### 8.2 nsenter + tcpdump (fallback)

If EdgeShark is not available, `collect_pcaps.sh` falls back to entering the
container's network namespace with `nsenter` and running `tcpdump` directly.

Requirements:

```bash
sudo apt install tcpdump
# The calling user needs CAP_SYS_PTRACE + CAP_NET_ADMIN, or run as root.
```

### 8.3 Manual capture

To capture a single scenario manually using the sidecar approach
(no root required beyond Docker socket access):

```bash
# Start capture in background
docker run --rm -d \
  --name pcap-sidecar \
  --network container:tls-client \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v "$(pwd)/results/raw:/out" \
  nicolaka/netshoot:latest \
  tcpdump -i any -s 0 -U -w /out/tls_mlkem768_ideal.pcapng \
  "tcp or udp port 4433"

# Run your TLS scenario...

# Stop capture
docker rm -f pcap-sidecar
```

To inspect a capture interactively with Wireshark:

```bash
wireshark results/raw/tls_mlkem768_ideal.pcapng
```

Or with tshark:

```bash
tshark -r results/raw/tls_mlkem768_ideal.pcapng \
  -T fields \
  -e frame.number \
  -e frame.len \
  -e tls.handshake.type \
  -e tls.handshake.length \
  2>/dev/null | head -30
```

---

## 9. Analysis Pipeline

The analysis pipeline is a sequence of five Python scripts. Each script
reads from and writes to the `results/` directory.

```
results/raw/*.log
        │
        ▼
parse_results.py  ──►  results/csv/combined_results.csv
parse_pcaps.py    ──►  results/csv/pcap_stats.csv
        │
        ▼
statistics.py     ──►  results/csv/statistics_summary.csv
                  ──►  results/csv/pairwise_tests.csv
                  ──►  results/csv/tls_vs_quic.csv
        │
        ▼
plot_results.py   ──►  results/plots/*.png
report.py         ──►  results/report.md
```

### 9.1 Step 1 — Parse timing logs

Reads all `*.log` files from `results/raw/` and combines them into a single
annotated CSV.

```bash
python3 analysis/parse_results.py
```

**Options:**

```
--raw-dir DIR          Directory containing .log files  (default: results/raw)
--output FILE          Output CSV path  (default: results/csv/combined_results.csv)
--remove-outliers      Remove IQR-based outliers (1.5× IQR rule) before saving
```

**Examples:**

```bash
# Use a timestamped run directory
python3 analysis/parse_results.py \
  --raw-dir results/raw/20260115_143022

# Remove outliers before saving
python3 analysis/parse_results.py --remove-outliers

# Specify a custom output file
python3 analysis/parse_results.py \
  --output results/csv/ideal_only.csv \
  --raw-dir results/raw/ideal_run
```

**Expected filename pattern for log files:**

```
<protocol>_<kem_group>_<network_condition>.log

Examples:
  tls_mlkem768_ideal.log
  quic_x25519_mlkem768_medium_loss.log
  tls_p256_low_loss.log
```

Files that do not match this pattern are skipped with a warning.

### 9.2 Step 2 — Parse pcap files

Reads all `*.pcap` / `*.pcapng` files from `results/raw/` and extracts
per-handshake packet and byte counts.

```bash
python3 analysis/parse_pcaps.py
```

**Options:**

```
--pcap-dir DIR    Directory containing pcap files  (default: results/raw)
--output FILE     Output CSV path  (default: results/csv/pcap_stats.csv)
```

> **Note:** This step requires `tshark` to be installed on the host and
> `pyshark` to be installed in the Python environment.
> It can be skipped if packet capture was not performed.

### 9.3 Step 3 — Statistical analysis

Computes descriptive statistics and hypothesis tests for every
protocol × KEM × network group.

```bash
python3 analysis/statistics.py
```

**Options:**

```
--input FILE       Combined CSV from parse_results.py
                   (default: results/csv/combined_results.csv)
--out-dir DIR      Directory for output CSVs  (default: results/csv)
--alpha FLOAT      Significance level for tests  (default: 0.05)
--protocol PROTO   Filter to tls or quic only
--network LABEL    Filter to a single network condition
```

**Examples:**

```bash
# Statistics for TLS ideal-network results only
python3 analysis/statistics.py \
  --protocol tls \
  --network ideal

# Custom significance level
python3 analysis/statistics.py --alpha 0.01
```

**Output files produced:**

| File | Contents |
|---|---|
| `statistics_summary.csv` | Per-group descriptive stats (see §10.3) |
| `pairwise_tests.csv` | Welch's t-test for every KEM pair within each protocol × network |
| `tls_vs_quic.csv` | Head-to-head TLS vs. QUIC comparison per KEM × network |

### 9.4 Step 4 — Generate plots

Produces all publication-ready figures.

```bash
python3 analysis/plot_results.py
```

**Options:**

```
--input FILE     Combined results CSV  (default: results/csv/combined_results.csv)
--stats FILE     Statistics summary CSV  (default: results/csv/statistics_summary.csv)
--out-dir DIR    Output directory for .png files  (default: results/plots)
```

**Figures produced:**

| Filename | Description |
|---|---|
| `bar_ideal_latency.png` | Mean handshake latency by KEM, grouped by NIST level, both protocols |
| `box_latency_tls.png` | TLS latency distribution per KEM (box plot) |
| `box_latency_quic.png` | QUIC latency distribution per KEM (box plot) |
| `line_loss_impact.png` | Mean latency vs. network condition for Level I representative KEMs |
| `bar_tls_vs_quic.png` | Side-by-side TLS vs. QUIC comparison per KEM |
| `heatmap_overhead.png` | Relative overhead (×) vs. P-256 baseline, heatmap |

### 9.5 Step 5 — Generate report

Assembles a Markdown summary report from all analysis CSVs.

```bash
python3 analysis/report.py
```

**Options:**

```
--stats FILE    Statistics summary CSV  (default: results/csv/statistics_summary.csv)
--h2h   FILE    TLS-vs-QUIC comparison  (default: results/csv/tls_vs_quic.csv)
--pcap  FILE    Pcap stats CSV          (default: results/csv/pcap_stats.csv)
--output FILE   Output Markdown file    (default: results/report.md)
```

Open the report:

```bash
# In a Markdown viewer (e.g. VS Code)
code results/report.md

# As plain text
cat results/report.md
```

### 9.6 Running the full pipeline in one shot

```bash
#!/usr/bin/env bash
set -e

RAW_DIR="${1:-results/raw}"

python3 analysis/parse_results.py  --raw-dir "$RAW_DIR"
python3 analysis/parse_pcaps.py    --pcap-dir "$RAW_DIR"   # skip if no pcaps
python3 analysis/statistics.py
python3 analysis/plot_results.py
python3 analysis/report.py

echo "Done. Report: results/report.md"
echo "Plots:        results/plots/"
```

Save as `scripts/run_analysis.sh` and run:

```bash
chmod +x scripts/run_analysis.sh
./scripts/run_analysis.sh results/raw/20260115_143022
```

---

## 10. Understanding the Results

### 10.1 Timing log format

Each scenario produces one CSV file:

```
run,latency_us,timestamp_us
0,1842,1700000000000000
1,1791,1700000000001842
2,1834,1700000000003633
...
```

| Column | Type | Description |
|---|---|---|
| `run` | int | Zero-based measurement index (warmup runs already excluded) |
| `latency_us` | int | Handshake duration in **microseconds** |
| `timestamp_us` | int | `CLOCK_MONOTONIC` timestamp at start of this handshake (µs since epoch) |

**What "handshake duration" covers:**

- **TLS**: wall-clock time from before `SSL_connect()` to after it returns —
  the complete TLS 1.3 handshake including `ClientHello → ServerHello +
  EncryptedExtensions + Certificate + CertificateVerify + Finished → Finished`.
- **QUIC**: wall-clock time from before `ConnectionStart()` to the first
  instruction of the `QUIC_CONNECTION_EVENT_CONNECTED` callback — the complete
  QUIC + TLS 1.3 integrated handshake.

Both measurements use `CLOCK_MONOTONIC` with nanosecond resolution, reported
in microseconds.

### 10.2 Combined CSV columns

`results/csv/combined_results.csv` — produced by `parse_results.py`:

| Column | Description |
|---|---|
| `run` | Measurement index within the scenario |
| `latency_us` | Handshake latency in µs |
| `timestamp_us` | CLOCK_MONOTONIC start timestamp in µs |
| `protocol` | `tls` or `quic` |
| `kem` | OQS-Provider KEM group name (e.g. `mlkem768`) |
| `kem_type` | `traditional`, `hybrid`, or `post_quantum` |
| `security_level` | NIST level: `I`, `III`, or `V` |
| `network` | `ideal`, `low_loss`, `medium_loss`, or `high_loss` |
| `source_file` | Original log filename |

### 10.3 Statistics summary columns

`results/csv/statistics_summary.csv` — produced by `statistics.py`:

| Column | Description |
|---|---|
| `n` | Sample size (measured runs) |
| `mean_us` | Sample mean in µs |
| `std_us` | Sample standard deviation in µs |
| `cv_pct` | Coefficient of variation = (std / mean) × 100 % |
| `median_us` | 50th percentile |
| `q1_us` / `q3_us` | 25th / 75th percentiles |
| `iqr_us` | Interquartile range = q3 − q1 |
| `n_outliers` | Count of values outside [q1 − 1.5×IQR, q3 + 1.5×IQR] |
| `outlier_pct` | Outlier count as a percentage of n |
| `sw_stat` | Shapiro-Wilk test statistic |
| `sw_p` | Shapiro-Wilk p-value (> 0.05 → normally distributed) |
| `is_normal` | Boolean: `True` if `sw_p > 0.05` |

### 10.4 TLS vs QUIC comparison columns

`results/csv/tls_vs_quic.csv` — produced by `statistics.py`:

| Column | Description |
|---|---|
| `kem` | KEM group |
| `network` | Network condition |
| `mean_a_us` | TLS mean latency in µs |
| `mean_b_us` | QUIC mean latency in µs |
| `mean_diff_us` | TLS − QUIC in µs (positive → TLS is slower) |
| `mean_diff_pct` | Difference as % of QUIC mean |
| `levene_stat` / `levene_p` | Levene's test for variance equality |
| `equal_variances` | Boolean: `True` if `levene_p > 0.05` |
| `welch_stat` / `welch_p` | Welch's t-test statistic and p-value |
| `significant` | Boolean: `True` if `welch_p < 0.05` |
| `cohens_d` | Cohen's d effect size |

**Interpreting Cohen's d:**

| |d| | Interpretation |
|---|---|
| < 0.2 | Negligible difference |
| 0.2 – 0.5 | Small effect |
| 0.5 – 0.8 | Medium effect |
| > 0.8 | Large effect |

### 10.5 Generated plots

**`bar_ideal_latency.png`** — The primary comparison figure.
Three subplots (one per NIST security level) show mean ± SEM bars for every
KEM, with TLS (solid) and QUIC (hatched) bars side-by-side.
Bars are colour-coded by KEM type: blue = traditional, orange = hybrid,
green = post-quantum.

**`box_latency_{tls,quic}.png`** — Distribution figures.
Box plots ordered by median latency. Outliers shown as small dots.
Colour-coded by KEM type.

**`line_loss_impact.png`** — Network sensitivity figure.
Mean latency plotted against the four network conditions for representative
Level I KEMs. Shows how each protocol degrades as network quality worsens.

**`bar_tls_vs_quic.png`** — Head-to-head protocol comparison.
Paired bars (TLS vs. QUIC) for every KEM under ideal conditions.

**`heatmap_overhead.png`** — Overhead heatmap.
Relative latency overhead (× multiple vs. P-256 baseline) shown as a
colour-coded grid for all KEMs × protocols. Useful for spotting which
configurations are most expensive at a glance.

---

## 11. Evaluated KEMs and Algorithms

### 11.1 Traditional KEMs

These use classical elliptic-curve Diffie-Hellman and serve as the performance
baseline.

| OQS Group Name | Curve | NIST Level | FIPS |
|---|---|---|---|
| `p256` | NIST P-256 / secp256r1 | I | — |
| `x25519` | Curve25519 | I | — |
| `p384` | NIST P-384 / secp384r1 | III | — |
| `x448` | Curve448 / Goldilocks | III | — |
| `p521` | NIST P-521 / secp521r1 | V | — |

### 11.2 Hybrid KEMs

These concatenate a classical and a post-quantum key share in the TLS
`key_share` extension. Security holds as long as at least one component
is unbroken — the recommended transition strategy per NIST IR 8547.

| OQS Group Name | Classical + PQ | NIST Level |
|---|---|---|
| `x25519_mlkem512` | X25519 + ML-KEM-512 | I |
| `secp256r1_mlkem512` | P-256 + ML-KEM-512 | I |
| `x25519_mlkem768` | X25519 + ML-KEM-768 | III |
| `secp384r1_mlkem768` | P-384 + ML-KEM-768 | III |
| `x448_mlkem768` | X448 + ML-KEM-768 | III |
| `x25519_mlkem1024` | X25519 + ML-KEM-1024 | V |
| `secp521r1_mlkem1024` | P-521 + ML-KEM-1024 | V |

### 11.3 Post-quantum KEMs

Pure post-quantum KEMs that provide quantum resistance without a classical
component.

| OQS Group Name | Standard | Family | NIST Level |
|---|---|---|---|
| `mlkem512` | FIPS 203 | Module-LWE (Kyber) | I |
| `mlkem768` | FIPS 203 | Module-LWE (Kyber) | III |
| `mlkem1024` | FIPS 203 | Module-LWE (Kyber) | V |
| `hqc128` | In process | Quasi-cyclic codes | I |
| `hqc192` | In process | Quasi-cyclic codes | III |
| `hqc256` | In process | Quasi-cyclic codes | V |

### 11.4 Signature algorithms

The default fixed signature is **`mldsa65`** (ML-DSA, NIST Level III).
It is used unchanged across all KEM experiments to isolate the KEM
as the performance variable.

| OQS Name | Standard | NIST Level | Approx. sig size |
|---|---|---|---|
| `mldsa44` | FIPS 204 | II | 2.4 KB |
| `mldsa65` | FIPS 204 | III | 3.3 KB — **default** |
| `mldsa87` | FIPS 204 | V | 4.6 KB |
| `falcon512` | In process | I | 0.7 KB |
| `falcon1024` | In process | V | 1.3 KB |
| `sphincssha2128fsimple` | FIPS 205 | I | 17 KB |
| `sphincssha2128ssimple` | FIPS 205 | I | 8 KB |

---

## 12. Extending the Framework

### 12.1 Adding a new KEM

**Step 1** — Check availability in the current build:

```bash
docker run --rm pqc-base:latest \
  openssl list -kem-algorithms -provider oqsprovider 2>/dev/null \
  | grep -i <your_algorithm>
```

**Step 2** — Add it to `configs/scenarios.yaml` under the correct type and level:

```yaml
kems:
  post_quantum:
    level_III:
      - mlkem768
      - hqc192
      - <your_new_kem>   # ← add here
```

**Step 3** — No code changes needed. Re-run the experiments:

```bash
./scripts/run_experiments.sh --kem <your_new_kem>
```

### 12.2 Adding a new signature algorithm

**Step 1** — Check availability:

```bash
docker run --rm pqc-base:latest \
  openssl list -signature-algorithms -provider oqsprovider 2>/dev/null \
  | grep -i <your_sig_alg>
```

**Step 2** — Generate new certificates:

```bash
docker run --rm \
  -v pqc-eval_certs:/certs \
  pqc-tls-server:latest \
  /src/certs/gen_certs.sh <your_sig_alg> /certs
```

**Step 3** — Run with the new signature algorithm:

```bash
./scripts/run_experiments.sh --sig <your_sig_alg>
```

### 12.3 Adding a new network condition

**Step 1** — Add a profile to `configs/scenarios.yaml`:

```yaml
network_conditions:
  my_profile:
    delay_ms:    75
    jitter_ms:   8
    loss_pct:    2.5
    description: "Custom profile"
```

**Step 2** — Add the profile to the `NET_DELAY`, `NET_JITTER`, `NET_LOSS`
dictionaries in `scripts/run_experiments.sh`:

```bash
declare -A NET_DELAY=( ... [my_profile]=75  )
declare -A NET_JITTER=( ... [my_profile]=8  )
declare -A NET_LOSS=(   ... [my_profile]=2.5 )
```

**Step 3** — Run with the new condition:

```bash
./scripts/run_experiments.sh --network my_profile
```

### 12.4 Changing the number of runs

For a quick preview (100 runs per scenario, ~6× faster):

```bash
./scripts/run_experiments.sh --runs 100 --warmup 10
```

For higher confidence (2000 runs per scenario):

```bash
./scripts/run_experiments.sh --runs 2000 --warmup 100
```

The Shapiro-Wilk normality test is limited to the first 5000 samples by
`scipy`; all other statistics scale to any sample size.

---

## 13. Troubleshooting

### 13.1 Build failures

**`liboqs build fails with CMake error`**

```
Solution: Ensure cmake ≥ 3.20 and ninja-build are present in the
          builder image. Check docker/base/Dockerfile line 10:
          apt-get install -y cmake ninja-build
```

**`OpenSSL build fails: ./config not found`**

```
Cause:    The wget download of the OpenSSL tarball failed (network issue
          inside the build container).
Solution: Check your Docker daemon's DNS and proxy settings.
          docker build --network host docker/base/
```

**`OQS-Provider: liboqs not found`**

```
Cause:    The liboqs CMake target was not installed to the expected prefix.
Solution: Verify /opt/oqs/lib/cmake/liboqs/liboqsConfig.cmake exists:
          docker run --rm pqc-base:latest find /opt/oqs -name "*.cmake"
```

**`MsQuic build fails: OpenSSL version mismatch`**

```
Cause:    MsQuic requires OpenSSL ≥ 3.1 with QUIC APIs.
Solution: The Dockerfile builds OpenSSL 3.3.2 which satisfies this.
          If you see version errors, ensure OPENSSL_ROOT_DIR is set to
          /opt/openssl in the MsQuic cmake invocation.
```

### 13.2 Runtime errors

**`Failed to set KEM group 'mlkem768'`**

```
Cause:    OQS-Provider is not loaded in the TLS client's OpenSSL context.
Solution: 1. Verify the provider is available:
             docker run --rm pqc-tls-client:latest \
               openssl list -providers -provider oqsprovider
          2. Check /opt/openssl/ssl/openssl.cnf contains [oqsprovider_sect].
          3. Ensure OPENSSL_CONF is not being overridden in the container.
```

**`ConfigurationLoadCredential failed: 0x80000004`**

```
Cause:    QUIC_STATUS_NOT_FOUND — the certificate or key file was not found.
Solution: 1. Verify certificates exist in the volume:
             docker run --rm -v pqc-eval_certs:/c alpine ls /c
          2. If empty, regenerate:
             docker volume rm pqc-eval_certs
             docker compose up -d quic-server   # triggers auto-generation
```

**`MsQuicOpen2 failed: 0x80000001`**

```
Cause:    Out of memory or libmsquic.so not found.
Solution: Check LD_LIBRARY_PATH includes /opt/msquic/lib:
             docker run --rm pqc-quic-client:latest ldd /app/quic-client
```

**TLS client: all runs fail with `SSL_connect error=5`**

```
Cause:    The server is not running or the KEM group is unsupported.
Solution: 1. Check the server is healthy:
             docker compose ps tls-server
          2. Try the simplest classical KEM first:
             TLS_KEM_GROUP=x25519 docker compose --profile tls run --rm tls-client
          3. Check TLS 1.3 is negotiated:
             docker exec tls-server \
               /opt/openssl/bin/openssl s_client \
               -connect tls-server:4433 -brief < /dev/null
```

**QUIC client: high failure rate under lossy conditions**

```
Cause:    QUIC's handshake timeout (10 s) is too short for the emulated
          loss rate and round-trip time combination.
Solution: Increase the timeout in src/quic/client.c:
             Settings.HandshakeIdleTimeoutMs = 30000;  // 30 s
          Then rebuild the quic-client image:
             docker compose build quic-client
```

**`Pumba container exited immediately`**

```
Cause:    Pumba requires access to the Docker socket and CAP_NET_ADMIN.
Solution: 1. Verify /var/run/docker.sock is accessible.
          2. Run Docker with the correct permissions:
             ls -la /var/run/docker.sock
          3. Add your user to the docker group:
             sudo usermod -aG docker $USER && newgrp docker
          4. Check Pumba logs:
             docker logs pumba 2>&1 | tail -20
```

### 13.3 Analysis errors

**`parse_results.py: No .log files found`**

```
Solution: Check the --raw-dir path. Results are inside a timestamped
          subdirectory:
          ls results/raw/
          python3 analysis/parse_results.py \
            --raw-dir results/raw/20260115_143022
```

**`parse_pcaps.py: Import "pyshark" could not be resolved`**

```
Solution: pip install pyshark
          Also ensure tshark is installed: apt install tshark
```

**`statistics.py: No statistics computed — check input data`**

```
Cause:    combined_results.csv is empty or has fewer than 10 rows per group.
Solution: 1. Check the CSV has data:
             wc -l results/csv/combined_results.csv
          2. Re-run parse_results.py with the correct directory.
          3. Lower the minimum group size in statistics.py (line ~170):
             if len(data) < 10:  →  if len(data) < 5:
```

### 13.4 Diagnostic commands

```bash
# List all available KEM algorithms
docker run --rm pqc-base:latest \
  openssl list -kem-algorithms -provider oqsprovider 2>/dev/null

# List all available signature algorithms
docker run --rm pqc-base:latest \
  openssl list -signature-algorithms -provider oqsprovider 2>/dev/null

# Verify OQS-Provider loads correctly
docker run --rm pqc-base:latest \
  openssl list -providers -provider oqsprovider 2>/dev/null

# Test a TLS handshake manually from inside the container
docker exec tls-server \
  /opt/openssl/bin/openssl s_client \
    -connect tls-server:4433 \
    -groups mlkem768 \
    -CAfile /certs/ca.crt \
    -brief \
  < /dev/null

# Check what algorithms were negotiated in the last handshake
docker exec tls-server \
  /opt/openssl/bin/openssl s_client \
    -connect tls-server:4433 \
    -groups mlkem768 \
  < /dev/null 2>&1 \
  | grep -E "Protocol|Cipher|Server Temp Key|Group"

# Inspect Docker volume contents
docker run --rm -v pqc-eval_certs:/c   alpine ls -la /c
docker run --rm -v pqc-eval_results:/r alpine ls -la /r

# Check image sizes
docker images | grep pqc

# Monitor resource usage during a run
docker stats tls-client tls-server

# View container logs
docker logs tls-server --tail 50
docker logs quic-client --tail 50
```

---

## 14. Reproduction Checklist

Use this checklist to reproduce the results of the original paper.

- [ ] **Prerequisites met:** Docker 24+, Compose V2, Linux host, Python 3.11+,
      25 GB free disk, 4 GB RAM.

- [ ] **Base image built:**
      ```bash
      docker compose build base
      ```

- [ ] **All service images built:**
      ```bash
      docker compose build
      ```

- [ ] **Python dependencies installed:**
      ```bash
      pip install -r analysis/requirements.txt
      ```

- [ ] **Smoke test passed:**
      ```bash
      KEM_GROUP=mlkem768 N_RUNS=50 WARMUP_RUNS=5 \
        docker compose --profile tls up --abort-on-container-exit
      # Expected: "success=50 fail=0"
      ```

- [ ] **Certificates generated** (happens automatically on first server start):
      ```bash
      docker run --rm -v pqc-eval_certs:/c alpine ls /c
      # Expected: ca.crt  server.crt  server.key
      ```

- [ ] **Ideal-network full suite run:**
      ```bash
      ./scripts/run_experiments.sh --network ideal
      # Takes ~45 minutes. Results in results/raw/<timestamp>/
      ```

- [ ] **Lossy-network runs:**
      ```bash
      ./scripts/run_experiments.sh --network low_loss
      ./scripts/run_experiments.sh --network medium_loss
      ./scripts/run_experiments.sh --network high_loss
      ```

- [ ] **Analysis pipeline complete:**
      ```bash
      python3 analysis/parse_results.py
      python3 analysis/statistics.py
      python3 analysis/plot_results.py
      python3 analysis/report.py
      ```

- [ ] **Key findings match expectations (from abstract):**
  - Hybrid KEMs (e.g. `x25519_mlkem768`) show the **highest** latency.
  - Pure PQ KEMs (e.g. `mlkem768`) show **moderate** overhead.
  - QUIC outperforms TLS in lossy conditions.
  - This can be verified from `results/csv/tls_vs_quic.csv`:
    - `mean_diff_pct > 0` means TLS is slower than QUIC.
    - `significant = True` means the difference is statistically confirmed.

---

*End of Usage Manual.*