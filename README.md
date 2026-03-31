# PQC TLS/QUIC Handshake Performance Evaluation Framework

A Docker-based framework for evaluating post-quantum cryptographic (PQC)
handshake performance in TLS 1.3 (over TCP) and QUIC (over UDP), implementing
the methodology described in:

> Montenegro, J.A., Rios, R., Bonilla, J.
> *"Comparative analysis of post-quantum handshake performance in QUIC and TLS protocols"*
> Computer Networks 275 (2026) 111957.
> DOI: [10.1016/j.comnet.2025.111957](https://doi.org/10.1016/j.comnet.2025.111957)

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                        Docker Network  eval-net  172.28.0.0/24            │
│                                                                           │
│   ┌─────────────────────┐   TCP :4433   ┌─────────────────────┐          │
│   │     tls-client      │◄─────────────►│     tls-server      │          │
│   │     172.28.0.11     │               │     172.28.0.10     │          │
│   │  OpenSSL 3.3.2      │               │  OpenSSL 3.3.2      │          │
│   └─────────────────────┘               └─────────────────────┘          │
│                                                                           │
│   ┌─────────────────────┐   UDP :4433   ┌─────────────────────┐          │
│   │     quic-client     │◄─────────────►│     quic-server     │          │
│   │     172.28.0.21     │               │     172.28.0.20     │          │
│   │  MsQuic 2.4.4       │               │  MsQuic 2.4.4       │          │
│   └─────────────────────┘               └─────────────────────┘          │
│                                                                           │
│   ┌──────────┐   Network emulation : Pumba (Linux tc netem)               │
│   │  pumba   │   Packet capture   : EdgeShark / nsenter + tcpdump         │
│   └──────────┘                                                            │
└───────────────────────────────────────────────────────────────────────────┘
```

All containers share a **`pqc-base`** image built with:

| Component | Version | Role |
|---|---|---|
| [liboqs](https://github.com/open-quantum-safe/liboqs) | 0.11.0 | NIST PQC algorithm implementations |
| [OpenSSL](https://www.openssl.org/) | 3.3.2 | TLS 1.3 library |
| [OQS-Provider](https://github.com/open-quantum-safe/oqs-provider) | 0.7.0 | OpenSSL provider exposing PQC algorithms |
| [MsQuic](https://github.com/microsoft/msquic) | 2.4.4 | Cross-platform QUIC implementation |

---

## Project Structure

```
.
├── docker/
│   ├── base/               Shared base image (liboqs + OpenSSL + OQS-Provider)
│   │   └── Dockerfile
│   ├── tls-server/         TLS 1.3 server container
│   │   ├── Dockerfile
│   │   └── entrypoint.sh
│   ├── tls-client/         TLS 1.3 client container (with CLOCK_MONOTONIC timing)
│   │   ├── Dockerfile
│   │   └── entrypoint.sh
│   ├── quic-server/        QUIC server container (MsQuic + OQS-OpenSSL)
│   │   ├── Dockerfile
│   │   └── entrypoint.sh
│   └── quic-client/        QUIC client container (event-driven timing)
│       ├── Dockerfile
│       └── entrypoint.sh
├── src/
│   ├── tls/
│   │   ├── server.c        OpenSSL TLS 1.3 server
│   │   ├── client.c        OpenSSL TLS 1.3 client (handshake timing)
│   │   └── CMakeLists.txt
│   ├── quic/
│   │   ├── server.c        MsQuic QUIC server
│   │   ├── client.c        MsQuic QUIC client (event-driven timing)
│   │   └── CMakeLists.txt
│   └── certs/
│       └── gen_certs.sh    Generate PQC X.509 certificates via OQS-OpenSSL
├── scripts/
│   ├── run_experiments.sh  Master orchestrator — iterates all scenarios
│   ├── run_tls.sh          Single TLS scenario runner
│   ├── run_quic.sh         Single QUIC scenario runner
│   ├── apply_network.sh    Pumba wrapper for tc-netem emulation
│   └── collect_pcaps.sh    Packet capture (EdgeShark or nsenter+tcpdump)
├── analysis/
│   ├── parse_results.py    Raw timing logs → combined CSV dataset
│   ├── parse_pcaps.py      Pcap files → per-handshake bandwidth stats
│   ├── statistics.py       Descriptive stats + Shapiro-Wilk/Levene/Welch tests
│   ├── plot_results.py     Publication-ready figures (matplotlib + seaborn)
│   ├── report.py           Markdown summary report generator
│   └── requirements.txt    Python dependencies
├── configs/
│   └── scenarios.yaml      Complete experiment configuration
├── results/
│   ├── raw/                Raw timing logs (.log) and captures (.pcapng)
│   ├── csv/                Processed CSV datasets
│   └── plots/              Generated figures (.png)
├── docker-compose.yml
└── README.md               (this file)
```

---

## Quick Start

### Prerequisites

- **Docker Engine** ≥ 24.0 with **Compose V2** (`docker compose`)
- **Linux** host (required for Pumba's `tc netem` support)
- **~25 GB** free disk space (build artifacts for all images)
- **Python 3.11+** (for the analysis pipeline)
- Optional: [EdgeShark](https://github.com/siemens/edgeshark) for container-level packet capture

### 1 — Build the base image

This step compiles liboqs, OpenSSL 3.3.2, and OQS-Provider from source.
It takes approximately **15–20 minutes** on first run.

```bash
docker compose build base
```

### 2 — Build all service images

```bash
docker compose build
```

### 3 — Install Python analysis dependencies

```bash
pip install -r analysis/requirements.txt
```

### 4 — Smoke test (quick sanity check)

Run 100 handshakes with ML-KEM-768 under ideal conditions:

```bash
# TLS
KEM_GROUP=mlkem768 N_RUNS=100 \
    docker compose --profile tls up --abort-on-container-exit

# QUIC
KEM_GROUP=mlkem768 N_RUNS=100 \
    docker compose --profile quic up --abort-on-container-exit
```

Results appear in `results/raw/` via the named Docker volume.

### 5 — Run the full evaluation

```bash
# All protocols × all KEMs × all network conditions (~several hours)
./scripts/run_experiments.sh

# TLS only, ideal network only
./scripts/run_experiments.sh --protocol tls --network ideal

# Single KEM, all conditions
./scripts/run_experiments.sh --kem mlkem768

# Preview without executing
./scripts/run_experiments.sh --dry-run
```

### 6 — Analyse results

```bash
# 1. Parse raw logs into a unified CSV
python3 analysis/parse_results.py

# 2. Compute statistics
python3 analysis/statistics.py

# 3. Generate plots
python3 analysis/plot_results.py

# 4. Generate Markdown report
python3 analysis/report.py
```

Outputs:
- `results/csv/combined_results.csv` — all latency measurements
- `results/csv/statistics_summary.csv` — mean, std, CV, Shapiro-Wilk, etc.
- `results/csv/tls_vs_quic.csv` — head-to-head Welch's t-test results
- `results/plots/*.png` — publication-ready figures
- `results/report.md` — human-readable summary

---

## Evaluated Algorithms

### Key Encapsulation Mechanisms (KEMs)

| Type | Algorithm | NIST Level | FIPS | Based on |
|---|---|---|---|---|
| Traditional | P-256 (ECDH) | I | — | Elliptic Curve |
| Traditional | X25519 | I | — | Elliptic Curve |
| Traditional | P-384 | III | — | Elliptic Curve |
| Traditional | X448 | III | — | Elliptic Curve |
| Traditional | P-521 | V | — | Elliptic Curve |
| Hybrid | X25519 + ML-KEM-512 | I | 203 | EC + Lattice |
| Hybrid | P-256 + ML-KEM-512 | I | 203 | EC + Lattice |
| Hybrid | X25519 + ML-KEM-768 | III | 203 | EC + Lattice |
| Hybrid | P-384 + ML-KEM-768 | III | 203 | EC + Lattice |
| Hybrid | X448 + ML-KEM-768 | III | 203 | EC + Lattice |
| Hybrid | X25519 + ML-KEM-1024 | V | 203 | EC + Lattice |
| Hybrid | P-521 + ML-KEM-1024 | V | 203 | EC + Lattice |
| Post-Quantum | ML-KEM-512 | I | 203 | Module-LWE |
| Post-Quantum | ML-KEM-768 | III | 203 | Module-LWE |
| Post-Quantum | ML-KEM-1024 | V | 203 | Module-LWE |
| Post-Quantum | HQC-128 | I | TBD | Code-based |
| Post-Quantum | HQC-192 | III | TBD | Code-based |
| Post-Quantum | HQC-256 | V | TBD | Code-based |

### Fixed Signature Algorithm

All KEM comparison scenarios use **ML-DSA65** (FIPS 204, NIST Level III) for
server authentication. Keeping the signature algorithm constant isolates the
KEM as the sole performance variable.

---

## Measurement Methodology

### Metrics

| Metric | Description | Unit |
|---|---|---|
| Handshake latency | Wall-clock time from connection initiation to handshake completion | µs |
| Packet exchange volume | Total bytes and packet count per handshake | bytes / count |

### Timing implementation

**TLS client** (`src/tls/client.c`):
- `t_start` = `clock_gettime(CLOCK_MONOTONIC)` immediately before `SSL_connect()`
- `t_end` = `clock_gettime(CLOCK_MONOTONIC)` immediately after `SSL_connect()` returns
- `SSL_connect()` blocks until the full TLS 1.3 handshake completes

**QUIC client** (`src/quic/client.c`):
- `t_start` = `clock_gettime(CLOCK_MONOTONIC)` immediately before `ConnectionStart()`
- `t_end` = `clock_gettime(CLOCK_MONOTONIC)` at the first instruction of the
  `QUIC_CONNECTION_EVENT_CONNECTED` MsQuic callback
- A `pthread_cond_t` makes the main thread block until the callback fires,
  mirroring the blocking semantics of the TLS client

This asymmetry (OpenSSL blocking vs. MsQuic event-driven) was explicitly
addressed by implementing custom MsQuic clients, as described in the paper.

### Statistical analysis

Each scenario produces **1000 measured handshakes** + **50 discarded warmup runs**.
The following statistics are computed per scenario:

| Statistic | Purpose |
|---|---|
| Mean | Central tendency |
| Standard deviation | Absolute dispersion |
| Coefficient of Variation (CV) | Relative dispersion |
| IQR (1.5×) | Outlier identification |
| Shapiro-Wilk test | Normality assessment |
| Levene's test | Homogeneity of variance |
| Welch's t-test | Mean difference significance (α = 0.05) |
| Cohen's d | Effect size |

### Network conditions

| Label | Delay | Jitter | Packet Loss | Description |
|---|---|---|---|---|
| `ideal` | 0 ms | 0 ms | 0 % | Baseline — isolates cryptographic cost |
| `low_loss` | 20 ms | 2 ms | 0.1 % | Good broadband / office LAN |
| `medium_loss` | 50 ms | 5 ms | 1.0 % | Moderate congestion / 4G |
| `high_loss` | 100 ms | 10 ms | 5.0 % | Poor link / satellite / congested Wi-Fi |

Network conditions are applied at the Docker container level using
[Pumba](https://github.com/alexei-led/pumba) (Linux `tc netem`).

---

## KEM Group Configuration

### TLS (OpenSSL)
The KEM group is set directly in C code via:
```c
SSL_CTX_set1_groups_list(ctx, "mlkem768");
```

### QUIC (MsQuic)
MsQuic uses OpenSSL internally on Linux. The KEM group is configured via
the `OPENSSL_CONF` environment variable, which points to a dynamically
generated `openssl.cnf` containing:

```ini
[ssl_default_sect]
Groups = mlkem768
```

This file is generated by the Docker entrypoint scripts
(`docker/quic-server/entrypoint.sh`, `docker/quic-client/entrypoint.sh`)
before launching the QUIC binaries. MsQuic's OpenSSL backend reads the
`Groups` directive during TLS initialisation.

---

## Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| TLS library | OpenSSL 3.3.2 | Widely adopted; extensible via provider API |
| QUIC library | MsQuic 2.4.4 | Stable, mature; selected over OpenSSL's QUIC by the paper |
| PQC provider | liboqs + OQS-Provider 0.7.0 | Official Open Quantum Safe implementations |
| KEM config (TLS) | `SSL_CTX_set1_groups_list()` | Direct C API call |
| KEM config (QUIC) | `OPENSSL_CONF` env var + generated `openssl.cnf` | Transparent to MsQuic binary |
| Session resumption | Disabled on both sides | Forces a fresh full handshake every measurement |
| Timing (TLS) | `CLOCK_MONOTONIC` around `SSL_connect()` | Blocking; straightforward |
| Timing (QUIC) | `CLOCK_MONOTONIC` + `pthread_cond_t` | Event-driven; custom synchronisation |
| Containerisation | Docker + Compose | Reproducible, isolated environments |
| Network emulation | Pumba (`tc netem`) | Container-level; no host-wide side effects |
| Packet capture | EdgeShark → nsenter+tcpdump | Non-intrusive container-level capture |
| Fixed signature | ML-DSA65 (NIST Level III) | Isolates KEM as the performance variable |

---

## Expected Key Findings

Based on the article:

1. **Hybrid KEMs** (e.g. `x25519_mlkem768`) incur the **highest handshake
   latency and bandwidth overhead** — they carry two full key shares
   (classical + PQC) simultaneously.

2. **Pure post-quantum KEMs** (e.g. `mlkem768`) offer a **favourable
   security/performance trade-off** — overhead is moderate compared to
   classical baselines, and they deliver full quantum resistance.

3. **QUIC consistently outperforms TLS** in lossy network conditions —
   its integrated transport + TLS handshake reduces the number of
   retransmission-vulnerable round-trips compared to the layered TCP + TLS
   stack.

---

## Extending the Framework

### Adding a new KEM

1. Verify the KEM name is available in your OQS-Provider build:
   ```bash
   docker run --rm pqc-base:latest \
       openssl list -kem-algorithms -provider oqsprovider
   ```
2. Add the name to `configs/scenarios.yaml` under the appropriate type and level.
3. Re-run the experiments — no code changes needed.

### Adding a new signature algorithm

1. Verify availability:
   ```bash
   docker run --rm pqc-base:latest \
       openssl list -signature-algorithms -provider oqsprovider
   ```
2. Generate new certificates:
   ```bash
   docker run --rm \
       -v $(pwd)/certs:/certs \
       pqc-base:latest \
       /src/certs/gen_certs.sh <new_sig_alg> /certs
   ```
3. Pass `--sig <new_sig_alg>` to `run_experiments.sh`.

### Changing network conditions

Edit `configs/scenarios.yaml` under `network_conditions`, or pass Pumba
parameters directly via environment variables when calling `apply_network.sh`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Failed to set KEM group` | OQS-Provider not loaded | Check `OPENSSL_CONF` and `oqsprovider` availability |
| `ConfigurationLoadCredential failed` | Certificate mismatch or wrong path | Re-run `gen_certs.sh` with the correct sig alg |
| `MsQuicOpen2 failed` | `libmsquic.so` not found | Check `LD_LIBRARY_PATH` includes `/opt/msquic/lib` |
| High failure rate in QUIC | KEM not supported in this build | Verify with `openssl list -kem-algorithms -provider oqsprovider` |
| `pumba` exits immediately | Insufficient Docker socket permissions | Run with `--privileged` or add `CAP_NET_ADMIN` |
| Empty pcap files | EdgeShark not running, nsenter needs root | Use the sidecar tcpdump fallback or install EdgeShark |

---

## References

- NIST FIPS 203 — ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism): https://doi.org/10.6028/NIST.FIPS.203
- NIST FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Algorithm): https://doi.org/10.6028/NIST.FIPS.204
- NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm): https://doi.org/10.6028/NIST.FIPS.205
- Open Quantum Safe project: https://openquantumsafe.org/
- MsQuic documentation: https://github.com/microsoft/msquic/tree/main/docs
- Pumba documentation: https://github.com/alexei-led/pumba
- RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport: https://datatracker.ietf.org/doc/html/rfc9000
- RFC 8446 — TLS 1.3: https://datatracker.ietf.org/doc/html/rfc8446

---

## License

This implementation is released under the **MIT License**.

Copyright (c) 2026 — Based on the methodology of Montenegro et al., Computer Networks 275 (2026) 111957.