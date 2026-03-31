FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

# ── System build dependencies ─────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git wget curl pkg-config \
    python3 python3-pip python3-venv ca-certificates \
    iproute2 tcpdump tshark iputils-ping net-tools \
    libunwind-dev libicu-dev \
    && rm -rf /var/lib/apt/lists/*
# NOTE: libssl-dev is intentionally NOT installed here.
# Installing the system libssl-dev would put OpenSSL 3.0.x headers into
# /usr/include/openssl and /usr/lib/x86_64-linux-gnu, which CMake could
# accidentally pick up instead of our custom-built OpenSSL 3.3.2.
# Everything that needs OpenSSL links against /opt/openssl exclusively.

# ── 1. Build liboqs 0.11.0 ───────────────────────────────────────────────────
ARG LIBOQS_VERSION=0.11.0
WORKDIR /build
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} \
    https://github.com/open-quantum-safe/liboqs.git

RUN cmake -S /build/liboqs -B /build/liboqs/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/opt/oqs \
        -DOQS_USE_OPENSSL=OFF \
        -DBUILD_SHARED_LIBS=ON \
    && cmake --build /build/liboqs/build --parallel $(nproc) \
    && cmake --install /build/liboqs/build

# ── 2. Build OpenSSL 3.3.2 ───────────────────────────────────────────────────
ARG OPENSSL_VERSION=3.3.2
WORKDIR /build
RUN wget -q https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz \
    && tar -xzf openssl-${OPENSSL_VERSION}.tar.gz

RUN cd /build/openssl-${OPENSSL_VERSION} \
    && ./config \
        --prefix=/opt/openssl \
        --openssldir=/opt/openssl/ssl \
        shared \
        no-idea no-mdc2 no-rc5 \
    && make -j$(nproc) \
    && make install_sw \
    && make install_ssldirs

ENV OPENSSL_ROOT_DIR=/opt/openssl
ENV PATH="/opt/openssl/bin:$PATH"
ENV LD_LIBRARY_PATH="/opt/openssl/lib64:/opt/openssl/lib:/opt/oqs/lib:$LD_LIBRARY_PATH"
ENV PKG_CONFIG_PATH="/opt/openssl/lib64/pkgconfig:/opt/openssl/lib/pkgconfig"

# ── 3. Build OQS-Provider 0.7.0 ──────────────────────────────────────────────
ARG OQS_PROVIDER_VERSION=0.7.0
WORKDIR /build
RUN git clone --depth 1 --branch ${OQS_PROVIDER_VERSION} \
    https://github.com/open-quantum-safe/oqs-provider.git

RUN cmake -S /build/oqs-provider -B /build/oqs-provider/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/opt/openssl \
        -Dliboqs_DIR=/opt/oqs/lib/cmake/liboqs \
        -DCMAKE_INSTALL_PREFIX=/opt/openssl \
    && cmake --build /build/oqs-provider/build --parallel $(nproc) \
    && cmake --install /build/oqs-provider/build

# ── 4. Configure openssl.cnf to auto-load the OQS-Provider ───────────────────
#
# WHY a Python script instead of `cat >> openssl.cnf`:
#
#   OpenSSL 3.x installs a default openssl.cnf that may already contain an
#   [openssl_init] section. The cat-append approach would create a DUPLICATE
#   section — OpenSSL silently uses only the FIRST occurrence, so the appended
#   OQS section would be unreachable and the provider would never auto-load.
#
#   Additionally the top-level directive `openssl_conf = openssl_init` must
#   exist in the file for [openssl_init] to be processed at all; appending
#   the section alone is not sufficient.
#
#   The Python script below:
#     (a) Locates oqsprovider.so so the module path is always correct,
#         regardless of whether OpenSSL placed it in lib/ or lib64/.
#     (b) Writes a complete, self-consistent openssl.cnf from scratch,
#         including the mandatory top-level openssl_conf directive.
#     (c) Keeps a minimal [req] block so gen_certs.sh works without
#         requiring -config on every invocation.
#
RUN python3 - <<'PYEOF'
import subprocess, sys, os

# ── Locate the installed oqsprovider.so ──────────────────────────────────────
result = subprocess.run(
    ["find", "/opt/openssl", "-name", "oqsprovider.so"],
    capture_output=True, text=True
)
candidates = [p.strip() for p in result.stdout.strip().splitlines() if p.strip()]

if not candidates:
    print("FATAL: oqsprovider.so not found under /opt/openssl", file=sys.stderr)
    print("       OQS-Provider build may have failed.", file=sys.stderr)
    sys.exit(1)

mod_path = candidates[0]
print(f"[openssl.cnf] oqsprovider module : {mod_path}")

# ── Confirm the module is a valid shared library ──────────────────────────────
if not os.path.isfile(mod_path):
    print(f"FATAL: {mod_path} is not a regular file", file=sys.stderr)
    sys.exit(1)

# ── Write a complete openssl.cnf ──────────────────────────────────────────────
cnf_path = "/opt/openssl/ssl/openssl.cnf"

config = f"""\
# openssl.cnf — generated during Docker build
# Activates the default provider and the OQS-Provider for post-quantum
# cryptography support.  This file is read by all OpenSSL 3.x tools and
# by applications that call OPENSSL_init_ssl() without OPENSSL_INIT_NO_LOAD_CONFIG.
#
# The top-level directive below MUST be present; without it the [openssl_init]
# section is never processed and providers are not auto-loaded.
openssl_conf = openssl_init

# ── Provider configuration ────────────────────────────────────────────────────
[openssl_init]
providers = provider_sect

[provider_sect]
# Built-in default provider (symmetric ciphers, hashes, classical asymmetric)
default     = default_sect
# OQS-Provider: post-quantum KEMs and signature schemes (FIPS 203/204/205)
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
# Absolute path to the provider shared library.
# This makes loading robust regardless of OpenSSL's compiled-in MODULESDIR.
module   = {mod_path}

# ── Certificate / key-generation defaults (used by gen_certs.sh) ─────────────
[req]
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[dn]
C  = ES
O  = PQC-Eval
CN = pqc-eval

[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign
"""

with open(cnf_path, "w") as fh:
    fh.write(config)

print(f"[openssl.cnf] written to {cnf_path}")
PYEOF

# ── 5. Verify both providers load correctly ───────────────────────────────────
# Use OPENSSL_CONF explicitly to test our config file.
# The exit code of `openssl list` is 0 on success; we grep for the provider
# names to confirm they appear in the output.
RUN echo "=== Verifying providers ===" \
    && OPENSSL_CONF=/opt/openssl/ssl/openssl.cnf \
       openssl list -providers 2>&1 \
    | tee /tmp/provider_list.txt \
    && grep -q "oqsprovider" /tmp/provider_list.txt \
    && echo "=== OQS-Provider: FOUND ===" \
    && grep -q "OpenSSL Default Provider" /tmp/provider_list.txt \
    && echo "=== Default provider: FOUND ===" \
    && echo "=== Provider verification PASSED ==="

# ── 6. Quick algorithm smoke-test ─────────────────────────────────────────────
# Confirm that at least one PQC KEM (ML-KEM-768) and one PQC signature
# (ML-DSA-65) are available, which validates the full liboqs -> OQS-Provider
# -> OpenSSL integration chain.
RUN echo "=== Smoke-testing PQC algorithms ===" \
    && OPENSSL_CONF=/opt/openssl/ssl/openssl.cnf \
       openssl list -kem-algorithms -provider oqsprovider 2>&1 \
       | grep -qi "mlkem768" \
    && echo "  mlkem768 : OK" \
    && OPENSSL_CONF=/opt/openssl/ssl/openssl.cnf \
       openssl list -signature-algorithms -provider oqsprovider 2>&1 \
       | grep -qi "mldsa65" \
    && echo "  mldsa65  : OK" \
    && echo "=== Algorithm smoke-test PASSED ==="

WORKDIR /app
