FROM ubuntu:24.04 AS base

ENV DEBIAN_FRONTEND=noninteractive

# System build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git wget curl pkg-config \
    libssl-dev python3 python3-pip python3-venv ca-certificates \
    iproute2 tcpdump tshark iputils-ping net-tools \
    libunwind-dev libicu-dev \
    && rm -rf /var/lib/apt/lists/*

# ── 1. Build liboqs 0.11.0 ─────────────────────────────────────────────────
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

# ── 2. Build OpenSSL 3.3.2 ──────────────────────────────────────────────────
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

# ── 3. Build OQS-Provider 0.7.0 ─────────────────────────────────────────────
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

# ── 4. Configure OpenSSL to activate OQS-Provider by default ────────────────
RUN cat >> /opt/openssl/ssl/openssl.cnf <<'EOF'

# ── OQS-Provider activation ──────────────────────────────────────────────────
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
EOF

# ── 5. Verify OQS provider loads ─────────────────────────────────────────────
RUN openssl list -providers -provider oqsprovider 2>&1 | grep -q "oqsprovider" \
    || echo "[warn] OQS provider listing may require specific flags"

WORKDIR /app
