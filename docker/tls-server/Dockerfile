ARG BASE_IMAGE=pqc-base:latest
FROM ${BASE_IMAGE}

# ── Copy and build TLS sources ────────────────────────────────────────────────
COPY src/tls/ /src/tls/

# CMake configuration notes:
#
# 1. OPENSSL_ROOT_DIR is already set in the base image ENV, but we pass it
#    explicitly on the cmake command line to guarantee it takes precedence
#    over any cached value or system detection.
#
# 2. CMAKE_PREFIX_PATH prepends /opt/openssl so that find_package(OpenSSL)
#    searches our custom-built 3.3.2 before falling back to the system paths.
#
# 3. PKG_CONFIG_PATH is forwarded so that pkg-config (used as a fallback by
#    some CMake Find modules) also resolves to the correct OpenSSL.
#
# 4. CMAKE_LIBRARY_PATH explicitly lists lib64 and lib so the linker finds
#    libssl.so / libcrypto.so regardless of whether the build installed them
#    into lib/ or lib64/ (OpenSSL on 64-bit Linux defaults to lib64/).
#
# 5. We do NOT install libssl-dev.  The system libssl-dev (OpenSSL 3.0.x on
#    Ubuntu 24.04) would shadow our custom 3.3.2 headers and libraries,
#    causing SSL_get0_group_name() (added in 3.2.0) to be missing at compile
#    time and the wrong libssl to be linked at build time.
RUN cmake -S /src/tls -B /src/tls/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/opt/openssl \
        -DCMAKE_PREFIX_PATH=/opt/openssl \
        -DCMAKE_LIBRARY_PATH="/opt/openssl/lib64;/opt/openssl/lib" \
        -DCMAKE_INCLUDE_PATH=/opt/openssl/include \
        -DPKG_CONFIG_PATH="/opt/openssl/lib64/pkgconfig:/opt/openssl/lib/pkgconfig" \
    && cmake --build /src/tls/build --parallel "$(nproc)" \
    && cmake --install /src/tls/build --prefix /app/install

# Copy the installed binaries to the expected locations
RUN cp /app/install/bin/tls-server /app/tls-server \
    && cp /app/install/bin/tls-client /app/tls-client \
    && chmod +x /app/tls-server /app/tls-client

# ── Copy certificate generation script ───────────────────────────────────────
COPY src/certs/ /src/certs/
RUN chmod +x /src/certs/gen_certs.sh

# ── Sanity-check: confirm the binary links against our custom OpenSSL ─────────
# ldd should show libssl.so.3 resolving to /opt/openssl/lib64/libssl.so.3,
# not to /usr/lib/x86_64-linux-gnu/libssl.so.3 (the system OpenSSL 3.0.x).
RUN echo "=== Checking linked libraries ===" \
    && ldd /app/tls-server \
    && ldd /app/tls-server | grep -E "libssl|libcrypto" \
    && ldd /app/tls-server | grep "libssl" | grep -v "not found" \
    && echo "=== Link check PASSED ==="

EXPOSE 4433/tcp

COPY docker/tls-server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
