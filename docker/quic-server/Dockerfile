ARG BASE_IMAGE=pqc-base:latest
FROM ${BASE_IMAGE}

# Build MsQuic 2.4.4 against our OQS-enabled OpenSSL
ARG MSQUIC_VERSION=v2.4.4
WORKDIR /build
RUN git clone --depth 1 --branch ${MSQUIC_VERSION} --recursive \
    https://github.com/microsoft/msquic.git

RUN cmake -S /build/msquic -B /build/msquic/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DQUIC_TLS=openssl \
        -DQUIC_ENABLE_LOGGING=OFF \
        -DQUIC_BUILD_TOOLS=OFF \
        -DQUIC_BUILD_TEST=OFF \
        -DQUIC_BUILD_PERF=OFF \
        -DOPENSSL_ROOT_DIR=/opt/openssl \
        -DOPENSSL_USE_STATIC_LIBS=OFF \
        -DCMAKE_INSTALL_PREFIX=/opt/msquic \
    && cmake --build /build/msquic/build --parallel $(nproc) \
    && cmake --install /build/msquic/build

ENV LD_LIBRARY_PATH="/opt/msquic/lib:/opt/openssl/lib64:/opt/openssl/lib:${LD_LIBRARY_PATH:-}"

# Build QUIC server
COPY src/quic/ /src/quic/
RUN cmake -S /src/quic -B /src/quic/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/opt/openssl \
        -DMSQUIC_PATH=/opt/msquic \
    && cmake --build /src/quic/build --parallel $(nproc) \
    && cp /src/quic/build/quic-server /app/quic-server

COPY src/certs/ /src/certs/
RUN chmod +x /src/certs/gen_certs.sh

EXPOSE 4433/udp

COPY docker/quic-server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
