ARG BASE_IMAGE=pqc-base:latest
FROM ${BASE_IMAGE}

# Copy and build TLS sources
COPY src/tls/ /src/tls/
RUN cmake -S /src/tls -B /src/tls/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/opt/openssl \
    && cmake --build /src/tls/build --parallel $(nproc) \
    && cp /src/tls/build/tls-server /app/tls-server

COPY src/certs/ /src/certs/
RUN chmod +x /src/certs/gen_certs.sh

EXPOSE 4433

COPY docker/tls-server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
