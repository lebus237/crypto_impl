ARG BASE_IMAGE=pqc-base:latest
FROM ${BASE_IMAGE}

COPY src/tls/ /src/tls/
RUN cmake -S /src/tls -B /src/tls/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DOPENSSL_ROOT_DIR=/opt/openssl \
    && cmake --build /src/tls/build --parallel $(nproc) \
    && cp /src/tls/build/tls-client /app/tls-client

RUN mkdir -p /certs /results

COPY docker/tls-client/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
