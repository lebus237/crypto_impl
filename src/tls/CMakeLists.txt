# =============================================================================
# CMakeLists.txt — TLS 1.3 server & client (OpenSSL + OQS-Provider)
# =============================================================================

cmake_minimum_required(VERSION 3.20)
project(pqc_tls_eval C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Compiler flags ────────────────────────────────────────────────────────────
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -O2
    -g
)

# ── Find OpenSSL ──────────────────────────────────────────────────────────────
# Prefer the OQS-enabled OpenSSL installed at /opt/openssl.
# Override at cmake time with: -DOPENSSL_ROOT_DIR=/opt/openssl
if(NOT DEFINED OPENSSL_ROOT_DIR AND EXISTS "/opt/openssl")
    set(OPENSSL_ROOT_DIR "/opt/openssl")
endif()

find_package(OpenSSL REQUIRED)

message(STATUS "OpenSSL version : ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include : ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL SSL lib : ${OPENSSL_SSL_LIBRARY}")
message(STATUS "OpenSSL Crypto  : ${OPENSSL_CRYPTO_LIBRARY}")

# Warn if the found OpenSSL is older than 3.0
if(OPENSSL_VERSION VERSION_LESS "3.0.0")
    message(WARNING
        "OpenSSL ${OPENSSL_VERSION} found, but >= 3.0.0 is required "
        "for OQS-Provider support. Set OPENSSL_ROOT_DIR to the correct path.")
endif()

# ── Helper: common link/include setup ────────────────────────────────────────
function(apply_openssl_settings target)
    target_include_directories(${target} PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${target} PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    # On some Linux distros the runtime linker needs a hint
    target_link_options(${target} PRIVATE
        "-Wl,-rpath,${OPENSSL_ROOT_DIR}/lib64"
        "-Wl,-rpath,${OPENSSL_ROOT_DIR}/lib"
    )
endfunction()

# ── tls-server ────────────────────────────────────────────────────────────────
add_executable(tls-server server.c)
apply_openssl_settings(tls-server)

# ── tls-client ────────────────────────────────────────────────────────────────
add_executable(tls-client client.c)
apply_openssl_settings(tls-client)

# ── Installation ─────────────────────────────────────────────────────────────
install(TARGETS tls-server tls-client
    RUNTIME DESTINATION bin
)
