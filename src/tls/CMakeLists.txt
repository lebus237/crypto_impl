# =============================================================================
# CMakeLists.txt — TLS 1.3 server & client (OpenSSL + OQS-Provider)
# =============================================================================

cmake_minimum_required(VERSION 3.20)
project(pqc_tls_eval C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ── IMPORTANT: keep extensions ON (gnu11, not c11) ───────────────────────────
# With CMAKE_C_EXTENSIONS OFF, GCC uses strict -std=c11 which, combined with
# _POSIX_C_SOURCE=200809L, hides usleep() from glibc headers because glibc
# only exposes usleep when __USE_XOPEN_EXTENDED is set AND __USE_XOPEN2K8 is
# NOT set. _POSIX_C_SOURCE=200809L sets __USE_XOPEN2K8, making usleep()
# invisible, and GCC 12+ (Ubuntu 24.04) treats implicit function declarations
# as errors in C99/C11 mode. Setting extensions ON uses -std=gnu11 which
# implicitly defines _GNU_SOURCE, making all POSIX/GNU extensions available.
set(CMAKE_C_EXTENSIONS ON)

# ── Compiler flags ────────────────────────────────────────────────────────────
add_compile_options(
    -Wall
    -Wextra
    # -Wpedantic is intentionally omitted: OpenSSL headers use macro patterns
    # (SSL_OP_BIT, SSL_set_tlsext_host_name, etc.) that violate strict ISO C
    # pedantic rules and would generate dozens of warnings from third-party
    # headers that we cannot modify.
    -O2
    -g
)

# ── Find OQS-enabled OpenSSL ──────────────────────────────────────────────────
# The base Docker image installs a custom OpenSSL 3.3.2 at /opt/openssl.
# Ubuntu 24.04 also ships a system OpenSSL 3.0.x via libssl-dev.
# We must prefer the custom build because:
#   (a) OpenSSL 3.0.x lacks SSL_get0_group_name() (added in 3.2.0)
#   (b) The OQS-Provider is linked against our custom build
#
# Priority order for discovery:
#   1. -DOPENSSL_ROOT_DIR=... passed on the cmake command line  (highest)
#   2. OPENSSL_ROOT_DIR environment variable (set in base image ENV)
#   3. /opt/openssl hardcoded fallback
if(NOT DEFINED OPENSSL_ROOT_DIR)
    if(DEFINED ENV{OPENSSL_ROOT_DIR})
        set(OPENSSL_ROOT_DIR "$ENV{OPENSSL_ROOT_DIR}")
    elseif(EXISTS "/opt/openssl/include/openssl/ssl.h")
        set(OPENSSL_ROOT_DIR "/opt/openssl")
    endif()
endif()

message(STATUS "OPENSSL_ROOT_DIR        : ${OPENSSL_ROOT_DIR}")

# Tell CMake to search lib64 in addition to lib.
# OpenSSL built from source on 64-bit Linux installs shared libraries to
# ${prefix}/lib64/ by default, but FindOpenSSL.cmake may search lib/ first.
list(PREPEND CMAKE_LIBRARY_PATH
    "${OPENSSL_ROOT_DIR}/lib64"
    "${OPENSSL_ROOT_DIR}/lib"
)
list(PREPEND CMAKE_INCLUDE_PATH
    "${OPENSSL_ROOT_DIR}/include"
)

# Prevent CMake from finding the system OpenSSL before our custom build.
# NO_DEFAULT_PATH is not used here because it would break on systems where
# /opt/openssl doesn't exist; instead we rely on HINTS having priority over
# PATHS in find_path/find_library.
set(OPENSSL_NO_CMAKE_PACKAGE_REGISTRY ON)

find_package(OpenSSL REQUIRED)

message(STATUS "OpenSSL version found   : ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include dir     : ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL SSL library     : ${OPENSSL_SSL_LIBRARY}")
message(STATUS "OpenSSL Crypto library  : ${OPENSSL_CRYPTO_LIBRARY}")

# Hard error if we resolved to an OpenSSL older than 3.2.0.
# SSL_get0_group_name() used in server.c was added in 3.2.0.
# If this check fails, set -DOPENSSL_ROOT_DIR=/opt/openssl explicitly.
if(OPENSSL_VERSION VERSION_LESS "3.2.0")
    message(FATAL_ERROR
        "OpenSSL ${OPENSSL_VERSION} found at '${OPENSSL_ROOT_DIR}', "
        "but >= 3.2.0 is required (SSL_get0_group_name was added in 3.2.0). "
        "The system libssl-dev provides OpenSSL 3.0.x which is insufficient. "
        "Pass -DOPENSSL_ROOT_DIR=/opt/openssl to cmake to use the custom build.")
endif()

# ── Helper: apply OpenSSL include/link settings to a target ──────────────────
function(apply_openssl_settings target)
    target_include_directories(${target} SYSTEM PRIVATE
        ${OPENSSL_INCLUDE_DIR}
    )
    target_link_libraries(${target} PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    # Embed runtime library search paths so the binary works inside the
    # container without relying solely on LD_LIBRARY_PATH.
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
