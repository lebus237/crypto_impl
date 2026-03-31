# =============================================================================
# CMakeLists.txt — QUIC server & client (MsQuic + OQS-enabled OpenSSL)
# =============================================================================

cmake_minimum_required(VERSION 3.20)
project(pqc_quic_eval C)

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

# ── Find OQS-enabled OpenSSL ──────────────────────────────────────────────────
if(NOT DEFINED OPENSSL_ROOT_DIR AND EXISTS "/opt/openssl")
    set(OPENSSL_ROOT_DIR "/opt/openssl")
endif()

find_package(OpenSSL REQUIRED)

message(STATUS "OpenSSL version : ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include : ${OPENSSL_INCLUDE_DIR}")

if(OPENSSL_VERSION VERSION_LESS "3.0.0")
    message(WARNING
        "OpenSSL ${OPENSSL_VERSION} found, but >= 3.0.0 is required "
        "for OQS-Provider support.")
endif()

# ── Find MsQuic ───────────────────────────────────────────────────────────────
# Search path can be overridden at cmake time:
#   cmake -DMSQUIC_PATH=/opt/msquic ...
if(NOT DEFINED MSQUIC_PATH)
    set(MSQUIC_PATH "/opt/msquic")
endif()

# Header
find_path(MSQUIC_INCLUDE_DIR
    NAMES msquic.h
    HINTS
        "${MSQUIC_PATH}/include"
        "/usr/local/include"
        "/usr/include"
    REQUIRED
)

# Shared library
find_library(MSQUIC_LIBRARY
    NAMES msquic
    HINTS
        "${MSQUIC_PATH}/lib"
        "${MSQUIC_PATH}/lib64"
        "/usr/local/lib"
        "/usr/lib"
        "/usr/lib/x86_64-linux-gnu"
    REQUIRED
)

message(STATUS "MsQuic include  : ${MSQUIC_INCLUDE_DIR}")
message(STATUS "MsQuic library  : ${MSQUIC_LIBRARY}")

# Create an imported target for cleaner linking
add_library(msquic SHARED IMPORTED)
set_target_properties(msquic PROPERTIES
    IMPORTED_LOCATION             "${MSQUIC_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${MSQUIC_INCLUDE_DIR}"
)

# ── Helper: common link/include setup ────────────────────────────────────────
function(apply_quic_settings target)
    target_include_directories(${target} PRIVATE
        ${MSQUIC_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
    )
    target_link_libraries(${target} PRIVATE
        msquic
        OpenSSL::SSL
        OpenSSL::Crypto
        pthread
    )
    # Runtime linker paths for both MsQuic and OQS-OpenSSL
    target_link_options(${target} PRIVATE
        "-Wl,-rpath,${MSQUIC_PATH}/lib"
        "-Wl,-rpath,${MSQUIC_PATH}/lib64"
        "-Wl,-rpath,${OPENSSL_ROOT_DIR}/lib64"
        "-Wl,-rpath,${OPENSSL_ROOT_DIR}/lib"
    )
endfunction()

# ── quic-server ───────────────────────────────────────────────────────────────
add_executable(quic-server server.c)
apply_quic_settings(quic-server)

# ── quic-client ───────────────────────────────────────────────────────────────
add_executable(quic-client client.c)
apply_quic_settings(quic-client)

# ── Installation ─────────────────────────────────────────────────────────────
install(TARGETS quic-server quic-client
    RUNTIME DESTINATION bin
)
