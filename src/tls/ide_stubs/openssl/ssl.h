/*
 * openssl/ssl.h — Minimal IDE stub for OpenSSL 3.x TLS API.
 *
 * PURPOSE
 * -------
 * This file exists ONLY to give the clangd language server on a Windows
 * development host enough type information to parse src/tls/server.c and
 * src/tls/client.c without cascading "unknown type / undeclared identifier"
 * errors.
 *
 * It is NOT used during compilation.  The real OpenSSL 3.3.2 headers live at
 *   /opt/openssl/include/openssl/ssl.h
 * inside the Docker build container (Ubuntu 24.04).
 *
 * MAINTENANCE
 * -----------
 * Keep this stub in sync with the OpenSSL version declared in
 *   docker/base/Dockerfile  (OPENSSL_VERSION=3.3.2)
 *
 * When upgrading OpenSSL, check whether any new types or functions used in
 * src/tls/server.c or src/tls/client.c need to be added here.
 *
 * DO NOT include this file from production code.
 */

#pragma once

#ifndef OPENSSL_SSL_H_STUB
#define OPENSSL_SSL_H_STUB

#ifdef __cplusplus
extern "C" {
#endif

/* ── Pull in POSIX type stubs for Windows IDE support ──────────────────────────
 * When clangd on Windows resolves #include <openssl/ssl.h> to this stub,
 * it also needs struct timespec, struct addrinfo, NULL, AF_UNSPEC, fprintf(),
 * nanosleep(), etc.  The real <openssl/ssl.h> on Linux gets these transitively
 * from <sys/types.h>, <stdio.h>, etc.  On Windows those Linux headers are
 * absent, so we pull them in from our own posix_types.h stub instead.
 * The include guards inside posix_types.h prevent any redefinition when the
 * real Linux headers have already been found first.                            */
#include "../posix_types.h"

/* ── Guard against double-inclusion if real headers are somehow found ──────── */
#ifndef OPENSSL_VERSION_NUMBER
/* OpenSSL 3.3.2  →  0x30302000L */
#  define OPENSSL_VERSION_NUMBER  0x30302000L
#endif

/* ── Primitive types ─────────────────────────────────────────────────────── */

typedef unsigned long  SSL_OP_TYPE;   /* option bitmask (uint64_t in real API) */
typedef unsigned int   SSL_MODE_TYPE;
typedef int            SSL_VERIFY_MODE;

/* Opaque handle types — all pointer-to-struct in the real API */
typedef struct ssl_ctx_st   SSL_CTX;
typedef struct ssl_st       SSL;
typedef struct ssl_cipher_st SSL_CIPHER;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ossl_provider_st OSSL_PROVIDER;
typedef struct ossl_lib_ctx_st  OSSL_LIB_CTX;

/* ── Version constants ───────────────────────────────────────────────────── */
#define TLS1_VERSION    0x0301
#define TLS1_1_VERSION  0x0302
#define TLS1_2_VERSION  0x0303
#define TLS1_3_VERSION  0x0304

/* ── SSL_CTX_set_options / SSL_CTX_set_mode bits ────────────────────────── */
#define SSL_OP_NO_SSLv2                              0x00000000UL
#define SSL_OP_NO_SSLv3                              0x02000000UL
#define SSL_OP_NO_TLSv1                              0x04000000UL
#define SSL_OP_NO_TLSv1_1                            0x10000000UL
#define SSL_OP_NO_TLSv1_2                            0x08000000UL
#define SSL_OP_NO_TLSv1_3                            0x20000000UL
#define SSL_OP_NO_TICKET                             0x00004000UL
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION 0x00010000UL
#define SSL_OP_ALL                                   0x80000FFFUL

/* ── Session cache mode flags ────────────────────────────────────────────── */
#define SSL_SESS_CACHE_OFF     0x0000
#define SSL_SESS_CACHE_CLIENT  0x0001
#define SSL_SESS_CACHE_SERVER  0x0002
#define SSL_SESS_CACHE_BOTH    (SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER)

/* ── Verify flags ────────────────────────────────────────────────────────── */
#define SSL_VERIFY_NONE                 0x00
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define SSL_VERIFY_CLIENT_ONCE          0x04
#define SSL_VERIFY_POST_HANDSHAKE       0x08

/* ── SSL_connect / SSL_accept return / error codes ───────────────────────── */
#define SSL_ERROR_NONE             0
#define SSL_ERROR_SSL              1
#define SSL_ERROR_WANT_READ        2
#define SSL_ERROR_WANT_WRITE       3
#define SSL_ERROR_WANT_X509_LOOKUP 4
#define SSL_ERROR_SYSCALL          5
#define SSL_ERROR_ZERO_RETURN      6
#define SSL_ERROR_WANT_CONNECT     7
#define SSL_ERROR_WANT_ACCEPT      8

/* ── TLSEXT hostname type ────────────────────────────────────────────────── */
#define TLSEXT_NAMETYPE_host_name  0

/* SSL_set_tlsext_host_name is a macro in the real API */
#define SSL_set_tlsext_host_name(ssl, name) \
    SSL_ctrl((ssl), 55 /* SSL_CTRL_SET_TLSEXT_HOSTNAME */, \
             0 /* TLSEXT_NAMETYPE_host_name */, (void *)(name))

/* ── SSL_CTX_set_options is a macro in the real API ─────────────────────── */
#define SSL_CTX_set_options(ctx, op) \
    SSL_CTX_ctrl((ctx), 32 /* SSL_CTRL_OPTIONS */, (op), NULL)

/* ── SSL_CTX_set_session_cache_mode is a macro ───────────────────────────── */
#define SSL_CTX_set_session_cache_mode(ctx, mode) \
    SSL_CTX_ctrl((ctx), 44 /* SSL_CTRL_SET_SESS_CACHE_MODE */, (mode), NULL)

/* ── SSL_CTX_set_min/max_proto_version macros ────────────────────────────── */
#define SSL_CTX_set_min_proto_version(ctx, ver) \
    SSL_CTX_ctrl((ctx), 123 /* SSL_CTRL_SET_MIN_PROTO_VERSION */, (ver), NULL)
#define SSL_CTX_set_max_proto_version(ctx, ver) \
    SSL_CTX_ctrl((ctx), 124 /* SSL_CTRL_SET_MAX_PROTO_VERSION */, (ver), NULL)

/* ── SSL method constructors ─────────────────────────────────────────────── */
const SSL_METHOD *TLS_client_method(void);
const SSL_METHOD *TLS_server_method(void);
const SSL_METHOD *TLS_method(void);

/* ── SSL_CTX lifecycle ───────────────────────────────────────────────────── */
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
void     SSL_CTX_free(SSL_CTX *ctx);

/* ── SSL_CTX configuration ───────────────────────────────────────────────── */
long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);

int SSL_CTX_set1_groups_list(SSL_CTX *ctx, const char *list);
int SSL_CTX_set1_sigalgs_list(SSL_CTX *ctx, const char *list);

int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_check_private_key(const SSL_CTX *ctx);

int SSL_CTX_load_verify_locations(SSL_CTX *ctx,
                                   const char *CAfile,
                                   const char *CApath);
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                         int (*verify_callback)(int, void *));

/* ── File type constants ─────────────────────────────────────────────────── */
#define SSL_FILETYPE_PEM  1
#define SSL_FILETYPE_ASN1 2

/* ── SSL object lifecycle ────────────────────────────────────────────────── */
SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);

int  SSL_set_fd(SSL *ssl, int fd);
long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);

/* ── Handshake functions ─────────────────────────────────────────────────── */
int SSL_connect(SSL *ssl);
int SSL_accept(SSL *ssl);
int SSL_shutdown(SSL *ssl);
int SSL_read(SSL *ssl, void *buf, int num);
int SSL_write(SSL *ssl, const void *buf, int num);

/* ── Error retrieval ─────────────────────────────────────────────────────── */
int SSL_get_error(const SSL *ssl, int ret);

/* ── Cipher / group information ──────────────────────────────────────────── */
const SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl);
const char       *SSL_CIPHER_get_name(const SSL_CIPHER *cipher);

/*
 * SSL_get0_group_name — added in OpenSSL 3.2.0.
 * Returns the name of the key-share group negotiated during the TLS 1.3
 * handshake (e.g. "mlkem768", "x25519_mlkem768").
 * Returns NULL if no group has been negotiated yet.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
const char *SSL_get0_group_name(SSL *ssl);
#endif

/* ── Library initialisation (OpenSSL 1.1+ auto-init, these are no-ops) ──── */
int SSL_library_init(void);
void SSL_load_error_strings(void);
void OpenSSL_add_all_algorithms(void);

/* ── Error printing ──────────────────────────────────────────────────────── */
void ERR_print_errors_fp(void *fp);  /* fp is FILE* in real API */
void ERR_clear_error(void);
unsigned long ERR_get_error(void);

/* ── Provider API (OpenSSL 3.x) ──────────────────────────────────────────── */
OSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *libctx, const char *name);
int            OSSL_PROVIDER_unload(OSSL_PROVIDER *prov);
int            OSSL_PROVIDER_available(OSSL_LIB_CTX *libctx, const char *name);

/* ── err.h inline stub (pulled in via openssl/err.h which we also stub) ──── */
#ifndef OPENSSL_ERR_H_STUB
#define OPENSSL_ERR_H_STUB
/* Already declared above via ERR_* prototypes */
#endif

/* ── provider.h inline stub ─────────────────────────────────────────────── */
#ifndef OPENSSL_PROVIDER_H_STUB
#define OPENSSL_PROVIDER_H_STUB
/* Already declared above via OSSL_PROVIDER_* prototypes */
#endif

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_SSL_H_STUB */