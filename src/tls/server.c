/*
 * server.c — TLS 1.3 Server for Post-Quantum Handshake Performance Evaluation
 *
 * Listens for incoming TLS 1.3 connections, completes the cryptographic
 * handshake, then immediately closes the connection. Designed to serve
 * repeated connections from the benchmark client.
 *
 * Build: see CMakeLists.txt
 * Requires: OpenSSL 3.x with OQS-Provider loaded
 *
 * Usage:
 *   tls-server [--port PORT] [--cert FILE] [--key FILE] [--kem GROUP] [--verbose]
 */

/* _GNU_SOURCE exposes all POSIX/GNU extensions (nanosleep, SO_REUSEPORT,
 * etc.) regardless of the -std= flag used by the compiler.  It must be
 * defined before any system header is included. */
#define _GNU_SOURCE

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── Constants ───────────────────────────────────────────────────────────── */
#define DEFAULT_PORT        4433
#define DEFAULT_CERT        "/certs/server.crt"
#define DEFAULT_KEY         "/certs/server.key"
#define LISTEN_BACKLOG      512

/* ── Globals ─────────────────────────────────────────────────────────────── */
static volatile int g_running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ── Usage ───────────────────────────────────────────────────────────────── */
static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  --port  PORT   TCP listen port          (default: %d)\n"
        "  --cert  FILE   PEM certificate chain    (default: %s)\n"
        "  --key   FILE   PEM private key          (default: %s)\n"
        "  --kem   GROUP  Preferred KEM group name (optional)\n"
        "  --verbose      Print per-handshake info\n"
        "  --help         Show this message\n",
        prog, DEFAULT_PORT, DEFAULT_CERT, DEFAULT_KEY);
}

/* ── Main ────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    int         port    = DEFAULT_PORT;
    const char *cert    = DEFAULT_CERT;
    const char *key     = DEFAULT_KEY;
    const char *kem     = NULL;   /* optional: restrict server-side groups */
    int         verbose = 0;

    /* ── Parse arguments ─────────────────────────────────────────────────── */
    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--port")    == 0 && i + 1 < argc) port    = atoi(argv[++i]);
        else if (strcmp(argv[i], "--cert")    == 0 && i + 1 < argc) cert    = argv[++i];
        else if (strcmp(argv[i], "--key")     == 0 && i + 1 < argc) key     = argv[++i];
        else if (strcmp(argv[i], "--kem")     == 0 && i + 1 < argc) kem     = argv[++i];
        else if (strcmp(argv[i], "--verbose") == 0) verbose = 1;
        else if (strcmp(argv[i], "--help")    == 0) { print_usage(argv[0]); return 0; }
        else { fprintf(stderr, "[error] Unknown argument: %s\n", argv[i]); return 1; }
    }

    fprintf(stderr, "[tls-server] port=%d  cert=%s  key=%s  kem=%s\n",
            port, cert, key, kem ? kem : "(default)");

    /* ── Signal handling ─────────────────────────────────────────────────── */
    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);
    signal(SIGPIPE, SIG_IGN);

    /* ── Load OpenSSL providers ──────────────────────────────────────────── */
    OSSL_PROVIDER *prov_oqs     = OSSL_PROVIDER_load(NULL, "oqsprovider");
    OSSL_PROVIDER *prov_default = OSSL_PROVIDER_load(NULL, "default");

    if (!prov_oqs) {
        fprintf(stderr, "[warn] OQS provider not loaded — PQC algorithms unavailable\n");
        ERR_clear_error();
    }
    if (!prov_default) {
        fprintf(stderr, "[error] Default OpenSSL provider failed to load\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* ── Create SSL context ──────────────────────────────────────────────── */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* TLS 1.3 only — no fallback to earlier versions */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* ── Load certificate chain ──────────────────────────────────────────── */
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0) {
        fprintf(stderr, "[error] Failed to load certificate: %s\n", cert);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    /* ── Load private key ────────────────────────────────────────────────── */
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "[error] Failed to load private key: %s\n", key);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "[error] Certificate and private key do not match\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    /* ── Optionally restrict supported KEM groups ────────────────────────── */
    if (kem != NULL) {
        if (SSL_CTX_set1_groups_list(ctx, kem) != 1) {
            fprintf(stderr, "[warn] Failed to set server KEM group '%s' — using default\n", kem);
            ERR_clear_error();
        } else {
            fprintf(stderr, "[tls-server] KEM group restricted to: %s\n", kem);
        }
    }

    /* ── Disable session resumption (force full handshake every time) ────── */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

    /* ── Create TCP listening socket ─────────────────────────────────────── */
    int srv_fd = socket(AF_INET6, SOCK_STREAM, 0);
    int use_v6 = (srv_fd >= 0);
    if (!use_v6) {
        srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    }
    if (srv_fd < 0) {
        perror("socket");
        SSL_CTX_free(ctx);
        return 1;
    }

    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    int bind_ret = -1;
    if (use_v6) {
        /* Listen on IPv6 wildcard (also accepts IPv4-mapped addresses) */
        struct sockaddr_in6 addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port   = htons((uint16_t)port);
        addr6.sin6_addr   = in6addr_any;
        bind_ret = bind(srv_fd, (struct sockaddr *)&addr6, sizeof(addr6));
    }

    if (bind_ret < 0) {
        /* Fall back to IPv4 */
        if (use_v6) {
            close(srv_fd);
            srv_fd = socket(AF_INET, SOCK_STREAM, 0);
            setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            setsockopt(srv_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        }
        struct sockaddr_in addr4;
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family      = AF_INET;
        addr4.sin_port        = htons((uint16_t)port);
        addr4.sin_addr.s_addr = INADDR_ANY;
        bind_ret = bind(srv_fd, (struct sockaddr *)&addr4, sizeof(addr4));
    }

    if (bind_ret < 0) {
        perror("bind");
        close(srv_fd);
        SSL_CTX_free(ctx);
        return 1;
    }

    if (listen(srv_fd, LISTEN_BACKLOG) < 0) {
        perror("listen");
        close(srv_fd);
        SSL_CTX_free(ctx);
        return 1;
    }

    fprintf(stdout, "[tls-server] ready — listening on port %d\n", port);
    fflush(stdout);

    /* ── Accept loop ─────────────────────────────────────────────────────── */
    long handshake_count = 0;
    long handshake_errors = 0;

    while (g_running) {
        struct sockaddr_storage cli_addr;
        socklen_t cli_len = sizeof(cli_addr);

        int cli_fd = accept(srv_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (cli_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            if (!g_running) break;
            perror("accept");
            continue;
        }

        /* Disable Nagle algorithm for lower latency */
        int nodelay = 1;
        setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        /* ── TLS handshake ─────────────────────────────────────────────── */
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, cli_fd);

        int ret = SSL_accept(ssl);
        if (ret <= 0) {
            int ssl_err = SSL_get_error(ssl, ret);
            /* SSL_ERROR_ZERO_RETURN is a clean close — not an error */
            if (ssl_err != SSL_ERROR_ZERO_RETURN && ssl_err != SSL_ERROR_SYSCALL) {
                if (verbose) {
                    fprintf(stderr, "[warn] SSL_accept error=%d on connection %ld\n",
                            ssl_err, handshake_count + handshake_errors + 1);
                }
                ERR_clear_error();
            }
            handshake_errors++;
        } else {
            handshake_count++;
            if (verbose) {
                const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
                /* SSL_get0_group_name() was added in OpenSSL 3.2.0.
                 * Guard it so the binary still compiles if, for any
                 * reason, an older OpenSSL header is resolved by CMake
                 * (e.g. the system libssl-dev on Ubuntu 24.04 is 3.0.x). */
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
                const char *grp = SSL_get0_group_name(ssl);
#else
                const char *grp = NULL;  /* not available before 3.2 */
#endif
                fprintf(stderr, "[handshake #%ld] cipher=%s  group=%s\n",
                        handshake_count,
                        cipher ? SSL_CIPHER_get_name(cipher) : "?",
                        grp    ? grp                          : "(N/A)");
            }
        }

        /* ── Graceful shutdown ─────────────────────────────────────────── */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(cli_fd);
    }

    /* ── Cleanup ─────────────────────────────────────────────────────────── */
    fprintf(stderr, "[tls-server] shutting down — "
            "handshakes: %ld ok / %ld errors\n",
            handshake_count, handshake_errors);

    close(srv_fd);
    SSL_CTX_free(ctx);

    if (prov_oqs)     OSSL_PROVIDER_unload(prov_oqs);
    if (prov_default) OSSL_PROVIDER_unload(prov_default);

    return 0;
}