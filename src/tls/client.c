/*
 * client.c — TLS 1.3 Client for Post-Quantum Handshake Performance Evaluation
 *
 * Performs N consecutive TLS 1.3 handshakes against a server, measuring the
 * wall-clock latency of each handshake using CLOCK_MONOTONIC. Results are
 * written as CSV. A configurable number of warm-up runs are discarded before
 * measurement begins.
 *
 * Build: see CMakeLists.txt
 * Requires: OpenSSL 3.x with OQS-Provider loaded
 *
 * Usage:
 *   tls-client [--host HOST] [--port PORT] [--kem GROUP] [--sig ALG]
 *              [--runs N] [--warmup N] [--output FILE] [--ca-cert FILE]
 *              [--verbose]
 */

#define _POSIX_C_SOURCE 200809L

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ── Defaults ────────────────────────────────────────────────────────────── */
#define DEFAULT_HOST        "tls-server"
#define DEFAULT_PORT        4433
#define DEFAULT_KEM         "mlkem768"
#define DEFAULT_SIG         "mldsa65"
#define DEFAULT_RUNS        1000
#define DEFAULT_WARMUP      50
#define DEFAULT_OUTPUT      "/results/tls_timing.log"
#define DEFAULT_CA_CERT     "/certs/ca.crt"

/* ── Configuration ───────────────────────────────────────────────────────── */
typedef struct {
    const char *host;
    int         port;
    const char *kem_group;   /* KEM group for key exchange, e.g. "mlkem768"    */
    const char *sig_alg;     /* Signature alg for cert verification            */
    int         n_runs;      /* Number of measured handshakes                  */
    int         warmup;      /* Discarded warm-up handshakes                   */
    const char *output_file; /* CSV output path                                */
    const char *ca_cert;     /* CA certificate for server verification         */
    int         verbose;     /* Print latency for every run                    */
} ClientConfig;

/* ── High-resolution monotonic timestamp (microseconds) ─────────────────── */
static inline long get_time_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000000L + (long)(ts.tv_nsec / 1000L);
}

/* ── Establish a plain TCP connection ────────────────────────────────────── */
static int tcp_connect(const char *host, int port)
{
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        fprintf(stderr, "[error] getaddrinfo(%s:%s) failed\n", host, port_str);
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        /* Disable Nagle — we want minimum latency per round-trip */
        int flag = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;  /* success */

        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ── Usage ───────────────────────────────────────────────────────────────── */
static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  --host     HOST   Server hostname              (default: %s)\n"
        "  --port     PORT   Server port                  (default: %d)\n"
        "  --kem      GROUP  KEM group for key exchange   (default: %s)\n"
        "  --sig      ALG    Signature algorithm          (default: %s)\n"
        "  --runs     N      Measured handshakes          (default: %d)\n"
        "  --warmup   N      Discarded warm-up runs       (default: %d)\n"
        "  --output   FILE   CSV output path              (default: %s)\n"
        "  --ca-cert  FILE   CA certificate for verif.   (default: %s)\n"
        "  --verbose         Print latency for each run\n"
        "  --help            Show this message\n",
        prog,
        DEFAULT_HOST, DEFAULT_PORT,
        DEFAULT_KEM, DEFAULT_SIG,
        DEFAULT_RUNS, DEFAULT_WARMUP,
        DEFAULT_OUTPUT, DEFAULT_CA_CERT);
}

/* ── Argument parsing ────────────────────────────────────────────────────── */
static int parse_args(int argc, char *argv[], ClientConfig *cfg)
{
    cfg->host        = DEFAULT_HOST;
    cfg->port        = DEFAULT_PORT;
    cfg->kem_group   = DEFAULT_KEM;
    cfg->sig_alg     = DEFAULT_SIG;
    cfg->n_runs      = DEFAULT_RUNS;
    cfg->warmup      = DEFAULT_WARMUP;
    cfg->output_file = DEFAULT_OUTPUT;
    cfg->ca_cert     = DEFAULT_CA_CERT;
    cfg->verbose     = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return -1;
        }
#define STRARG(flag, field) \
        else if (strcmp(argv[i], flag) == 0 && i + 1 < argc) cfg->field = argv[++i]
#define INTARG(flag, field) \
        else if (strcmp(argv[i], flag) == 0 && i + 1 < argc) cfg->field = atoi(argv[++i])
        STRARG("--host",    host);
        INTARG("--port",    port);
        STRARG("--kem",     kem_group);
        STRARG("--sig",     sig_alg);
        INTARG("--runs",    n_runs);
        INTARG("--warmup",  warmup);
        STRARG("--output",  output_file);
        STRARG("--ca-cert", ca_cert);
        else if (strcmp(argv[i], "--verbose") == 0) cfg->verbose = 1;
        else {
            fprintf(stderr, "[error] Unknown argument: %s\n", argv[i]);
            return -1;
        }
#undef STRARG
#undef INTARG
    }
    return 0;
}

/* ── Main ────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    ClientConfig cfg;
    if (parse_args(argc, argv, &cfg) != 0)
        return 1;

    fprintf(stderr,
            "[tls-client] host=%s  port=%d  kem=%s  sig=%s  "
            "runs=%d  warmup=%d\n",
            cfg.host, cfg.port, cfg.kem_group, cfg.sig_alg,
            cfg.n_runs, cfg.warmup);

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
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* TLS 1.3 only */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* ── Set KEM group for key exchange ──────────────────────────────────── */
    /*
     * SSL_CTX_set1_groups_list() accepts a colon-separated list of group
     * names. OQS-Provider registers names like "mlkem768", "x25519_mlkem768",
     * "hqc192", etc. Only the first group in the list is sent in the
     * ClientHello key_share extension for TLS 1.3.
     */
    if (SSL_CTX_set1_groups_list(ctx, cfg.kem_group) != 1) {
        fprintf(stderr, "[error] Failed to set KEM group '%s'\n", cfg.kem_group);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    /* ── Set signature algorithms ─────────────────────────────────────────
     * This controls which signature algorithms the client will advertise in
     * its supported_signature_algorithms extension and accept in the server's
     * CertificateVerify message. Setting it to the PQC sig alg (e.g.
     * "mldsa65") means the client will only accept a PQC-signed certificate,
     * ensuring the full PQC handshake is exercised.
     */
    if (strcmp(cfg.sig_alg, "default") != 0) {
        if (SSL_CTX_set1_sigalgs_list(ctx, cfg.sig_alg) != 1) {
            fprintf(stderr,
                    "[warn] Failed to set sig alg '%s' — using OpenSSL default\n",
                    cfg.sig_alg);
            ERR_clear_error();
        }
    }

    /* ── Disable session resumption ───────────────────────────────────────
     * Every connection must perform a full handshake so we measure the true
     * cost of the cryptographic operations each time.
     */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx,
        SSL_OP_NO_TICKET |
        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    /* ── Load CA certificate for server verification ─────────────────────── */
    if (SSL_CTX_load_verify_locations(ctx, cfg.ca_cert, NULL) == 1) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (cfg.verbose)
            fprintf(stderr, "[info] CA cert loaded: %s\n", cfg.ca_cert);
    } else {
        fprintf(stderr,
                "[warn] Could not load CA cert '%s' — skipping verification\n",
                cfg.ca_cert);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        ERR_clear_error();
    }

    /* ── Open output CSV file ────────────────────────────────────────────── */
    FILE *out = fopen(cfg.output_file, "w");
    if (!out) {
        fprintf(stderr, "[error] Cannot open output file '%s': %s\n",
                cfg.output_file, strerror(errno));
        SSL_CTX_free(ctx);
        return 1;
    }
    /* Header row */
    fprintf(out, "run,latency_us,timestamp_us\n");

    /* ── Run measurement loop ────────────────────────────────────────────── */
    int total_runs    = cfg.n_runs + cfg.warmup;
    int success_count = 0;
    int fail_count    = 0;

    for (int run = 0; run < total_runs; run++) {
        /* Open a fresh TCP connection for every handshake */
        int fd = tcp_connect(cfg.host, cfg.port);
        if (fd < 0) {
            fprintf(stderr, "[error] TCP connect failed on run %d\n", run);
            fail_count++;
            usleep(10000); /* 10 ms back-off before retry */
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);

        /* SNI — required by many server implementations */
        SSL_set_tlsext_host_name(ssl, cfg.host);

        /* ── Measure the handshake ───────────────────────────────────────
         *
         * t_start is recorded immediately before SSL_connect().
         * t_end   is recorded immediately after SSL_connect() returns.
         *
         * SSL_connect() blocks until the full TLS 1.3 handshake is complete:
         *   ClientHello  →
         *   ← ServerHello + EncryptedExtensions + Certificate +
         *     CertificateVerify + Finished
         *   Finished     →
         *
         * This captures all cryptographic operations on both sides as
         * observed from the client's perspective (round-trip latency).
         */
        long t_start = get_time_us();
        int  ret     = SSL_connect(ssl);
        long t_end   = get_time_us();

        if (ret == 1) {
            /* Successful handshake */
            if (run >= cfg.warmup) {
                long latency = t_end - t_start;
                fprintf(out, "%d,%ld,%ld\n",
                        run - cfg.warmup, latency, t_start);
                if (cfg.verbose) {
                    fprintf(stderr, "run=%4d  latency=%7ld us\n",
                            run - cfg.warmup, latency);
                }
                success_count++;
            }
        } else {
            int ssl_err = SSL_get_error(ssl, ret);
            if (run >= cfg.warmup) {
                fprintf(stderr,
                        "[warn] SSL_connect failed on run %d, ssl_error=%d\n",
                        run, ssl_err);
                ERR_print_errors_fp(stderr);
                fail_count++;
            } else {
                /* Warm-up failure — log but don't count against quota */
                ERR_clear_error();
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);

        /*
         * Brief pause between connections to prevent port-reuse collisions
         * (TIME_WAIT on the server side). 500 µs is negligible relative to
         * handshake latency but avoids ECONNREFUSED on fast hardware.
         */
        usleep(500);
    }

    /* ── Finalize ────────────────────────────────────────────────────────── */
    fclose(out);
    SSL_CTX_free(ctx);

    if (prov_oqs)     OSSL_PROVIDER_unload(prov_oqs);
    if (prov_default) OSSL_PROVIDER_unload(prov_default);

    fprintf(stderr,
            "[tls-client] done — success=%d  fail=%d  total_measured=%d\n",
            success_count, fail_count, cfg.n_runs);

    /*
     * Return non-zero if more than 10 % of measured runs failed.
     * A small failure rate under lossy network conditions is acceptable.
     */
    return (fail_count * 10 > cfg.n_runs) ? 1 : 0;
}