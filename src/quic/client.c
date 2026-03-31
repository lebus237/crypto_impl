/*
 * client.c — QUIC Client for Post-Quantum Handshake Performance Evaluation
 *
 * Performs N consecutive QUIC handshakes against a server, measuring the
 * wall-clock latency of each handshake using CLOCK_MONOTONIC.
 *
 * MsQuic is event-driven (callback-based), which differs from OpenSSL's
 * blocking SSL_connect(). To produce comparable measurements we:
 *
 *   1. Record t_start immediately before MsQuic->ConnectionStart().
 *   2. Record t_end at the very first instruction of the
 *      QUIC_CONNECTION_EVENT_CONNECTED callback.
 *   3. Use a pthread condition variable so the main thread blocks until
 *      the callback fires, mirroring the blocking semantics of the TLS
 *      client.
 *
 * KEM group selection is handled externally via the OPENSSL_CONF environment
 * variable set by the Docker entrypoint script. MsQuic's OpenSSL backend
 * reads the Groups directive from that config file during TLS initialisation.
 *
 * Build: see CMakeLists.txt
 * Requires: MsQuic 2.4.x linked against OQS-enabled OpenSSL 3.x
 *
 * Usage:
 *   quic-client [--host HOST] [--port PORT] [--runs N] [--warmup N]
 *               [--output FILE] [--ca-cert FILE] [--verbose]
 */

#define _POSIX_C_SOURCE 200809L

#include <msquic.h>

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* ── ALPN — must match the server ────────────────────────────────────────── */
static const QUIC_BUFFER ALPN = {
    .Length = sizeof("pqc-eval") - 1,
    .Buffer = (uint8_t *)"pqc-eval"
};

/* ── Defaults ─────────────────────────────────────────────────────────────── */
#define DEFAULT_HOST     "quic-server"
#define DEFAULT_PORT     4433
#define DEFAULT_RUNS     1000
#define DEFAULT_WARMUP   50
#define DEFAULT_OUTPUT   "/results/quic_timing.log"
#define DEFAULT_CA_CERT  "/certs/ca.crt"

/* ── Connection state machine ─────────────────────────────────────────────── */
typedef enum {
    CONN_STATE_PENDING   =  0,   /* Waiting for outcome                */
    CONN_STATE_CONNECTED =  1,   /* Handshake succeeded                */
    CONN_STATE_FAILED    = -1,   /* Handshake or transport error       */
    CONN_STATE_CLOSED    =  2,   /* SHUTDOWN_COMPLETE fired; handle safe to discard */
} ConnState;

/* ── Per-connection context ───────────────────────────────────────────────── */
/*
 * This struct is stack-allocated in the measurement loop and its address
 * is passed as the MsQuic "context" pointer for the connection.
 * All fields are protected by mutex/cond except t_start which is written
 * by the main thread before the callback can possibly run.
 */
typedef struct {
    /* Timing — written by main thread (t_start) and callback (t_end) */
    struct timespec t_start;
    struct timespec t_end;

    /* State machine — written by callback, read by main thread */
    volatile ConnState state;

    /* Synchronisation */
    pthread_mutex_t mutex;
    pthread_cond_t  cond;

    /* Set when ConnectionClose has been called inside the callback */
    volatile int    handle_closed;
} ConnCtx;

/* ── Global MsQuic API table ──────────────────────────────────────────────── */
static const QUIC_API_TABLE *MsQuic = NULL;

/* ── High-resolution monotonic timestamp ─────────────────────────────────── */
static inline long timespec_to_us(const struct timespec *ts)
{
    return (long)ts->tv_sec * 1000000L + (long)(ts->tv_nsec / 1000L);
}

static inline long latency_us(const struct timespec *start,
                               const struct timespec *end)
{
    return timespec_to_us(end) - timespec_to_us(start);
}

/* ── Signal helper: wake the main thread ─────────────────────────────────── */
static void ctx_signal(ConnCtx *ctx, ConnState new_state)
{
    pthread_mutex_lock(&ctx->mutex);
    ctx->state = new_state;
    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->mutex);
}

/* ── Timed wait helper: wait until state leaves CONN_STATE_PENDING ───────── */
static ConnState ctx_wait_for_outcome(ConnCtx *ctx, int timeout_sec)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_sec;

    pthread_mutex_lock(&ctx->mutex);
    while (ctx->state == CONN_STATE_PENDING) {
        int rc = pthread_cond_timedwait(&ctx->cond, &ctx->mutex, &deadline);
        if (rc == ETIMEDOUT) {
            ctx->state = CONN_STATE_FAILED;
            break;
        }
    }
    ConnState result = ctx->state;
    pthread_mutex_unlock(&ctx->mutex);
    return result;
}

/* ── Wait until the connection handle has been closed ────────────────────── */
static void ctx_wait_for_close(ConnCtx *ctx, int timeout_sec)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_sec;

    pthread_mutex_lock(&ctx->mutex);
    while (ctx->state != CONN_STATE_CLOSED) {
        int rc = pthread_cond_timedwait(&ctx->cond, &ctx->mutex, &deadline);
        if (rc == ETIMEDOUT) break;
    }
    pthread_mutex_unlock(&ctx->mutex);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Connection callback
 *
 * Called by MsQuic on a worker thread for every event on the connection.
 * The main thread blocks on ctx_wait_for_outcome() and is woken here.
 * ═══════════════════════════════════════════════════════════════════════════ */
static QUIC_STATUS QUIC_API
ClientConnectionCallback(HQUIC Connection,
                         void  *Context,
                         QUIC_CONNECTION_EVENT *Event)
{
    ConnCtx *ctx = (ConnCtx *)Context;

    switch (Event->Type) {

    /*
     * CONNECTED — the TLS 1.3 handshake embedded in QUIC has completed.
     *
     * We capture t_end HERE, as the very first action, to measure the
     * handshake duration as precisely as possible from the client side.
     * Any processing after this point does not affect the timing result.
     */
    case QUIC_CONNECTION_EVENT_CONNECTED:
        clock_gettime(CLOCK_MONOTONIC, &ctx->t_end);
        ctx_signal(ctx, CONN_STATE_CONNECTED);
        break;

    /*
     * SHUTDOWN_INITIATED_BY_TRANSPORT — the connection was closed due to a
     * transport error (e.g. handshake timeout, packet loss exhaustion).
     */
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        /* Only signal failure if we haven't already marked success */
        if (ctx->state == CONN_STATE_PENDING) {
            ctx_signal(ctx, CONN_STATE_FAILED);
        }
        break;

    /*
     * SHUTDOWN_INITIATED_BY_PEER — server initiated graceful close.
     * Normal after each benchmark handshake.
     */
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        break;

    /*
     * SHUTDOWN_COMPLETE — all shutdown processing is done.
     * This is the ONLY safe place to call ConnectionClose().
     * After this callback returns, the Connection handle is invalid.
     */
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->ConnectionClose(Connection);
        }
        ctx->handle_closed = 1;
        ctx_signal(ctx, CONN_STATE_CLOSED);
        break;

    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

/* ── Usage ───────────────────────────────────────────────────────────────── */
static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  --host     HOST   Server hostname              (default: %s)\n"
        "  --port     PORT   Server UDP port              (default: %d)\n"
        "  --runs     N      Measured handshakes          (default: %d)\n"
        "  --warmup   N      Discarded warm-up runs       (default: %d)\n"
        "  --output   FILE   CSV output path              (default: %s)\n"
        "  --ca-cert  FILE   CA cert (informational only) (default: %s)\n"
        "  --verbose         Print latency for each run\n"
        "  --help            Show this message\n"
        "\n"
        "  KEM group is selected via the OPENSSL_CONF environment variable\n"
        "  (set automatically by the Docker entrypoint script).\n",
        prog,
        DEFAULT_HOST, DEFAULT_PORT,
        DEFAULT_RUNS, DEFAULT_WARMUP,
        DEFAULT_OUTPUT, DEFAULT_CA_CERT);
}

/* ── Main ────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    const char *host        = DEFAULT_HOST;
    int         port        = DEFAULT_PORT;
    int         n_runs      = DEFAULT_RUNS;
    int         warmup      = DEFAULT_WARMUP;
    const char *output_file = DEFAULT_OUTPUT;
    const char *ca_cert     = DEFAULT_CA_CERT;
    int         verbose     = 0;

    /* ── Parse arguments ─────────────────────────────────────────────────── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) { print_usage(argv[0]); return 0; }
#define STRARG(f, v) else if (strcmp(argv[i], f) == 0 && i+1 < argc) v = argv[++i]
#define INTARG(f, v) else if (strcmp(argv[i], f) == 0 && i+1 < argc) v = atoi(argv[++i])
        STRARG("--host",    host);
        INTARG("--port",    port);
        INTARG("--runs",    n_runs);
        INTARG("--warmup",  warmup);
        STRARG("--output",  output_file);
        STRARG("--ca-cert", ca_cert);
        else if (strcmp(argv[i], "--verbose") == 0) verbose = 1;
        else { fprintf(stderr, "[error] Unknown argument: %s\n", argv[i]); return 1; }
#undef STRARG
#undef INTARG
    }

    fprintf(stderr,
            "[quic-client] host=%s  port=%d  runs=%d  warmup=%d\n",
            host, port, n_runs, warmup);

    /* Log the KEM group configuration source */
    const char *ossl_conf = getenv("OPENSSL_CONF");
    if (ossl_conf) {
        fprintf(stderr, "[quic-client] OPENSSL_CONF=%s\n", ossl_conf);
    } else {
        fprintf(stderr,
                "[quic-client] OPENSSL_CONF not set — "
                "using OpenSSL default groups\n");
    }

    /* ── Initialise MsQuic ───────────────────────────────────────────────── */
    QUIC_STATUS Status = MsQuicOpen2(&MsQuic);
    if (QUIC_FAILED(Status)) {
        fprintf(stderr, "[error] MsQuicOpen2 failed: 0x%x\n", Status);
        return 1;
    }

    /* ── Registration ────────────────────────────────────────────────────── */
    HQUIC Registration = NULL;
    const QUIC_REGISTRATION_CONFIG RegConfig = {
        .AppName          = "pqc-quic-client",
        .ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY
    };

    Status = MsQuic->RegistrationOpen(&RegConfig, &Registration);
    if (QUIC_FAILED(Status)) {
        fprintf(stderr, "[error] RegistrationOpen failed: 0x%x\n", Status);
        MsQuicClose(MsQuic);
        return 1;
    }

    /* ── Configuration (TLS settings) ────────────────────────────────────── */
    HQUIC Configuration = NULL;
    QUIC_SETTINGS Settings;
    memset(&Settings, 0, sizeof(Settings));

    /* Handshake idle timeout: 10 seconds per run */
    Settings.HandshakeIdleTimeoutMs       = 10000;
    Settings.IsSet.HandshakeIdleTimeoutMs = TRUE;

    /* Overall idle timeout */
    Settings.IdleTimeoutMs                = 15000;
    Settings.IsSet.IdleTimeoutMs          = TRUE;

    Status = MsQuic->ConfigurationOpen(
        Registration,
        &ALPN, 1,
        &Settings, sizeof(Settings),
        NULL,
        &Configuration);

    if (QUIC_FAILED(Status)) {
        fprintf(stderr, "[error] ConfigurationOpen failed: 0x%x\n", Status);
        goto cleanup_registration;
    }

    /* ── Load client credentials ──────────────────────────────────────────
     *
     * The client does not present a certificate (mutual auth not required
     * for this benchmark). Certificate validation is disabled because we
     * use self-signed PQC certificates that are not in the system trust
     * store. The certificate is still transmitted by the server and its
     * size therefore contributes to bandwidth measurements.
     *
     * To enable proper validation, add the PQC CA to the system trust
     * store and remove QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION.
     */
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type  = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT
                     | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig);
    if (QUIC_FAILED(Status)) {
        fprintf(stderr,
                "[error] ConfigurationLoadCredential failed: 0x%x\n", Status);
        goto cleanup_configuration;
    }

    /* ── Open output CSV file ────────────────────────────────────────────── */
    FILE *out = fopen(output_file, "w");
    if (!out) {
        fprintf(stderr, "[error] Cannot open output file '%s': %s\n",
                output_file, strerror(errno));
        goto cleanup_configuration;
    }
    fprintf(out, "run,latency_us,timestamp_us\n");

    /* ── Measurement loop ────────────────────────────────────────────────── */
    int total_runs    = n_runs + warmup;
    int success_count = 0;
    int fail_count    = 0;

    for (int run = 0; run < total_runs; run++) {

        /* ── Initialise per-connection context ───────────────────────────── */
        ConnCtx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.state        = CONN_STATE_PENDING;
        ctx.handle_closed = 0;
        pthread_mutex_init(&ctx.mutex, NULL);
        pthread_cond_init(&ctx.cond, NULL);

        /* ── Open connection handle ───────────────────────────────────────── */
        HQUIC Connection = NULL;
        Status = MsQuic->ConnectionOpen(
            Registration,
            ClientConnectionCallback,
            &ctx,            /* per-connection context */
            &Connection);

        if (QUIC_FAILED(Status)) {
            fprintf(stderr,
                    "[error] ConnectionOpen failed on run %d: 0x%x\n",
                    run, Status);
            fail_count++;
            pthread_mutex_destroy(&ctx.mutex);
            pthread_cond_destroy(&ctx.cond);
            continue;
        }

        /* ── Start connection — record t_start immediately before ─────────
         *
         * This is the moment the client begins the QUIC handshake:
         *   Initial packet (ClientHello in CRYPTO frame) is sent here.
         * t_end is set inside QUIC_CONNECTION_EVENT_CONNECTED.
         *
         * The measured interval therefore covers:
         *   Client Initial  →
         *   ← Server Initial + Handshake (ServerHello + EncExtensions
         *                                  + Certificate + CertVerify
         *                                  + Finished)
         *   Client Handshake (Finished) →
         *   ← HANDSHAKE_DONE
         */
        clock_gettime(CLOCK_MONOTONIC, &ctx.t_start);

        Status = MsQuic->ConnectionStart(
            Connection,
            Configuration,
            QUIC_ADDRESS_FAMILY_UNSPEC,
            host,
            (uint16_t)port);

        if (QUIC_FAILED(Status)) {
            fprintf(stderr,
                    "[error] ConnectionStart failed on run %d: 0x%x\n",
                    run, Status);
            /*
             * ConnectionStart failed synchronously — the callback will NOT
             * fire. We must call ConnectionClose directly here.
             */
            MsQuic->ConnectionClose(Connection);
            fail_count++;
            pthread_mutex_destroy(&ctx.mutex);
            pthread_cond_destroy(&ctx.cond);
            continue;
        }

        /* ── Wait for handshake outcome (10 second timeout) ─────────────── */
        ConnState outcome = ctx_wait_for_outcome(&ctx, 10);

        if (outcome == CONN_STATE_CONNECTED) {
            if (run >= warmup) {
                long us = latency_us(&ctx.t_start, &ctx.t_end);
                fprintf(out, "%d,%ld,%ld\n",
                        run - warmup, us, timespec_to_us(&ctx.t_start));
                if (verbose) {
                    fprintf(stderr, "run=%4d  latency=%7ld us\n",
                            run - warmup, us);
                }
                success_count++;
            }

            /*
             * Initiate graceful shutdown. The SHUTDOWN_COMPLETE callback
             * will call ConnectionClose and signal CONN_STATE_CLOSED.
             */
            MsQuic->ConnectionShutdown(
                Connection,
                QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                0 /* app error code */);

        } else {
            /* Handshake failed or timed out */
            if (run >= warmup) {
                fprintf(stderr,
                        "[warn] Handshake failed/timed-out on run %d\n", run);
                fail_count++;
            } else {
                fprintf(stderr,
                        "[warn] Warm-up run %d failed (ignored)\n", run);
            }

            MsQuic->ConnectionShutdown(
                Connection,
                QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                0);
        }

        /* ── Wait for SHUTDOWN_COMPLETE before next iteration ────────────── */
        ctx_wait_for_close(&ctx, 10);

        pthread_mutex_destroy(&ctx.mutex);
        pthread_cond_destroy(&ctx.cond);

        /*
         * Brief inter-run pause. Even 1 ms is negligible relative to QUIC
         * handshake times but avoids hammering the server immediately.
         */
        usleep(1000);
    }

    /* ── Finalize ────────────────────────────────────────────────────────── */
    fclose(out);

    fprintf(stderr,
            "[quic-client] done — success=%d  fail=%d  total_measured=%d\n",
            success_count, fail_count, n_runs);

cleanup_configuration:
    MsQuic->ConfigurationClose(Configuration);

cleanup_registration:
    MsQuic->RegistrationClose(Registration);
    MsQuicClose(MsQuic);

    return (fail_count * 10 > n_runs) ? 1 : 0;
}