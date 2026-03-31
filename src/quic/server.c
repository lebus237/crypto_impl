/*
 * server.c — QUIC Server for Post-Quantum Handshake Performance Evaluation
 *
 * Listens for incoming QUIC connections, completes the cryptographic
 * handshake (TLS 1.3 integrated into QUIC transport), then closes the
 * connection. Designed to serve repeated connections from the benchmark
 * client.
 *
 * KEM group selection is handled externally via the OPENSSL_CONF environment
 * variable, which points to a generated openssl.cnf containing:
 *   [ssl_default_sect]
 *   Groups = <kem_group>
 * This is set by the Docker entrypoint script before launching this binary,
 * ensuring MsQuic's internal OpenSSL context picks up the correct group.
 *
 * Build: see CMakeLists.txt
 * Requires: MsQuic 2.4.x linked against OQS-enabled OpenSSL 3.x
 *
 * Usage:
 *   quic-server [--port PORT] [--cert FILE] [--key FILE] [--verbose]
 */

#define _POSIX_C_SOURCE 200809L

#include <msquic.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── ALPN token ───────────────────────────────────────────────────────────── */
/* Application-Layer Protocol Negotiation identifier used by both sides.      */
static const QUIC_BUFFER ALPN = {
    .Length = sizeof("pqc-eval") - 1,
    .Buffer = (uint8_t *)"pqc-eval"
};

/* ── Defaults ─────────────────────────────────────────────────────────────── */
#define DEFAULT_PORT     4433
#define DEFAULT_CERT     "/certs/server.crt"
#define DEFAULT_KEY      "/certs/server.key"

/* ── Global MsQuic API table ──────────────────────────────────────────────── */
static const QUIC_API_TABLE *MsQuic = NULL;

/* ── Shutdown flag ────────────────────────────────────────────────────────── */
static volatile int g_running = 1;

static pthread_mutex_t g_shutdown_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_shutdown_cond  = PTHREAD_COND_INITIALIZER;

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
    pthread_mutex_lock(&g_shutdown_mutex);
    pthread_cond_signal(&g_shutdown_cond);
    pthread_mutex_unlock(&g_shutdown_mutex);
}

/* ── Server statistics (protected by mutex) ───────────────────────────────── */
static pthread_mutex_t g_stats_mutex    = PTHREAD_MUTEX_INITIALIZER;
static long            g_handshake_ok   = 0;
static long            g_handshake_err  = 0;

/* ── Per-connection context ───────────────────────────────────────────────── */
typedef struct {
    int verbose;
} ServerConnCtx;

/* ═══════════════════════════════════════════════════════════════════════════
 * Connection callback
 *
 * Called by MsQuic for every event on an accepted connection.
 * We only care about CONNECTED (handshake done) and SHUTDOWN_COMPLETE
 * (safe to call ConnectionClose).
 * ═══════════════════════════════════════════════════════════════════════════ */
static QUIC_STATUS QUIC_API
ServerConnectionCallback(HQUIC Connection,
                         void  *Context,
                         QUIC_CONNECTION_EVENT *Event)
{
    ServerConnCtx *ctx = (ServerConnCtx *)Context;

    switch (Event->Type) {

    case QUIC_CONNECTION_EVENT_CONNECTED:
        /*
         * The TLS 1.3 handshake (embedded in the QUIC CRYPTO frames) has
         * completed successfully. Send HANDSHAKE_DONE to the client.
         */
        MsQuic->ConnectionSendResumptionTicket(
            Connection,
            QUIC_SEND_RESUMPTION_FLAG_NONE,
            0, NULL);

        pthread_mutex_lock(&g_stats_mutex);
        g_handshake_ok++;
        long count = g_handshake_ok;
        pthread_mutex_unlock(&g_stats_mutex);

        if (ctx && ctx->verbose) {
            fprintf(stderr, "[quic-server] handshake #%ld completed\n", count);
        }

        /* Initiate graceful shutdown of this connection immediately.
         * For benchmarking purposes we do not transfer application data. */
        MsQuic->ConnectionShutdown(
            Connection,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            0 /* error code */);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status !=
            QUIC_STATUS_CONNECTION_IDLE) {
            pthread_mutex_lock(&g_stats_mutex);
            g_handshake_err++;
            pthread_mutex_unlock(&g_stats_mutex);
        }
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        /* Client shut down — normal for benchmark pattern */
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        /*
         * It is now safe to close the connection handle and free context.
         * This is the ONLY place ConnectionClose should be called.
         */
        MsQuic->ConnectionClose(Connection);
        if (ctx) free(ctx);
        break;

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        /* We don't exchange streams — shut down any the client opens */
        MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        break;

    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Listener callback
 *
 * Called by MsQuic for each new incoming QUIC connection attempt.
 * We accept it, attach our connection callback, and pass Configuration
 * so that the TLS handshake can proceed.
 * ═══════════════════════════════════════════════════════════════════════════ */
static QUIC_STATUS QUIC_API
ServerListenerCallback(HQUIC          Listener,
                       void          *Context,
                       QUIC_LISTENER_EVENT *Event)
{
    (void)Listener;
    HQUIC  Configuration = (HQUIC)Context;
    QUIC_STATUS Status   = QUIC_STATUS_NOT_SUPPORTED;

    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {

        ServerConnCtx *ctx = calloc(1, sizeof(ServerConnCtx));
        /* verbose flag inherited from server config — stored as int in Context
         * We repurpose the low bit of the pointer for the flag safely here.  */

        MsQuic->SetCallbackHandler(
            Event->NEW_CONNECTION.Connection,
            (void *)ServerConnectionCallback,
            ctx);

        Status = MsQuic->ConnectionSetConfiguration(
            Event->NEW_CONNECTION.Connection,
            Configuration);

        if (QUIC_FAILED(Status)) {
            fprintf(stderr,
                    "[quic-server] ConnectionSetConfiguration failed: 0x%x\n",
                    Status);
            if (ctx) free(ctx);
        }
    }

    return Status;
}

/* ── Usage ───────────────────────────────────────────────────────────────── */
static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  --port  PORT   UDP listen port          (default: %d)\n"
        "  --cert  FILE   PEM certificate chain    (default: %s)\n"
        "  --key   FILE   PEM private key          (default: %s)\n"
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
    int         verbose = 0;

    /* ── Parse arguments ─────────────────────────────────────────────────── */
    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--port")    == 0 && i + 1 < argc) port    = atoi(argv[++i]);
        else if (strcmp(argv[i], "--cert")    == 0 && i + 1 < argc) cert    = argv[++i];
        else if (strcmp(argv[i], "--key")     == 0 && i + 1 < argc) key     = argv[++i];
        else if (strcmp(argv[i], "--verbose") == 0) verbose = 1;
        else if (strcmp(argv[i], "--help")    == 0) { print_usage(argv[0]); return 0; }
        else { fprintf(stderr, "[error] Unknown argument: %s\n", argv[i]); return 1; }
    }

    fprintf(stderr, "[quic-server] port=%d  cert=%s  key=%s\n",
            port, cert, key);

    /* Note: KEM group is configured via OPENSSL_CONF env var set by the
     * Docker entrypoint.  MsQuic initialises OpenSSL internally and will
     * pick up the Groups directive from the config file automatically.    */
    const char *ossl_conf = getenv("OPENSSL_CONF");
    if (ossl_conf) {
        fprintf(stderr, "[quic-server] OPENSSL_CONF=%s\n", ossl_conf);
    } else {
        fprintf(stderr,
                "[quic-server] OPENSSL_CONF not set — using OpenSSL default groups\n");
    }

    /* ── Signal handling ─────────────────────────────────────────────────── */
    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);

    /* ── Initialise MsQuic ───────────────────────────────────────────────── */
    QUIC_STATUS Status = MsQuicOpen2(&MsQuic);
    if (QUIC_FAILED(Status)) {
        fprintf(stderr, "[error] MsQuicOpen2 failed: 0x%x\n", Status);
        return 1;
    }

    /* ── Registration ────────────────────────────────────────────────────── */
    HQUIC Registration = NULL;
    const QUIC_REGISTRATION_CONFIG RegConfig = {
        .AppName       = "pqc-quic-server",
        .ExecutionProfile = QUIC_EXECUTION_PROFILE_LOW_LATENCY
    };

    Status = MsQuic->RegistrationOpen(&RegConfig, &Registration);
    if (QUIC_FAILED(Status)) {
        fprintf(stderr, "[error] RegistrationOpen failed: 0x%x\n", Status);
        MsQuicClose(MsQuic);
        return 1;
    }

    /* ── Configuration (server TLS settings) ─────────────────────────────── */
    HQUIC Configuration = NULL;
    QUIC_SETTINGS Settings;
    memset(&Settings, 0, sizeof(Settings));

    /* Disable session resumption — force a full handshake every time */
    Settings.ServerResumptionLevel    = QUIC_SERVER_NO_RESUME;
    Settings.IsSet.ServerResumptionLevel = TRUE;

    /* Handshake idle timeout: 10 seconds */
    Settings.HandshakeIdleTimeoutMs    = 10000;
    Settings.IsSet.HandshakeIdleTimeoutMs = TRUE;

    /* Connection idle timeout: 30 seconds */
    Settings.IdleTimeoutMs             = 30000;
    Settings.IsSet.IdleTimeoutMs       = TRUE;

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

    /* ── Load TLS credentials (certificate + private key) ────────────────── */
    QUIC_CERTIFICATE_FILE CertFile;
    memset(&CertFile, 0, sizeof(CertFile));
    CertFile.PrivateKeyFile  = key;
    CertFile.CertificateFile = cert;

    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type           = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    CredConfig.Flags          = QUIC_CREDENTIAL_FLAG_NONE;
    CredConfig.CertificateFile = &CertFile;

    Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig);
    if (QUIC_FAILED(Status)) {
        fprintf(stderr,
                "[error] ConfigurationLoadCredential failed: 0x%x\n"
                "        cert=%s  key=%s\n",
                Status, cert, key);
        goto cleanup_configuration;
    }

    /* ── Open listener ───────────────────────────────────────────────────── */
    HQUIC Listener = NULL;
    Status = MsQuic->ListenerOpen(
        Registration,
        ServerListenerCallback,
        (void *)Configuration,  /* pass Configuration as context */
        &Listener);

    if (QUIC_FAILED(Status)) {
        fprintf(stderr, "[error] ListenerOpen failed: 0x%x\n", Status);
        goto cleanup_configuration;
    }

    /* ── Bind to address and start listening ─────────────────────────────── */
    QUIC_ADDR ListenAddr;
    memset(&ListenAddr, 0, sizeof(ListenAddr));
    QuicAddrSetFamily(&ListenAddr, QUIC_ADDRESS_FAMILY_INET6);
    QuicAddrSetPort(&ListenAddr, (uint16_t)port);

    Status = MsQuic->ListenerStart(Listener, &ALPN, 1, &ListenAddr);
    if (QUIC_FAILED(Status)) {
        /* Try IPv4 */
        QuicAddrSetFamily(&ListenAddr, QUIC_ADDRESS_FAMILY_INET);
        Status = MsQuic->ListenerStart(Listener, &ALPN, 1, &ListenAddr);
    }

    if (QUIC_FAILED(Status)) {
        fprintf(stderr, "[error] ListenerStart failed: 0x%x\n", Status);
        MsQuic->ListenerClose(Listener);
        goto cleanup_configuration;
    }

    fprintf(stdout, "[quic-server] ready — listening on UDP port %d\n", port);
    fflush(stdout);

    /* ── Wait for shutdown signal ────────────────────────────────────────── */
    pthread_mutex_lock(&g_shutdown_mutex);
    while (g_running) {
        pthread_cond_wait(&g_shutdown_cond, &g_shutdown_mutex);
    }
    pthread_mutex_unlock(&g_shutdown_mutex);

    /* ── Teardown ─────────────────────────────────────────────────────────── */
    fprintf(stderr,
            "[quic-server] shutting down — "
            "handshakes: %ld ok / %ld errors\n",
            g_handshake_ok, g_handshake_err);

    MsQuic->ListenerStop(Listener);
    MsQuic->ListenerClose(Listener);

cleanup_configuration:
    MsQuic->ConfigurationClose(Configuration);

cleanup_registration:
    MsQuic->RegistrationClose(Registration);
    MsQuicClose(MsQuic);

    return QUIC_FAILED(Status) ? 1 : 0;
}