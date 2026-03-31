/*
 * msquic.h — Minimal IDE stub for the MsQuic SDK.
 *
 * PURPOSE
 * -------
 * This file exists ONLY to give the clangd language server on a Windows
 * development host enough type information to parse src/quic/client.c and
 * src/quic/server.c without cascading "unknown type" errors.
 *
 * It is NOT used during compilation.  The real MsQuic header lives at
 *   /opt/msquic/include/msquic.h
 * inside the Docker build container (Ubuntu 24.04).
 *
 * MAINTENANCE
 * -----------
 * Keep this stub in sync with the MsQuic version declared in
 *   docker/quic-server/Dockerfile  (MSQUIC_VERSION=v2.4.4)
 *
 * When upgrading MsQuic, check whether any new types used in
 * src/quic/client.c or src/quic/server.c need to be added here.
 *
 * DO NOT include this file from production code.
 */

#pragma once

#ifndef MSQUIC_H          /* guard against the real header if somehow found */
#define MSQUIC_H

#ifdef __cplusplus
extern "C" {
#endif

/* ── Primitive / platform types ─────────────────────────────────────────── */

#ifndef BOOLEAN
typedef unsigned char BOOLEAN;
#endif

#ifndef TRUE
#  define TRUE  ((BOOLEAN)1)
#endif
#ifndef FALSE
#  define FALSE ((BOOLEAN)0)
#endif

/* All MsQuic object handles are opaque pointers. */
typedef void *HQUIC;

/* Status code: 0 = success, non-zero = error. */
typedef unsigned int QUIC_STATUS;

#define QUIC_STATUS_SUCCESS           ((QUIC_STATUS)0x00000000U)
#define QUIC_STATUS_PENDING           ((QUIC_STATUS)0x00000001U)
#define QUIC_STATUS_CONTINUE          ((QUIC_STATUS)0x00000002U)
#define QUIC_STATUS_OUT_OF_MEMORY     ((QUIC_STATUS)0x80000001U)
#define QUIC_STATUS_INVALID_PARAMETER ((QUIC_STATUS)0x80000002U)
#define QUIC_STATUS_INVALID_STATE     ((QUIC_STATUS)0x80000003U)
#define QUIC_STATUS_NOT_SUPPORTED     ((QUIC_STATUS)0x80000004U)
#define QUIC_STATUS_NOT_FOUND         ((QUIC_STATUS)0x80000005U)
#define QUIC_STATUS_BUFFER_TOO_SMALL  ((QUIC_STATUS)0x80000006U)
#define QUIC_STATUS_HANDSHAKE_FAILURE ((QUIC_STATUS)0x80000007U)
#define QUIC_STATUS_ABORTED           ((QUIC_STATUS)0x80000008U)
#define QUIC_STATUS_ADDRESS_IN_USE    ((QUIC_STATUS)0x80000009U)
#define QUIC_STATUS_CONNECTION_TIMEOUT ((QUIC_STATUS)0x8000000AU)
#define QUIC_STATUS_CONNECTION_IDLE   ((QUIC_STATUS)0x8000000BU)
#define QUIC_STATUS_INTERNAL_ERROR    ((QUIC_STATUS)0x8000000CU)
#define QUIC_STATUS_CONNECTION_REFUSED ((QUIC_STATUS)0x8000000DU)
#define QUIC_STATUS_PROTOCOL_ERROR    ((QUIC_STATUS)0x8000000EU)
#define QUIC_STATUS_VER_NEG_ERROR     ((QUIC_STATUS)0x8000000FU)
#define QUIC_STATUS_UNREACHABLE       ((QUIC_STATUS)0x80000010U)
#define QUIC_STATUS_TLS_ERROR         ((QUIC_STATUS)0x80000011U)
#define QUIC_STATUS_USER_CANCELED     ((QUIC_STATUS)0x80000012U)
#define QUIC_STATUS_ALPN_NEG_FAILURE  ((QUIC_STATUS)0x80000013U)
#define QUIC_STATUS_STREAM_LIMIT_REACHED ((QUIC_STATUS)0x80000014U)
#define QUIC_STATUS_CLOSE_NOTIFY      ((QUIC_STATUS)0x80000015U)
#define QUIC_STATUS_BAD_CERTIFICATE   ((QUIC_STATUS)0x80000016U)
#define QUIC_STATUS_REQUIRED_CERTIFICATE ((QUIC_STATUS)0x80000017U)
#define QUIC_STATUS_CERT_EXPIRED      ((QUIC_STATUS)0x80000018U)
#define QUIC_STATUS_CERT_UNTRUSTED_ROOT ((QUIC_STATUS)0x80000019U)
#define QUIC_STATUS_CERT_NO_CERT      ((QUIC_STATUS)0x8000001AU)

#define QUIC_FAILED(Status)     ((QUIC_STATUS)(Status) != QUIC_STATUS_SUCCESS)
#define QUIC_SUCCEEDED(Status)  ((QUIC_STATUS)(Status) == QUIC_STATUS_SUCCESS)

/* Calling convention — empty on Linux. */
#ifndef QUIC_API
#  define QUIC_API
#endif

/* ── Address family ──────────────────────────────────────────────────────── */

typedef unsigned char QUIC_ADDRESS_FAMILY;
#define QUIC_ADDRESS_FAMILY_UNSPEC ((QUIC_ADDRESS_FAMILY)0)
#define QUIC_ADDRESS_FAMILY_INET   ((QUIC_ADDRESS_FAMILY)2)
#define QUIC_ADDRESS_FAMILY_INET6  ((QUIC_ADDRESS_FAMILY)23)

/* ── QUIC_ADDR ───────────────────────────────────────────────────────────── */

typedef struct QUIC_ADDR {
    QUIC_ADDRESS_FAMILY Family;
    unsigned short      Port;
    unsigned char       _Addr[28]; /* enough for IPv6 */
} QUIC_ADDR;

static inline void QuicAddrSetFamily(QUIC_ADDR *Addr, QUIC_ADDRESS_FAMILY Family) {
    Addr->Family = Family;
}

static inline void QuicAddrSetPort(QUIC_ADDR *Addr, unsigned short Port) {
    /* Network byte order — swap on little-endian. */
    Addr->Port = (unsigned short)((Port >> 8) | (Port << 8));
}

/* ── QUIC_BUFFER ─────────────────────────────────────────────────────────── */

typedef struct QUIC_BUFFER {
    unsigned int  Length;
    unsigned char *Buffer;
} QUIC_BUFFER;

/* ── Execution profile ───────────────────────────────────────────────────── */

typedef enum QUIC_EXECUTION_PROFILE {
    QUIC_EXECUTION_PROFILE_LOW_LATENCY       = 0,
    QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT,
    QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER,
    QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME,
} QUIC_EXECUTION_PROFILE;

/* ── Registration ────────────────────────────────────────────────────────── */

typedef struct QUIC_REGISTRATION_CONFIG {
    const char            *AppName;
    QUIC_EXECUTION_PROFILE ExecutionProfile;
} QUIC_REGISTRATION_CONFIG;

/* ── Settings ────────────────────────────────────────────────────────────── */

typedef enum QUIC_SERVER_RESUMPTION_LEVEL {
    QUIC_SERVER_NO_RESUME       = 0,
    QUIC_SERVER_RESUME_ONLY     = 1,
    QUIC_SERVER_RESUME_AND_ZERORTT = 2,
} QUIC_SERVER_RESUMPTION_LEVEL;

typedef struct QUIC_SETTINGS {
    /* Each field has a corresponding IsSet flag in a union/bitfield.
       For the stub we use a simple struct with individual BOOLEAN flags. */
    unsigned long long MaxBytesPerKey;
    unsigned long long HandshakeIdleTimeoutMs;
    unsigned long long IdleTimeoutMs;
    unsigned long long MtuDiscoverySearchCompleteTimeoutUs;
    unsigned int       TlsClientMaxSendBuffer;
    unsigned int       TlsServerMaxSendBuffer;
    unsigned int       StreamRecvWindowDefault;
    unsigned int       StreamRecvBufferDefault;
    unsigned int       ConnFlowControlWindow;
    unsigned int       MaxWorkerQueueDelayUs;
    unsigned int       MaxStatelessOperations;
    unsigned int       InitialWindowPackets;
    unsigned int       SendIdleTimeoutMs;
    unsigned int       InitialRttMs;
    unsigned int       MaxAckDelayMs;
    unsigned int       DisconnectTimeoutMs;
    unsigned int       KeepAliveIntervalMs;
    unsigned short     CongestionControlAlgorithm;
    unsigned short     PeerBidiStreamCount;
    unsigned short     PeerUnidiStreamCount;
    unsigned short     MaxBindingStatelessOperations;
    unsigned short     StatelessOperationExpirationMs;
    unsigned short     MinimumMtu;
    unsigned short     MaximumMtu;
    unsigned char      MaxOperationsPerDrain;
    unsigned char      MtuDiscoveryMissingProbeCount;
    unsigned int       DestCidUpdateIdleTimeoutMs;

    QUIC_SERVER_RESUMPTION_LEVEL ServerResumptionLevel;
    BOOLEAN                      VersionNegotiationExtEnabled;
    BOOLEAN                      GreaseQuicBitEnabled;
    BOOLEAN                      EcnEnabled;
    BOOLEAN                      HyStartEnabled;
    BOOLEAN                      StreamRecvWindowBidiLocalDefault;
    BOOLEAN                      StreamRecvWindowBidiRemoteDefault;
    BOOLEAN                      StreamRecvWindowUnidiDefault;

    /* IsSet bitfield — simplified as a struct of BOOLEANs for the stub. */
    struct {
        BOOLEAN MaxBytesPerKey                 : 1;
        BOOLEAN HandshakeIdleTimeoutMs         : 1;
        BOOLEAN IdleTimeoutMs                  : 1;
        BOOLEAN MtuDiscoverySearchCompleteTimeoutUs : 1;
        BOOLEAN TlsClientMaxSendBuffer         : 1;
        BOOLEAN TlsServerMaxSendBuffer         : 1;
        BOOLEAN StreamRecvWindowDefault        : 1;
        BOOLEAN StreamRecvBufferDefault        : 1;
        BOOLEAN ConnFlowControlWindow          : 1;
        BOOLEAN MaxWorkerQueueDelayUs          : 1;
        BOOLEAN MaxStatelessOperations         : 1;
        BOOLEAN InitialWindowPackets           : 1;
        BOOLEAN SendIdleTimeoutMs              : 1;
        BOOLEAN InitialRttMs                   : 1;
        BOOLEAN MaxAckDelayMs                  : 1;
        BOOLEAN DisconnectTimeoutMs            : 1;
        BOOLEAN KeepAliveIntervalMs            : 1;
        BOOLEAN CongestionControlAlgorithm    : 1;
        BOOLEAN PeerBidiStreamCount            : 1;
        BOOLEAN PeerUnidiStreamCount           : 1;
        BOOLEAN MaxBindingStatelessOperations  : 1;
        BOOLEAN StatelessOperationExpirationMs : 1;
        BOOLEAN MinimumMtu                     : 1;
        BOOLEAN MaximumMtu                     : 1;
        BOOLEAN MaxOperationsPerDrain          : 1;
        BOOLEAN MtuDiscoveryMissingProbeCount  : 1;
        BOOLEAN DestCidUpdateIdleTimeoutMs     : 1;
        BOOLEAN ServerResumptionLevel          : 1;
        BOOLEAN VersionNegotiationExtEnabled   : 1;
        BOOLEAN GreaseQuicBitEnabled           : 1;
        BOOLEAN EcnEnabled                     : 1;
        BOOLEAN HyStartEnabled                 : 1;
    } IsSet;
} QUIC_SETTINGS;

/* ── Credential configuration ────────────────────────────────────────────── */

typedef enum QUIC_CREDENTIAL_TYPE {
    QUIC_CREDENTIAL_TYPE_NONE                    = 0x00000000,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH        = 0x00000001,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE  = 0x00000002,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT     = 0x00000003,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE        = 0x00000004,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED = 0x00000005,
    QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12      = 0x00000006,
} QUIC_CREDENTIAL_TYPE;

typedef enum QUIC_CREDENTIAL_FLAGS {
    QUIC_CREDENTIAL_FLAG_NONE                           = 0x00000000,
    QUIC_CREDENTIAL_FLAG_CLIENT                         = 0x00000001,
    QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS              = 0x00000002,
    QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION      = 0x00000004,
    QUIC_CREDENTIAL_FLAG_ENABLE_OCSP                    = 0x00000008,
    QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED  = 0x00000010,
    QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION   = 0x00000020,
    QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION  = 0x00000040,
    QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION = 0x00000080,
    QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT      = 0x00000100,
    QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN         = 0x00000200,
    QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000400,
    QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK     = 0x00000800,
    QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE      = 0x00001000,
    QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CERT_ERRORS        = 0x00002000,
    QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES      = 0x00004000,
    QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS       = 0x00008000,
    QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER              = 0x00010000,
    QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL       = 0x00020000,
    QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY    = 0x00040000,
    QUIC_CREDENTIAL_FLAG_INPROC_PEER_CERTIFICATE        = 0x00080000,
    QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE        = 0x00100000,
} QUIC_CREDENTIAL_FLAGS;

typedef struct QUIC_CERTIFICATE_FILE {
    const char *PrivateKeyFile;
    const char *CertificateFile;
} QUIC_CERTIFICATE_FILE;

typedef struct QUIC_CREDENTIAL_CONFIG {
    QUIC_CREDENTIAL_TYPE  Type;
    QUIC_CREDENTIAL_FLAGS Flags;
    union {
        QUIC_CERTIFICATE_FILE *CertificateFile;
        void                  *CertificateFileProtected;
        void                  *CertificateHash;
        void                  *CertificateHashStore;
        void                  *CertificateContext;
        void                  *CertificatePkcs12;
    };
    const char *Principal;
    void       *Reserved;
    void       *AsyncHandler;        /* QUIC_CREDENTIAL_LOAD_COMPLETE_HANDLER */
    unsigned int AllowedCertificateErrors;
    const char  *CaFile;
} QUIC_CREDENTIAL_CONFIG;

/* ── Connection / listener event types ──────────────────────────────────── */

typedef enum QUIC_CONNECTION_EVENT_TYPE {
    QUIC_CONNECTION_EVENT_CONNECTED                  = 0,
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT = 1,
    QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER = 2,
    QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE          = 3,
    QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED      = 4,
    QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED       = 5,
    QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED        = 6,
    QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE          = 7,
    QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS         = 8,
    QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED    = 9,
    QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED     = 10,
    QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED          = 11,
    QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED = 12,
    QUIC_CONNECTION_EVENT_RESUMED                    = 13,
    QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED = 14,
    QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED  = 15,
    QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED  = 16,
    QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_UPDATED      = 17,
    QUIC_CONNECTION_EVENT_NETWORK_STATISTICS         = 18,
} QUIC_CONNECTION_EVENT_TYPE;

typedef struct QUIC_CONNECTION_EVENT {
    QUIC_CONNECTION_EVENT_TYPE Type;
    union {
        /* QUIC_CONNECTION_EVENT_CONNECTED */
        struct {
            BOOLEAN SessionResumed;
            unsigned char NegotiatedAlpnLength;
            const unsigned char *NegotiatedAlpn;
        } CONNECTED;

        /* QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT */
        struct {
            QUIC_STATUS Status;
            unsigned long long ErrorCode;
        } SHUTDOWN_INITIATED_BY_TRANSPORT;

        /* QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER */
        struct {
            unsigned long long ErrorCode;
        } SHUTDOWN_INITIATED_BY_PEER;

        /* QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE */
        struct {
            BOOLEAN HandshakeCompleted;
            BOOLEAN PeerAcknowledgedShutdown;
            BOOLEAN AppCloseInProgress;
        } SHUTDOWN_COMPLETE;

        /* QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED */
        struct {
            HQUIC       Stream;
            unsigned int Flags;
        } PEER_STREAM_STARTED;

        /* QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE */
        struct {
            unsigned short BidirectionalCount;
            unsigned short UnidirectionalCount;
        } STREAMS_AVAILABLE;

        /* QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED */
        struct {
            unsigned int          ResumptionTicketLength;
            const unsigned char  *ResumptionTicket;
        } RESUMPTION_TICKET_RECEIVED;

        /* QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED */
        struct {
            void        *Certificate;
            unsigned int DeferredErrorFlags;
            QUIC_STATUS  DeferredStatus;
            void        *Chain;
        } PEER_CERTIFICATE_RECEIVED;
    };
} QUIC_CONNECTION_EVENT;

/* ── Listener event ──────────────────────────────────────────────────────── */

typedef enum QUIC_LISTENER_EVENT_TYPE {
    QUIC_LISTENER_EVENT_NEW_CONNECTION      = 0,
    QUIC_LISTENER_EVENT_STOP_COMPLETE       = 1,
    QUIC_LISTENER_EVENT_DOS_MODE_CHANGED    = 2,
} QUIC_LISTENER_EVENT_TYPE;

typedef struct QUIC_NEW_CONNECTION_INFO {
    unsigned int       QuicVersion;
    const QUIC_ADDR   *LocalAddress;
    const QUIC_ADDR   *RemoteAddress;
    unsigned int       CryptoBufferLength;
    unsigned short     ClientAlpnListLength;
    unsigned short     ServerNameLength;
    unsigned char      NegotiatedAlpnLength;
    const unsigned char *CryptoBuffer;
    const unsigned char *ClientAlpnList;
    const unsigned char *NegotiatedAlpn;
    const char         *ServerName;
} QUIC_NEW_CONNECTION_INFO;

typedef struct QUIC_LISTENER_EVENT {
    QUIC_LISTENER_EVENT_TYPE Type;
    union {
        struct {
            const QUIC_NEW_CONNECTION_INFO *Info;
            HQUIC                           Connection;
        } NEW_CONNECTION;
        struct {
            BOOLEAN AppCloseInProgress;
        } STOP_COMPLETE;
    };
} QUIC_LISTENER_EVENT;

/* ── Callback signatures ─────────────────────────────────────────────────── */

typedef QUIC_STATUS (QUIC_API *QUIC_CONNECTION_CALLBACK_HANDLER)(
    HQUIC                  Connection,
    void                  *Context,
    QUIC_CONNECTION_EVENT *Event
);

typedef QUIC_STATUS (QUIC_API *QUIC_LISTENER_CALLBACK_HANDLER)(
    HQUIC                Listener,
    void                *Context,
    QUIC_LISTENER_EVENT *Event
);

typedef QUIC_STATUS (QUIC_API *QUIC_STREAM_CALLBACK_HANDLER)(
    HQUIC  Stream,
    void  *Context,
    void  *Event   /* QUIC_STREAM_EVENT* — not needed in this project */
);

/* ── Send resumption flags ───────────────────────────────────────────────── */

typedef enum QUIC_SEND_RESUMPTION_FLAGS {
    QUIC_SEND_RESUMPTION_FLAG_NONE  = 0x0000,
    QUIC_SEND_RESUMPTION_FLAG_FINAL = 0x0001,
} QUIC_SEND_RESUMPTION_FLAGS;

/* ── Connection shutdown flags ───────────────────────────────────────────── */

typedef enum QUIC_CONNECTION_SHUTDOWN_FLAGS {
    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE   = 0x0000,
    QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT = 0x0001,
} QUIC_CONNECTION_SHUTDOWN_FLAGS;

/* ── API function pointer typedefs ───────────────────────────────────────── */

typedef QUIC_STATUS (QUIC_API *QUIC_REGISTRATION_OPEN_FN)(
    const QUIC_REGISTRATION_CONFIG *Config,
    HQUIC                          *Registration
);
typedef void (QUIC_API *QUIC_REGISTRATION_CLOSE_FN)(HQUIC Registration);
typedef void (QUIC_API *QUIC_REGISTRATION_SHUTDOWN_FN)(
    HQUIC Registration, unsigned int Flags, unsigned long long ErrorCode);

typedef QUIC_STATUS (QUIC_API *QUIC_CONFIGURATION_OPEN_FN)(
    HQUIC               Registration,
    const QUIC_BUFFER  *AlpnBuffers,
    unsigned int        AlpnBufferCount,
    const QUIC_SETTINGS *Settings,
    unsigned int        SettingsSize,
    void               *Context,
    HQUIC              *Configuration
);
typedef void        (QUIC_API *QUIC_CONFIGURATION_CLOSE_FN)(HQUIC Configuration);
typedef QUIC_STATUS (QUIC_API *QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN)(
    HQUIC                         Configuration,
    const QUIC_CREDENTIAL_CONFIG *CredConfig
);

typedef QUIC_STATUS (QUIC_API *QUIC_LISTENER_OPEN_FN)(
    HQUIC                        Registration,
    QUIC_LISTENER_CALLBACK_HANDLER Handler,
    void                         *Context,
    HQUIC                        *Listener
);
typedef void        (QUIC_API *QUIC_LISTENER_CLOSE_FN)(HQUIC Listener);
typedef QUIC_STATUS (QUIC_API *QUIC_LISTENER_START_FN)(
    HQUIC               Listener,
    const QUIC_BUFFER  *AlpnBuffers,
    unsigned int        AlpnBufferCount,
    const QUIC_ADDR    *LocalAddress
);
typedef void (QUIC_API *QUIC_LISTENER_STOP_FN)(HQUIC Listener);

typedef QUIC_STATUS (QUIC_API *QUIC_CONNECTION_OPEN_FN)(
    HQUIC                           Registration,
    QUIC_CONNECTION_CALLBACK_HANDLER Handler,
    void                            *Context,
    HQUIC                           *Connection
);
typedef void (QUIC_API *QUIC_CONNECTION_CLOSE_FN)(HQUIC Connection);
typedef void (QUIC_API *QUIC_CONNECTION_SHUTDOWN_FN)(
    HQUIC                          Connection,
    QUIC_CONNECTION_SHUTDOWN_FLAGS Flags,
    unsigned long long             ErrorCode
);
typedef QUIC_STATUS (QUIC_API *QUIC_CONNECTION_START_FN)(
    HQUIC               Connection,
    HQUIC               Configuration,
    QUIC_ADDRESS_FAMILY Family,
    const char         *ServerName,
    unsigned short      ServerPort
);
typedef QUIC_STATUS (QUIC_API *QUIC_CONNECTION_SET_CONFIGURATION_FN)(
    HQUIC Connection,
    HQUIC Configuration
);
typedef QUIC_STATUS (QUIC_API *QUIC_CONNECTION_SEND_RESUMPTION_TICKET_FN)(
    HQUIC                     Connection,
    QUIC_SEND_RESUMPTION_FLAGS Flags,
    unsigned short             DataLength,
    const unsigned char       *ResumptionData
);

typedef void (QUIC_API *QUIC_SET_CALLBACK_HANDLER_FN)(
    HQUIC Handle,
    void  *Handler,
    void  *Context
);

typedef QUIC_STATUS (QUIC_API *QUIC_SET_PARAM_FN)(
    HQUIC        Handle,
    unsigned int Param,
    unsigned int BufferLength,
    const void  *Buffer
);
typedef QUIC_STATUS (QUIC_API *QUIC_GET_PARAM_FN)(
    HQUIC        Handle,
    unsigned int Param,
    unsigned int *BufferLength,
    void        *Buffer
);

typedef void (QUIC_API *QUIC_STREAM_CLOSE_FN)(HQUIC Stream);

/* ── API table ───────────────────────────────────────────────────────────── */

typedef struct QUIC_API_TABLE {
    /* Context helpers */
    QUIC_SET_CALLBACK_HANDLER_FN              SetCallbackHandler;
    QUIC_SET_PARAM_FN                         SetParam;
    QUIC_GET_PARAM_FN                         GetParam;

    /* Registration */
    QUIC_REGISTRATION_OPEN_FN                 RegistrationOpen;
    QUIC_REGISTRATION_CLOSE_FN                RegistrationClose;
    QUIC_REGISTRATION_SHUTDOWN_FN             RegistrationShutdown;

    /* Configuration */
    QUIC_CONFIGURATION_OPEN_FN                ConfigurationOpen;
    QUIC_CONFIGURATION_CLOSE_FN               ConfigurationClose;
    QUIC_CONFIGURATION_LOAD_CREDENTIAL_FN     ConfigurationLoadCredential;

    /* Listener */
    QUIC_LISTENER_OPEN_FN                     ListenerOpen;
    QUIC_LISTENER_CLOSE_FN                    ListenerClose;
    QUIC_LISTENER_START_FN                    ListenerStart;
    QUIC_LISTENER_STOP_FN                     ListenerStop;

    /* Connection */
    QUIC_CONNECTION_OPEN_FN                   ConnectionOpen;
    QUIC_CONNECTION_CLOSE_FN                  ConnectionClose;
    QUIC_CONNECTION_SHUTDOWN_FN               ConnectionShutdown;
    QUIC_CONNECTION_START_FN                  ConnectionStart;
    QUIC_CONNECTION_SET_CONFIGURATION_FN      ConnectionSetConfiguration;
    QUIC_CONNECTION_SEND_RESUMPTION_TICKET_FN ConnectionSendResumptionTicket;

    /* Stream */
    QUIC_STREAM_CLOSE_FN                      StreamClose;
} QUIC_API_TABLE;

/* ── Library open / close ────────────────────────────────────────────────── */

typedef QUIC_STATUS (QUIC_API *QUIC_OPEN_VERSION_FN)(
    unsigned int         Version,
    const QUIC_API_TABLE **QuicApi
);

#define QUIC_API_VERSION_2 2

QUIC_STATUS QUIC_API MsQuicOpen2(const QUIC_API_TABLE **QuicApi);
void        QUIC_API MsQuicClose(const QUIC_API_TABLE *QuicApi);

#ifdef __cplusplus
}
#endif

#endif /* MSQUIC_H */