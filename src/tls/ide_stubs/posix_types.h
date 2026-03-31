/*
 * posix_types.h — Minimal POSIX type stubs for the clangd IDE on Windows.
 *
 * PURPOSE
 * -------
 * On a Windows development host, clangd with --target=x86_64-pc-linux-gnu
 * cannot find the Linux sysroot headers (time.h, sys/socket.h, netdb.h, etc.).
 * When these headers are missing, types like struct timespec, struct addrinfo,
 * and constants like NULL, AF_UNSPEC, CLOCK_MONOTONIC are either undeclared or
 * treated as forward-declared incomplete structs, causing cascading
 * "variable has incomplete type" / "undeclared identifier" IDE errors.
 *
 * This file is force-included by clangd via the -include flag in .clangd so
 * that all POSIX types used across src/tls/server.c and src/tls/client.c are
 * defined BEFORE any user include is processed.
 *
 * It is NOT used during actual compilation.  The real system headers at their
 * standard Linux paths supply these types inside the Docker build container.
 *
 * MAINTENANCE
 * -----------
 * Add entries here only for types/constants that cause "incomplete type" or
 * "undeclared identifier" IDE errors in server.c or client.c.  Keep this file
 * as minimal as possible — it is a diagnostic aid, not a portability layer.
 *
 * DO NOT include this file from production code.
 */

#pragma once

#ifndef POSIX_TYPES_STUB_H
#define POSIX_TYPES_STUB_H

/* ── Only active when the real system headers are absent ───────────────────
 * On Linux (inside Docker) the real <time.h>, <sys/socket.h>, etc. are found
 * before this stub is processed; their include guards prevent double
 * definitions.  On Windows these guards are not set, so our definitions below
 * take effect.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * stddef / stdint equivalents
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifndef NULL
#  ifdef __cplusplus
#    define NULL nullptr
#  else
#    define NULL ((void *)0)
#  endif
#endif

#ifndef __SIZE_TYPE__
typedef unsigned long  size_t;
#endif

typedef long           ssize_t;
typedef unsigned long  uint64_t;
typedef unsigned int   uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char  uint8_t;
typedef long           int64_t;
typedef int            int32_t;
typedef short          int16_t;
typedef signed char    int8_t;

/* ═══════════════════════════════════════════════════════════════════════════
 * POSIX time types  (<time.h>)
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifndef _STRUCT_TIMESPEC
#define _STRUCT_TIMESPEC
struct timespec {
    long tv_sec;   /* seconds */
    long tv_nsec;  /* nanoseconds [0, 999999999] */
};
#endif

#ifndef CLOCK_REALTIME
#  define CLOCK_REALTIME   0
#endif
#ifndef CLOCK_MONOTONIC
#  define CLOCK_MONOTONIC  1
#endif
#ifndef CLOCK_PROCESS_CPUTIME_ID
#  define CLOCK_PROCESS_CPUTIME_ID 2
#endif
#ifndef CLOCK_THREAD_CPUTIME_ID
#  define CLOCK_THREAD_CPUTIME_ID  3
#endif

typedef int clockid_t;

/* clock_gettime / nanosleep — POSIX.1b real-time extensions */
int clock_gettime(clockid_t clk_id, struct timespec *tp);
int nanosleep(const struct timespec *req, struct timespec *rem);

/* ═══════════════════════════════════════════════════════════════════════════
 * POSIX signal types  (<signal.h>)
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifndef SIG_IGN
#  define SIG_IGN  ((void (*)(int))1)
#  define SIG_DFL  ((void (*)(int))0)
#  define SIG_ERR  ((void (*)(int))-1)
#endif

#ifndef SIGTERM
#  define SIGTERM  15
#  define SIGINT    2
#  define SIGPIPE  13
#  define SIGKILL   9
#endif

typedef void (*sighandler_t)(int);
sighandler_t signal(int signum, sighandler_t handler);

/* ═══════════════════════════════════════════════════════════════════════════
 * POSIX file descriptors / I/O  (<unistd.h>)
 * ═══════════════════════════════════════════════════════════════════════════ */

int close(int fd);
int read(int fd, void *buf, size_t count);
int write(int fd, const void *buf, size_t count);
int usleep(unsigned int usecs);   /* legacy; use nanosleep in new code */

/* ═══════════════════════════════════════════════════════════════════════════
 * POSIX errno  (<errno.h>)
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifndef EINTR
#  define EINTR    4
#  define EAGAIN  11
#  define EWOULDBLOCK EAGAIN
#  define ETIMEDOUT 110
#  define ECONNREFUSED 111
#  define ENOBUFS  105
#endif

/* errno is typically a macro expanding to a thread-local variable.
 * Provide a simple global for IDE parsing purposes only. */
#ifndef errno
extern int errno;
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * POSIX socket types  (<sys/socket.h>, <netinet/in.h>, <arpa/inet.h>)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef unsigned int  socklen_t;
typedef unsigned short sa_family_t;
typedef unsigned short in_port_t;
typedef unsigned int   in_addr_t;

/* Address families */
#ifndef AF_UNSPEC
#  define AF_UNSPEC   0
#  define AF_INET     2
#  define AF_INET6   10
#  define PF_UNSPEC   AF_UNSPEC
#  define PF_INET     AF_INET
#  define PF_INET6    AF_INET6
#endif

/* Socket types */
#ifndef SOCK_STREAM
#  define SOCK_STREAM   1
#  define SOCK_DGRAM    2
#  define SOCK_RAW      3
#endif

/* Socket-level options */
#ifndef SOL_SOCKET
#  define SOL_SOCKET    1
#endif
#ifndef SO_REUSEADDR
#  define SO_REUSEADDR  2
#  define SO_REUSEPORT 15
#  define SO_KEEPALIVE  9
#  define SO_ERROR      4
#  define SO_SNDBUF     7
#  define SO_RCVBUF     8
#endif

/* IP protocol numbers */
#ifndef IPPROTO_TCP
#  define IPPROTO_TCP   6
#  define IPPROTO_UDP  17
#  define IPPROTO_IP    0
#  define IPPROTO_IPV6 41
#endif

/* TCP options */
#ifndef TCP_NODELAY
#  define TCP_NODELAY   1
#  define TCP_KEEPIDLE  4
#  define TCP_KEEPINTVL 5
#  define TCP_KEEPCNT   6
#endif

struct in_addr {
    in_addr_t s_addr;
};

struct in6_addr {
    unsigned char s6_addr[16];
};

struct sockaddr {
    sa_family_t sa_family;
    char        sa_data[14];
};

struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t   sin_port;
    struct in_addr sin_addr;
    char        sin_zero[8];
};

struct sockaddr_in6 {
    sa_family_t  sin6_family;
    in_port_t    sin6_port;
    unsigned int sin6_flowinfo;
    struct in6_addr sin6_addr;
    unsigned int sin6_scope_id;
};

struct sockaddr_storage {
    sa_family_t  ss_family;
    char         __ss_padding[128 - sizeof(sa_family_t) - sizeof(unsigned long)];
    unsigned long __ss_align;
};

/* in6addr_any */
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;

/* htons / htonl / ntohs / ntohl */
uint16_t htons(uint16_t hostshort);
uint16_t ntohs(uint16_t netshort);
uint32_t htonl(uint32_t hostlong);
uint32_t ntohl(uint32_t netlong);

/* Socket API */
int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int setsockopt(int sockfd, int level, int optname,
               const void *optval, socklen_t optlen);
int getsockopt(int sockfd, int level, int optname,
               void *optval, socklen_t *optlen);
int shutdown(int sockfd, int how);

/* inet helpers */
int         inet_pton(int af, const char *src, void *dst);
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

/* ═══════════════════════════════════════════════════════════════════════════
 * POSIX name resolution  (<netdb.h>)
 * ═══════════════════════════════════════════════════════════════════════════ */

struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    socklen_t        ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};

#ifndef AI_PASSIVE
#  define AI_PASSIVE     0x0001
#  define AI_CANONNAME   0x0002
#  define AI_NUMERICHOST 0x0004
#  define AI_V4MAPPED    0x0008
#  define AI_ALL         0x0010
#  define AI_ADDRCONFIG  0x0020
#endif

int  getaddrinfo(const char *node, const char *service,
                 const struct addrinfo *hints, struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);
const char *gai_strerror(int errcode);

/* ═══════════════════════════════════════════════════════════════════════════
 * Standard C library  (<stdio.h>, <stdlib.h>, <string.h>)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* FILE / stdio */
typedef struct _IO_FILE FILE;
extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;

int    fprintf(FILE *stream, const char *format, ...);
int    printf(const char *format, ...);
int    snprintf(char *str, size_t size, const char *format, ...);
int    sscanf(const char *str, const char *format, ...);
int    fclose(FILE *stream);
FILE  *fopen(const char *pathname, const char *mode);
int    fflush(FILE *stream);
char  *fgets(char *s, int size, FILE *stream);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int    fputs(const char *s, FILE *stream);
void   perror(const char *s);

/* stdlib */
void  *malloc(size_t size);
void  *calloc(size_t nmemb, size_t size);
void  *realloc(void *ptr, size_t size);
void   free(void *ptr);
void   exit(int status);
int    atoi(const char *nptr);
long   atol(const char *nptr);
long   strtol(const char *nptr, char **endptr, int base);
double strtod(const char *nptr, char **endptr);

/* string */
void  *memset(void *s, int c, size_t n);
void  *memcpy(void *dest, const void *src, size_t n);
void  *memmove(void *dest, const void *src, size_t n);
int    memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);
char  *strcpy(char *dest, const char *src);
char  *strncpy(char *dest, const char *src, size_t n);
int    strcmp(const char *s1, const char *s2);
int    strncmp(const char *s1, const char *s2, size_t n);
char  *strcat(char *dest, const char *src);
char  *strncat(char *dest, const char *src, size_t n);
char  *strdup(const char *s);
char  *strerror(int errnum);
char  *strchr(const char *s, int c);
char  *strrchr(const char *s, int c);
char  *strstr(const char *haystack, const char *needle);

/* ═══════════════════════════════════════════════════════════════════════════
 * TCP/IP constants  (<netinet/tcp.h>)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Already defined above via TCP_NODELAY block. */

/* INADDR_ANY / INADDR_LOOPBACK */
#ifndef INADDR_ANY
#  define INADDR_ANY       ((in_addr_t)0x00000000)
#  define INADDR_LOOPBACK  ((in_addr_t)0x7f000001)
#  define INADDR_BROADCAST ((in_addr_t)0xffffffff)
#  define INADDR_NONE      ((in_addr_t)0xffffffff)
#endif

#ifdef __cplusplus
}
#endif

#endif /* POSIX_TYPES_STUB_H */