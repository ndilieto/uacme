/*
 * Copyright (C) 2019-2026 Nicola Di Lieto <nicola.dilieto@gmail.com>
 *
 * This file is part of uacme.
 *
 * uacme is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * uacme is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <ev.h>
#if defined(USE_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#elif defined(USE_OPENSSL)
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#elif defined(USE_MBEDTLS)
#include <mbedtls/asn1write.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#endif

#include "sglib.h"
#include "base64.h"
#include "log.h"

#define MAXHOST 64
#define MAXSERV 16

#if defined(USE_GNUTLS)
#if GNUTLS_VERSION_NUMBER < 0x03031e
#error GnuTLS version 3.3.30 or later is required
#endif
#elif defined(USE_OPENSSL)
#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error OpenSSL version 1.1.1 or later is required
#endif
static void openssl_error(const char *prefix)
{
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        warnx("%s: openssl %s", prefix, ERR_error_string(e, NULL));
        return;
    }
}
#elif defined(USE_MBEDTLS)
#if MBEDTLS_VERSION_NUMBER < 0x02100000
#error mbedTLS version 2.16 or later is required
#endif
#if MBEDTLS_VERSION_NUMBER < 0x02170000 && \
    !defined(MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
#error mbedTLS earlier than version 2.23 needs to be configured with \
    MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
#endif

static const char *_mbedtls_strerror(int code)
{
    static char buf[0x100];
    mbedtls_strerror(code, buf, sizeof(buf));
    return buf;
}

#ifndef MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE
#define MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE -1
#endif
#endif

#if !defined(EAGAIN)
#define EAGAIN EWOULDBLOCK
#endif

#if !defined(EWOULDBLOCK)
#define EWOULDBLOCK EAGAIN
#endif

typedef struct auth {
    ev_tstamp timestamp;
    char ident[0x100];
    char auth[0x30];
    uint8_t key[0x100];
    size_t key_size;
    uint8_t crt[0x500];
    size_t crt_size;
    uint8_t rb;
    struct auth *left, *right;
} auth_t;

#define ACME_AUTH_CMP(x,y) (strcasecmp(((x)->ident), ((y)->ident)))

SGLIB_DEFINE_RBTREE_PROTOTYPES(auth_t, left, right, rb, ACME_AUTH_CMP)
SGLIB_DEFINE_RBTREE_FUNCTIONS(auth_t, left, right, rb, ACME_AUTH_CMP)

#if !defined(PIPE_BUF)
#define PIPE_BUF 2048
#endif

typedef struct buffer {
    uint8_t data[2*PIPE_BUF];
    size_t rp;
    size_t wp;
    size_t n;
} buffer_t;

typedef struct addr {
    union {
        struct sockaddr sa;
        struct sockaddr_storage ss;
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
        struct sockaddr_un un;
    } addr;
    socklen_t len;
} uaddr_t;

typedef struct client {
    unsigned int id;
#if EV_MULTIPLICITY
    struct ev_loop *loop;
#endif
    ev_tstamp timestamp;
    ev_timer timer;
    ev_io io_txf;
    ev_io io_rxf;
    ev_io io_txb;
    ev_io io_rxb;
    int fd_f;
    int fd_b;
#if HAVE_SPLICE
    ev_io io_f2b0;
    ev_io io_f2b1;
    ev_io io_b2f0;
    ev_io io_b2f1;
    int fd_f2b[2];
    int fd_b2f[2];
    ssize_t n_f2b;
    ssize_t n_b2f;
#else
    buffer_t buf_f2b;
    buffer_t buf_b2f;
#endif
    size_t brx, btx, frx, ftx;
    char lhost_f[MAXHOST];
    char lserv_f[MAXSERV];
    char rhost_f[MAXHOST];
    char rserv_f[MAXSERV];
    char rhost_b[MAXHOST];
    char rserv_b[MAXSERV];
    bool backend_initialized;
    int backend_retries;
    enum {
        STATE_INIT = 0,
        STATE_ACME_MAYBE,
        STATE_ACME,
        STATE_PROXY_INIT,
        STATE_PROXY,
        STATE_CLOSING,
        STATE_DONE
    } state;
#if defined(USE_GNUTLS)
    gnutls_session_t tls;
    gnutls_certificate_credentials_t cred;
#elif defined(USE_OPENSSL)
    SSL *ssl;
#elif defined(USE_MBEDTLS)
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config cnf;
    mbedtls_x509_crt crt;
    mbedtls_pk_context key;
#endif
    char ident[0x100];
    char auth[0x30];
    struct client *prev, *next;
} client_t;

typedef struct controller {
    unsigned int id;
    ev_io io_send;
    ev_io io_recv;
    int fd;
    ev_timer timer;
    ev_tstamp timestamp;
    buffer_t buf_recv;
    buffer_t buf_send;
    bool done;
    struct controller *prev, *next;
} controller_t;

typedef struct worker {
    ev_io io;
    ev_child child;
    ev_timer timer;
    ev_signal sigint;
    ev_signal sigterm;
    ev_tstamp timestamp;
    pid_t pid;
    int sv[2];
    bool shutdown;
    bool terminate;
    struct worker *prev, *next;
} worker_t;

typedef struct listener {
    ev_io io;
    struct listener *next;
} listener_t;

typedef struct str {
    char *str;
    struct str *prev, *next;
} str_t;

static struct globs {
    bool daemon;
    bool stop;
    bool syslog;
    unsigned loglevel;
    char *logfilename;
    FILE *logfile;
    int family;
    unsigned proxy;
    unsigned num_workers;
    unsigned max_auths;
    char **argv;
    char *progname;
    char *chroot;
    char *pidfile;
    char *socket;
    mode_t sockmode;
    int sockfd;
#if HAVE_MAP_DEVZERO
    int devzero;
#endif
    int pipefd[2];
    char *user;
    uid_t uid;
    char *group;
    gid_t gid;
    str_t *bind;
    str_t *connect;
    bool auths_touched;
    controller_t *controllers;
    listener_t *listeners;
    client_t *clients;
    worker_t *workers;
#if defined(USE_OPENSSL)
    SSL_CTX *ssl_ctx;
    BIO_METHOD *bio_meth;
    int ssl_idx;
    int bio_idx;
#elif defined(USE_MBEDTLS)
    unsigned char *crt;
    unsigned char *key;
    unsigned int crt_len;
    unsigned int key_len;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
#endif
    ev_io controller;
    ev_cleanup cleanup;
    ev_signal sigint;
    ev_signal sigterm;
    ev_timer timer;
 } g = {
    .daemon = false,
    .stop = false,
    .syslog = false,
    .loglevel = 0,
    .logfilename = NULL,
    .logfile = NULL,
    .family = AF_UNSPEC,
    .proxy = 1,
    .num_workers = 2,
    .max_auths = 100,
    .progname = NULL,
    .chroot = NULL,
    .pidfile = NULL,
    .socket = NULL,
    .sockmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH,
    .sockfd = -1,
#if HAVE_MAP_DEVZERO
    .devzero = -1,
#endif
    .pipefd = {-1, -1},
    .user = NULL,
    .uid = 0,
    .group = NULL,
    .gid = 0,
    .bind = NULL,
    .connect = NULL,
    .auths_touched = false,
    .controllers = NULL,
    .listeners = NULL,
    .clients = NULL,
    .workers = NULL,
#if defined(USE_OPENSSL)
    .ssl_ctx = NULL,
    .bio_meth = NULL,
    .ssl_idx = -1,
    .bio_idx = -1,
#elif defined(USE_MBEDTLS)
    .crt = NULL,
    .key = NULL,
    .crt_len = 0,
    .key_len = 0
#endif
};

static struct shm {
    sem_t sem;
    sem_t logsem;
    bool shutdown;
    auth_t *auths;
    auth_t *avail;
    auth_t pool[1];
} *g_shm = NULL;
static size_t g_shm_size = 0;

static char *safe_strncpy(char *dst, const char *src, size_t n)
{
    size_t i;
    for (i = 0; i + 1 < n && src[i] != 0; i++)
        dst[i] = src[i];
    if (i < n)
        dst[i] = 0;
    return dst;
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    else
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_closeonexec(int fd)
{
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1)
        return -1;
    else
        return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int parse_addr(const char *s, int flags, int family, struct addrinfo **a)
{
    int rc;
    char *service;
    char *node;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = flags;
    hints.ai_family = family;

    node = s ? strdup(s) : NULL;
    if (s && !node)
        return EAI_MEMORY;

    service = node ? strrchr(node, '@') : NULL;
    if (service)
        *service++ = '\0';
    if (!node || strlen(node))
        rc = getaddrinfo(node, service ? service : "443", &hints, a);
    else
        rc = EAI_NONAME;
    free(node);
    return rc;
}

static void syslog_init() {
    static char buf[0x80];
    snprintf(buf, sizeof(buf), "%s/%ld", g.progname, (long)getpid());
    openlog(buf, 0, LOG_DAEMON);
    g.syslog = true;
}

static ssize_t buf_getline(buffer_t *b, char *line, size_t len)
{
    size_t n = 0;
    size_t bn = b->n;
    size_t rp = b->rp;
    while (n + 1 < len && bn > 0) {
        line[n] = b->data[rp++];
        if (rp >= sizeof(b->data))
            rp = 0;
        bn--;
        if (line[n] == '\n')
            break;
        n++;
    }
    if (n + 1 >= len)
        return -1;
    else if (line[n] == '\n') {
        line[n] = '\0';
        b->rp = rp;
        b->n = bn;
        return n;
    } else
        return 0;
}

static size_t buf_put(buffer_t *b, const void *data, size_t len)
{
    size_t n = 0;
    while (n < len && b->n < sizeof(b->data)) {
        b->data[b->wp++] = ((uint8_t *)data)[n];
        if (b->wp >= sizeof(b->data))
            b->wp = 0;
        n++;
        b->n++;
    }
    if (n == 0 && len > 0) {
        errno = EAGAIN;
        return -1;
    }
    return n;
}

static size_t buf_puts(buffer_t *b, const char *data)
{
    return buf_put(b, data, strlen(data));
}

static ssize_t buf_readv(int fd, buffer_t *b)
{
    ssize_t n;
    if (b->n >= sizeof(b->data)) {
        return -2;
    } else if (b->wp >= b->rp) {
        struct iovec iov[2];
        iov[0].iov_base = b->data + b->wp;
        iov[0].iov_len = sizeof(b->data) - b->wp;
        iov[1].iov_base = b->data;
        iov[1].iov_len = b->rp;
        n = readv(fd, iov, 2);
    } else
        n = read(fd, b->data + b->wp, b->rp - b->wp);
    if (n > 0) {
        b->n += n;
        b->wp += n;
        if (b->wp >= sizeof(b->data))
            b->wp -= sizeof(b->data);
    }
    return n;
}

static ssize_t buf_writev(int fd, buffer_t *b)
{
    ssize_t n;
    if (b->n == 0) {
        return 0;
    } else if (b->rp >= b->wp) {
        struct iovec iov[2];
        iov[0].iov_base = b->data + b->rp;
        iov[0].iov_len = sizeof(b->data) - b->rp;
        iov[1].iov_base = b->data;
        iov[1].iov_len = b->wp;
        n = writev(fd, iov, 2);
    } else
        n = write(fd, b->data + b->rp, b->wp - b->rp);
    if (n > 0) {
        b->n -= n;
        b->rp += n;
        if (b->rp >= sizeof(b->data))
            b->rp -= sizeof(b->data);
    }
    return n;
}

int auth_lock(unsigned int timeout_ms) {
    struct timespec ts;
    int rc = clock_gettime(CLOCK_REALTIME, &ts);
    if (rc != 0) {
        warn("auth_lock: clock_gettime");
        return rc;
    }
    ts.tv_nsec += timeout_ms * 1000000L;
    while (ts.tv_nsec >= 1000000000L) {
        ts.tv_nsec -= 1000000000L;
        ts.tv_sec++;
    }
    rc = sem_timedwait(&g_shm->sem, &ts);
    if (rc != 0)
        warn("auth_lock: sem_timedwait");
    return rc;
}

int auth_unlock(void) {
    int rc = sem_post(&g_shm->sem);
    if (rc != 0)
        warn("auth_unlock: sem_post");
    return rc;
}

auth_t *get_auth(const char *ident)
{
    auth_t *a;
    if (auth_lock(100) != 0)
        return NULL;
    for (a = g_shm->auths; a; ) {
        int c = strcasecmp(ident, a->ident);
        if (c < 0)
            a = a->left;
        else if (c > 0)
            a = a->right;
        else
            break;
    }
    auth_unlock();
    return a;
}

#if defined(USE_GNUTLS)
int auth_crt(const char *ident, const uint8_t *id, size_t id_len,
        gnutls_datum_t *crt, gnutls_datum_t *key)
{
    gnutls_x509_privkey_t k;
    gnutls_x509_crt_t c;
    struct addrinfo *ai;
    uint8_t serial[0x10];
    uint8_t keyid[0x100];
    size_t keyid_size = sizeof(keyid);
    time_t now = time(NULL);
    int rc;

    rc = gnutls_x509_privkey_init(&k);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_privkey_init: %s", gnutls_strerror(rc));
        return -1;
    }

    rc = gnutls_x509_privkey_generate(k, GNUTLS_PK_EC,
            GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_privkey_generate: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        return -1;
    }

    rc = gnutls_x509_crt_init(&c);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_init: %s", gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        return -1;
    }

    rc = gnutls_x509_crt_set_version(c, 3);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_version: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_rnd(GNUTLS_RND_NONCE, serial, sizeof(serial));
    serial[0] &= 0x7F;
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_rnd: %s", gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_set_serial(c, serial, sizeof(serial));
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_serial: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_set_activation_time(c, now - 30*24*60*60);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_activation_time: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_set_expiration_time(c, now + 30*24*60*60);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_expiration_time: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_set_basic_constraints(c, 1, -1);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_basic_constraints: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = parse_addr(ident, AI_NUMERICHOST | AI_NUMERICSERV, AF_UNSPEC, &ai);
    if (rc == 0 && ai->ai_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)ai->ai_addr;
        rc = gnutls_x509_crt_set_subject_alt_name(c, GNUTLS_SAN_IPADDRESS,
                &addr->sin_addr, sizeof(addr->sin_addr), GNUTLS_FSAN_APPEND);
        freeaddrinfo(ai);
    } else if (rc == 0 && ai->ai_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ai->ai_addr;
        rc = gnutls_x509_crt_set_subject_alt_name(c, GNUTLS_SAN_IPADDRESS,
                &addr->sin6_addr, sizeof(addr->sin6_addr), GNUTLS_FSAN_APPEND);
        freeaddrinfo(ai);
    } else {
        if (rc == 0)
            freeaddrinfo(ai);
        rc = gnutls_x509_crt_set_subject_alt_name(c, GNUTLS_SAN_DNSNAME,
                ident, strlen(ident), GNUTLS_FSAN_APPEND);
    }

    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_subject_alt_name: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_set_extension_by_oid(c, "1.3.6.1.5.5.7.1.31",
            id, id_len, 1);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_extension_by_oid: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_set_key(c, k);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_key: %s", gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_set_key_usage(c, GNUTLS_KEY_DIGITAL_SIGNATURE |
                GNUTLS_KEY_KEY_CERT_SIGN);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_key_usage: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_get_key_id(c, 0, keyid, &keyid_size);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_get_key_id: %s", gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_set_subject_key_id(c, keyid, keyid_size);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_subject_key_id: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_set_authority_key_id(c, keyid, keyid_size);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_set_authority_key_id: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_sign2(c, c, k, GNUTLS_DIG_SHA256, 0);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_sign2: %s", gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_privkey_export2(k, GNUTLS_X509_FMT_DER, key);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_privkey_export2: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        return -1;
    }

    rc = gnutls_x509_crt_export2(c, GNUTLS_X509_FMT_DER, crt);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("auth_crt: gnutls_x509_crt_export2: %s",
                gnutls_strerror(rc));
        gnutls_x509_privkey_deinit(k);
        gnutls_x509_crt_deinit(c);
        gnutls_free(key->data);
        return -1;
    }

    gnutls_x509_privkey_deinit(k);
    gnutls_x509_crt_deinit(c);
    return 0;
}
#elif defined(USE_OPENSSL)
int auth_crt(const char *ident, const uint8_t *id, size_t id_len,
        unsigned char **crt, unsigned int *crt_len,
        unsigned char **key, unsigned int *key_len)
{
    EVP_PKEY_CTX *pc = NULL;
    EVP_PKEY *k = NULL;
    X509 *c = NULL;
    X509V3_CTX ctx;
    BIGNUM *bn = NULL;
    ASN1_OBJECT *acmeid = NULL;
    ASN1_OCTET_STRING *idos = NULL;
    X509_EXTENSION *ext = NULL;
    char *san = NULL;
    struct addrinfo *ai = NULL;
    time_t now = time(NULL);
    int ret = -1;
    int rc;

    idos = ASN1_OCTET_STRING_new();
    if (!idos || !ASN1_OCTET_STRING_set(idos, id, id_len)) {
        openssl_error("auth_crt");
        goto out;
    }

    pc = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pc || !EVP_PKEY_keygen_init(pc)
            || !EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pc, NID_X9_62_prime256v1)
            || !EVP_PKEY_keygen(pc, &k)) {
        openssl_error("auth_crt");
        goto out;
    }

    bn = BN_new();
    if (!bn || !BN_rand(bn, 127, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
        openssl_error("auth_crt");
        goto out;
    }

    c = X509_new();
    if (!c || !X509_set_version(c, 2)
            || !BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(c))
            || !ASN1_TIME_adj(X509_getm_notBefore(c), now, -30, 0)
            || !ASN1_TIME_adj(X509_getm_notAfter(c), now, 30, 0)
            || !X509_set_pubkey(c, k)) {
        openssl_error("auth_crt");
        goto out;
    }

    rc = parse_addr(ident, AI_NUMERICHOST | AI_NUMERICSERV, AF_UNSPEC, &ai);
    if (rc == 0 && (ai->ai_family == AF_INET || ai->ai_family == AF_INET6)) {
        freeaddrinfo(ai);
        if (asprintf(&san, "IP:%s", ident) < 0) {
            warnx("auth_crt: asprintf failed");
            san = NULL;
            goto out;
        }
    } else {
        if (rc == 0)
            freeaddrinfo(ai);
        if (asprintf(&san, "DNS:%s", ident) < 0) {
            warnx("auth_crt: asprintf failed");
            san = NULL;
            goto out;
        }
    }

    acmeid = OBJ_txt2obj("1.3.6.1.5.5.7.1.31",1);
    if (!acmeid) {
        openssl_error("auth_crt");
        goto out;
    }

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, c, c, NULL, NULL, 0);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (!ext || !X509_add_ext(c, ext, -1)) {
        openssl_error("auth_crt");
        goto out;
    }
    X509_EXTENSION_free(ext);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
            "critical, keyCertSign, digitalSignature");
    if (!ext || !X509_add_ext(c, ext, -1)) {
        openssl_error("auth_crt");
        goto out;
    }
    X509_EXTENSION_free(ext);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints,
            "critical,CA:TRUE");
    if (!ext || !X509_add_ext(c, ext, -1)) {
        openssl_error("auth_crt");
        goto out;
    }
    X509_EXTENSION_free(ext);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier,
            "hash");
    if (!ext || !X509_add_ext(c, ext, -1)) {
        openssl_error("auth_crt");
        goto out;
    }
    X509_EXTENSION_free(ext);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier,
            "keyid,issuer");
    if (!ext || !X509_add_ext(c, ext, -1)) {
        openssl_error("auth_crt");
        goto out;
    }
    X509_EXTENSION_free(ext);

    ext = X509_EXTENSION_create_by_OBJ(NULL, acmeid, 1, idos);
    if (!ext || !X509_add_ext(c, ext, -1)) {
        openssl_error("auth_crt");
        goto out;
    }

    if (!X509_sign(c, k, EVP_sha256())) {
        openssl_error("auth_crt");
        goto out;
    }

    *crt = NULL;
    rc = i2d_X509(c, crt);
    if (rc < 0) {
        openssl_error("auth_crt");
        goto out;
    }
    *crt_len = rc;

    *key = NULL;
    rc = i2d_PrivateKey(k, key);
    if (rc < 0) {
        openssl_error("auth_crt");
        goto out;
    }
    *key_len = rc;

    ret = 0;
out:
    EVP_PKEY_CTX_free(pc);
    EVP_PKEY_free(k);
    X509_free(c);
    BN_free(bn);
    ASN1_OBJECT_free(acmeid);
    ASN1_OCTET_STRING_free(idos);
    X509_EXTENSION_free(ext);
    free(san);
    if (ret != 0) {
        OPENSSL_free(*key);
        *key = NULL;
        *key_len = 0;
        OPENSSL_free(*crt);
        *crt = NULL;
        *crt_len = 0;
    }
    return ret;
}
#elif defined(USE_MBEDTLS)
int auth_crt(const char *ident, const uint8_t *id, size_t id_len,
        unsigned char **crt, unsigned int *crt_len,
        unsigned char **key, unsigned int *key_len)
{
    size_t buf_len = 0x400;
    unsigned char *buf = NULL;
    struct addrinfo *ai;
    uaddr_t addr;
    struct tm t;
    time_t tnb = time(NULL) - 30*24*3600;
    time_t tna = tnb + 60*24*3600;
    char nb[MBEDTLS_X509_RFC5280_UTC_TIME_LEN] = "";
    char na[MBEDTLS_X509_RFC5280_UTC_TIME_LEN] = "";
    int ret = -1;
    int rc;
    mbedtls_x509write_cert c;
    mbedtls_pk_context k;
    mbedtls_mpi sn;

    strftime(nb, sizeof(nb), "%Y%m%d%H%M%S", gmtime_r(&tnb, &t));
    strftime(na, sizeof(na), "%Y%m%d%H%M%S", gmtime_r(&tna, &t));

    mbedtls_x509write_crt_init(&c);
    mbedtls_pk_init(&k);
    mbedtls_mpi_init(&sn);

    rc = mbedtls_mpi_fill_random(&sn, 16, mbedtls_ctr_drbg_random, &g.ctr_drbg);
    if (rc) {
        warnx("auth_crt: mbedtls_mpi_fill_random: %s", _mbedtls_strerror(rc));
        goto out;
    }

    rc = mbedtls_mpi_set_bit(&sn, 127, 0);
    if (rc) {
        warnx("auth_crt: mbedtls_mpi_set_bit: %s", _mbedtls_strerror(rc));
        goto out;
    }

    const mbedtls_pk_info_t *pki = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    if (!pki) {
        warnx("auth_crt: mbedtls_pk_info_from_type: %s", _mbedtls_strerror(rc));
        goto out;
    }

    rc = mbedtls_pk_setup(&k, pki);
    if (rc) {
        warnx("auth_crt: mbedtls_pk_setup: %s", _mbedtls_strerror(rc));
        goto out;
    }

    rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(k),
            mbedtls_ctr_drbg_random, &g.ctr_drbg);
    if (rc) {
        warnx("auth_crt: mbedtls_ecp_gen_key: %s", _mbedtls_strerror(rc));
        goto out;
    }

    mbedtls_x509write_crt_set_version(&c, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&c, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&c, &k);
    mbedtls_x509write_crt_set_issuer_key(&c, &k);

    rc = mbedtls_x509write_crt_set_basic_constraints(&c, 1, -1);
    if (rc) {
        warnx("auth_crt: mbedtls_x509write_crt_set_basic_constraints: %s",
                _mbedtls_strerror(rc));
        goto out;
    }

    rc = mbedtls_x509write_crt_set_serial(&c, &sn);
    if (rc) {
        warnx("auth_crt: mbedtls_x509write_crt_set_serial: %s",
                _mbedtls_strerror(rc));
        goto out;
    }

    rc = mbedtls_x509write_crt_set_validity(&c, nb, na);
    if (rc) {
        warnx("auth_crt: mbedtls_x509write_crt_set_validity: %s",
                _mbedtls_strerror(rc));
        goto out;
    }

    rc = parse_addr(ident, AI_NUMERICHOST | AI_NUMERICSERV, AF_UNSPEC, &ai);
    if (rc == 0) {
        memcpy(&addr.addr, ai->ai_addr, ai->ai_addrlen);
        addr.len = ai->ai_addrlen;
        freeaddrinfo(ai);
    } else
        addr.len = 0;

    while (1) {
        buf_len *= 2;
        free(buf);
        buf = calloc(1, buf_len);
        if (!buf) {
            warn("auth_crt: calloc");
            goto out;
        }
        unsigned char *p = buf + buf_len;
        size_t len = 0;
        const unsigned char *data = NULL;
        size_t data_len = 0;
        unsigned char tag;

        if (addr.len) {
            tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7;
            if (addr.addr.sa.sa_family == AF_INET) {
                data = (unsigned char *)&addr.addr.v4.sin_addr;
                data_len = sizeof(addr.addr.v4.sin_addr);
            } else if (addr.addr.sa.sa_family == AF_INET6) {
                data = (unsigned char *)&addr.addr.v6.sin6_addr;
                data_len = sizeof(addr.addr.v6.sin6_addr);
            }
        }
        if (!data || !data_len) {
            tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2;
            data = (const unsigned char *)ident;
            data_len = strlen(ident);
        }

        rc = mbedtls_asn1_write_raw_buffer(&p, buf, data, data_len);
        if (rc >= 0)
            len += rc;
        else if (rc == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            break;
        else {
            warnx("auth_crt: mbedtls_asn1_write_raw_buffer: %s",
                    _mbedtls_strerror(rc));
            goto out;
        }
        rc = mbedtls_asn1_write_len(&p, buf, data_len);
        if (rc >= 0)
            len += rc;
        else if (rc == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            break;
        else {
            warnx("auth_crt: mbedtls_asn1_write_len: %s",
                    _mbedtls_strerror(rc));
            goto out;
        }
        rc = mbedtls_asn1_write_tag(&p, buf, tag);
        if (rc >= 0)
            len += rc;
        else if (rc == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            break;
        else {
            warnx("auth_crt: mbedtls_asn1_write_tag: %s",
                    _mbedtls_strerror(rc));
            goto out;
        }

        if (rc == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            continue;
        rc = mbedtls_asn1_write_len(&p, buf, len);
        if (rc >= 0)
            len += rc;
        else if (rc == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            continue;
        else {
            warnx("auth_crt: mbedtls_asn1_write_len: %s",
                    _mbedtls_strerror(rc));
            goto out;
        }
        rc = mbedtls_asn1_write_tag(&p, buf,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (rc >= 0)
            len += rc;
        else if (rc == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            continue;
        else {
            warnx("auth_crt: mbedtls_asn1_write_tag: %s",
                    _mbedtls_strerror(rc));
            goto out;
        }
        rc = mbedtls_x509write_crt_set_extension(&c,
                MBEDTLS_OID_SUBJECT_ALT_NAME,
                MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
                1, buf + buf_len - len, len);
        if (rc) {
            warnx("auth_crt: mbedtls_x509write_crt_set_extension: %s",
                    _mbedtls_strerror(rc));
            goto out;
        }
        break;
    }
    rc = mbedtls_x509write_crt_set_extension(&c,
            // http://oid-info.com/get/1.3.6.1.5.5.7.1.31
            // pe(1) id-pe-acmeIdentifier(31)
            MBEDTLS_OID_PKIX "\x01\x1F",
            MBEDTLS_OID_SIZE(MBEDTLS_OID_PKIX "\x01\x1F"),
            1, id, id_len);
    if (rc) {
        warnx("auth_crt: mbedtls_x509write_crt_set_extension: %s",
                _mbedtls_strerror(rc));
        goto out;
    }

    rc = mbedtls_x509write_crt_set_key_usage(&c,
            MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_CERT_SIGN);
    if (rc) {
        warnx("auth_crt: mbedtls_x509write_crt_set_key_usage: %s",
                _mbedtls_strerror(rc));
        goto out;
    }

    rc = mbedtls_x509write_crt_set_subject_key_identifier(&c);
    if (rc) {
        warnx("auth_crt: mbedtls_x509write_crt_set_subject_key_identifier: %s",
                _mbedtls_strerror(rc));
        goto out;
    }

    rc = mbedtls_x509write_crt_set_authority_key_identifier(&c);
    if (rc) {
        warnx("auth_crt: mbedtls_x509write_crt_set_authority_key_identifier:"
                " %s", _mbedtls_strerror(rc));
        goto out;
    }

    while (1) {
        rc = mbedtls_x509write_crt_der(&c, buf, buf_len,
                mbedtls_ctr_drbg_random, &g.ctr_drbg);
        if (rc > 0) {
            *crt_len = rc;
            *crt = calloc(1, *crt_len);
            if (!*crt) {
                warn("auth_crt: calloc");
                goto out;
            }
            memcpy(*crt, buf + buf_len - *crt_len, *crt_len);
            break;
        } else if (rc == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
            free(buf);
            buf_len *= 2;
            buf = calloc(1, buf_len);
            if (!buf) {
                warn("auth_crt: calloc");
                goto out;
            }
        } else {
            warnx("auth_crt: mbedtls_x509write_crt_der: %s",
                    _mbedtls_strerror(rc));
            goto out;
        }
    }

    while (1) {
        rc = mbedtls_pk_write_key_der(&k, buf, buf_len);
        if (rc > 0) {
            *key_len = rc;
            *key = calloc(1, *key_len);
            if (!*key) {
                warn("auth_crt: calloc");
                goto out;
            }
            memcpy(*key, buf + buf_len - *key_len, *key_len);
            break;
        } else if (rc == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
            free(buf);
            buf_len *= 2;
            buf = calloc(1, buf_len);
            if (!buf) {
                warn("auth_crt: calloc");
                goto out;
            }
        } else {
            warnx("auth_crt: mbedtls_pk_write_key_der: %s",
                    _mbedtls_strerror(rc));
            goto out;
        }
    }

    ret = 0;
out:
    mbedtls_x509write_crt_free(&c);
    mbedtls_pk_free(&k);
    mbedtls_mpi_free(&sn);
    free(buf);
    if (ret != 0) {
        free(*key);
        *key = NULL;
        *key_len = 0;
        free(*crt);
        *crt = NULL;
        *crt_len = 0;
    }
    return ret;
}
#endif

static void controller_done(EV_P_ controller_t *c, bool drain)
{
    c->done = true;

    if (drain) {
        c->buf_send.n = 0;
        c->buf_send.rp = 0;
        c->buf_send.wp = 0;
    }

    if (c->fd != -1) {
        ev_io_stop(EV_A_ &c->io_recv);
        if (c->buf_send.n == 0) {
            ev_io_stop(EV_A_ &c->io_send);
            infox("controller %08x: connection closed", c->id);
            shutdown(c->fd, SHUT_RDWR);
            close(c->fd);
            c->fd = -1;
        } else
            ev_io_start(EV_A_ &c->io_send);
    }

    if (c->fd == -1) {
        debugx("controller %08x: removed", c->id);
        ev_timer_stop(EV_A_ &c->timer);
        SGLIB_DL_LIST_DELETE(controller_t, g.controllers, c, prev, next);
        free(c);
    }
}

static void cb_controller_timer(EV_P_ ev_timer *w, int revents)
{
    controller_t *c = (controller_t *)(((uint8_t *)w) -
            offsetof(controller_t, timer));

    if ((revents & EV_TIMER) == 0)
        return;

    ev_tstamp after = c->timestamp - ev_now(EV_A) + 5;
    if (after < 0.0) {
        infox("controller %08x: disconnecting due to timeout", c->id);
        controller_done(EV_A_ c, true);
    } else {
        ev_timer_set(w, after, 0.0);
        ev_timer_start(EV_A_ w);
    }
}

static void controller_handle_cmd(controller_t *c, char *line, ev_tstamp ts)
{
    char *saveptr;
    char *cmd = strtok_r(line, " \t", &saveptr);
    char *ident = strtok_r(NULL, " \t", &saveptr);
    char *auth = strtok_r(NULL, " \t", &saveptr);
    size_t ident_len = ident ? strlen(ident) : 0;
    struct addrinfo *ai;
    char arpa[80];

    if (!cmd || (strcmp(cmd, "auth") && strcmp(cmd, "unauth"))) {
        buf_puts(&c->buf_send,
                "ERR usage: auth <ident> <auth> | unauth <ident>\n");
        return;
    }

    if (ident_len == 0 || ident_len > 250 ||
            ident_len != strspn(ident, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz0123456789-_.:")) {
        buf_puts(&c->buf_send, "ERR invalid ident\n");
        return;
    }

    memset(arpa, 0, sizeof(arpa));
    if (parse_addr(ident, AI_NUMERICHOST|AI_NUMERICSERV, AF_UNSPEC, &ai) == 0) {
        if (ai->ai_family == AF_INET) {
            struct sockaddr_in *ain = (struct sockaddr_in *)ai->ai_addr;
            uint32_t addr = ntohl(ain->sin_addr.s_addr);
            snprintf(arpa, sizeof(arpa), "%d.%d.%d.%d.in-addr.arpa",
                    addr & 0xFF, (addr >> 8) & 0xFF,
                    (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
        } else if (ai->ai_family == AF_INET6) {
            struct sockaddr_in6 *ain6 = (struct sockaddr_in6 *)ai->ai_addr;
            unsigned char *addr = ain6->sin6_addr.s6_addr;
            char *p = arpa;
            for (int i = sizeof(ain6->sin6_addr.s6_addr) - 1; i >= 0 &&
                    p < arpa + sizeof(arpa) - 5; i--) {
                *p++ = "0123456789abcdef"[addr[i] & 0xF];
                *p++ = '.';
                *p++ = "0123456789abcdef"[(addr[i] >> 4) & 0xF];
                *p++ = '.';
            }
            strncat(p, "ip6.arpa", sizeof(arpa) - (p - arpa) - 1);
        }
        freeaddrinfo(ai);
    }

    if (strcmp(cmd, "auth") == 0) {
        size_t id_len;
        uint8_t id[0x22] = {
            0x04, // OCTET_STRING
            0x20, // LENGTH
        };

        if (!auth || base642bin(id + 2, sizeof(id) - 2, auth, strlen(auth),
                    NULL, &id_len, NULL, base64_VARIANT_URLSAFE_NO_PADDING)
                || id_len != sizeof(id) - 2) {
            buf_puts(&c->buf_send, "ERR invalid auth\n");
            return;
        }

        auth_t *a = get_auth(arpa[0] ? arpa : ident);
        if (a && strcmp(a->auth, auth) == 0) {
            buf_puts(&c->buf_send, "ERR already inserted\n");
            return;
        }

#if defined(USE_GNUTLS)
        gnutls_datum_t crt = {NULL, 0}, key = {NULL, 0};
        if (auth_crt(ident, id, sizeof(id), &crt, &key) != 0) {
#elif defined(USE_OPENSSL) || defined(USE_MBEDTLS)
        struct {
            unsigned char *data;
            unsigned int size;
        } crt = {NULL, 0}, key = {NULL, 0};
        if (auth_crt(ident, id, sizeof(id), &crt.data, &crt.size,
                    &key.data, &key.size) != 0) {
#endif
            buf_puts(&c->buf_send, "ERR crypto failure (auth_crt)\n");
            return;
        }
        if (crt.size > sizeof(a->crt) || key.size > sizeof(a->key)) {
            buf_puts(&c->buf_send, "ERR crypto failure (crt/key size)\n");
#if defined(USE_GNUTLS)
            gnutls_free(key.data);
            gnutls_free(crt.data);
#elif defined(USE_OPENSSL)
            OPENSSL_free(key.data);
            OPENSSL_free(crt.data);
#elif defined(USE_MBEDTLS)
            free(key.data);
            free(crt.data);
#endif
            return;
        }

        if (auth_lock(100) != 0) {
            buf_puts(&c->buf_send, "ERR locked\n");
#if defined(USE_GNUTLS)
            gnutls_free(key.data);
            gnutls_free(crt.data);
#elif defined(USE_OPENSSL)
            OPENSSL_free(key.data);
            OPENSSL_free(crt.data);
#elif defined(USE_MBEDTLS)
            free(key.data);
            free(crt.data);
#endif
            return;
        }

        if (!a) {
            if (!g_shm->avail) {
                warnx("controller %08x: too many auths", c->id);
                buf_puts(&c->buf_send, "ERR too many auths\n");
                auth_unlock();
#if defined(USE_GNUTLS)
                gnutls_free(key.data);
                gnutls_free(crt.data);
#elif defined(USE_OPENSSL)
                OPENSSL_free(key.data);
                OPENSSL_free(crt.data);
#elif defined(USE_MBEDTLS)
                free(key.data);
                free(crt.data);
#endif
                return;
            }
            a = g_shm->avail;
            SGLIB_DL_LIST_DELETE(auth_t, g_shm->avail, a, left, right);
            safe_strncpy(a->ident, arpa[0] ? arpa : ident, sizeof(a->ident));
            sglib_auth_t_add(&g_shm->auths, a);
            g.auths_touched = true;
        }
        safe_strncpy(a->auth, auth, sizeof(a->auth));
        memcpy(a->key, key.data, key.size);
        a->key_size = key.size;
        memcpy(a->crt, crt.data, crt.size);
        a->crt_size = crt.size;
        a->timestamp = ts;
        auth_unlock();
#if defined(USE_GNUTLS)
        gnutls_free(key.data);
        gnutls_free(crt.data);
#elif defined(USE_OPENSSL)
        OPENSSL_free(key.data);
        OPENSSL_free(crt.data);
#elif defined(USE_MBEDTLS)
        free(key.data);
        free(crt.data);
#endif
        if (arpa[0])
            noticex("controller %08x: new auth %s for %s (%s)", c->id, auth,
                    ident, arpa);
        else
            noticex("controller %08x: new auth %s for %s", c->id, auth, ident);
    } else if (strcmp(cmd, "unauth") == 0) {
        if (auth) {
            buf_puts(&c->buf_send, "ERR too many parameters\n");
            return;
        }

        auth_t *a = get_auth(arpa[0] ? arpa : ident);
        if (!a) {
            infox("controller %08x: failed to remove missing auth for %s",
                    c->id, ident);
            buf_puts(&c->buf_send, "ERR not found\n");
            return;
        }

        if (auth_lock(100) != 0) {
            buf_puts(&c->buf_send, "ERR locked\n");
            return;
        }

        sglib_auth_t_delete(&g_shm->auths, a);
        SGLIB_DL_LIST_ADD(auth_t, g_shm->avail, a, left, right);
        g.auths_touched = true;
        auth_unlock();
        if (arpa[0])
            noticex("controller %08x: removed auth for %s (%s)", c->id, ident,
                    arpa);
        else
            noticex("controller %08x: removed auth for %s", c->id, ident);
    }
    buf_puts(&c->buf_send, "OK\n");
}

static void cb_controller_recv(EV_P_ ev_io *w, int revents)
{
    controller_t *c = (controller_t *)(((uint8_t *)w) -
            offsetof(controller_t, io_recv));

    if ((revents & EV_READ) == 0)
        return;

    c->timestamp = ev_now(EV_A);

    switch (buf_readv(c->fd, &c->buf_recv)) {
        case 0:
            controller_done(EV_A_ c, true);
            return;

        case -1:
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                warn("controller %08x: failed to receive", c->id);
                controller_done(EV_A_ c, true);
                return;
            }
            break;

        case -2:
            buf_puts(&c->buf_send, "ERR too long\n");
            controller_done(EV_A_ c, false);
            return;

        default:
            break;
    }

    char line[0x200];
    switch (buf_getline(&c->buf_recv, line, sizeof(line))) {
        case -1:
            buf_puts(&c->buf_send, "ERR too long\n");
            controller_done(EV_A_ c, false);
            return;

        case 0:
            return;

        default:
            controller_handle_cmd(c, line, ev_now(EV_A));
            ev_io_start(EV_A_ &c->io_send);
            return;
    }
}

static void cb_controller_send(EV_P_ ev_io *w, int revents)
{
    controller_t *c = (controller_t *)(((uint8_t *)w) -
            offsetof(controller_t, io_send));

    if ((revents & EV_WRITE) == 0)
        return;

    switch (buf_writev(c->fd, &c->buf_send)) {
        case 0:
            ev_io_stop(EV_A_ &c->io_send);
            break;

        case -1:
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                warn("controller %08x: failed to send", c->id);
                controller_done(EV_A_ c, true);
                return;
            }
            break;

        default:
            break;
    }
    if (c->done) {
        controller_done(EV_A_ c, false);
        return;
    } else if (c->fd != -1)
        ev_io_start(EV_A_ &c->io_recv);
}

static void cb_controller_accept(EV_P_ ev_io *w, int revents)
{
    if ((revents & EV_READ) == 0)
        return;

    if (g_shm->shutdown) {
        ev_io_stop(EV_A_ w);
        return;
    }

    controller_t *c = calloc(1, sizeof(controller_t));
    if (!c) {
        warn("control accept: calloc");
        return;
    }
    c->id = 0xFFFFFFFF & (unsigned int)random();

    int fd = accept(w->fd, NULL, NULL);
    if (fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            warn("control accept");
        free(c);
        return;
    }

    noticex("new controller %08x: handling connection", c->id);

    if (set_nonblocking(fd)) {
        warn("controller %08x: failed to set O_NONBLOCK, closing", c->id);
        close(fd);
        free(c);
        return;
    }

    SGLIB_DL_LIST_ADD(controller_t, g.controllers, c, prev, next);
    c->fd = fd;

    c->timestamp = ev_now(EV_A);
    ev_init(&c->timer, cb_controller_timer);
    ev_set_priority(&c->timer, -1);
    ev_invoke(EV_A_ &c->timer, EV_TIMER);

    ev_io_init(&c->io_recv, cb_controller_recv, fd, EV_READ);
    ev_io_init(&c->io_send, cb_controller_send, fd, EV_WRITE);
    ev_io_start(EV_A_ &c->io_recv);
}

typedef enum {
    DRAIN_NONE = 0,
    DRAIN_FRONTEND,
    DRAIN_BACKEND,
    DRAIN_BOTH
} drain_t;

static void client_done(EV_P_ client_t *c, drain_t drain)
{
    c->state = STATE_DONE;

    if (drain == DRAIN_FRONTEND || drain == DRAIN_BOTH) {
#if HAVE_SPLICE
        c->n_b2f = 0;
#else
        c->buf_b2f.n = 0;
        c->buf_b2f.rp = 0;
        c->buf_b2f.wp = 0;
#endif
    }

    if (drain == DRAIN_BACKEND || drain == DRAIN_BOTH) {
#if HAVE_SPLICE
        c->n_f2b = 0;
#else
        c->buf_f2b.n = 0;
        c->buf_f2b.rp = 0;
        c->buf_f2b.wp = 0;
#endif
    }

    if (c->fd_f != -1) {
        ev_io_stop(EV_A_ &c->io_rxf);
#if HAVE_SPLICE
        if (c->n_b2f <= 0) {
            ev_io_stop(EV_A_ &c->io_b2f0);
            ev_io_stop(EV_A_ &c->io_f2b1);
#else
        if (c->buf_b2f.n == 0) {
#endif
            ev_io_stop(EV_A_ &c->io_txf);
            infox("client %08x: frontend connection closed (rx=%zu tx=%zu)",
                    c->id, c->frx, c->ftx);
            shutdown(c->fd_f, SHUT_RDWR);
            close(c->fd_f);
            c->fd_f = -1;
        } else
            ev_io_start(EV_A_ &c->io_txf);
    }

    if (c->fd_b != -1) {
        ev_io_stop(EV_A_ &c->io_rxb);
#if HAVE_SPLICE
        if (c->n_f2b <= 0) {
            ev_io_stop(EV_A_ &c->io_f2b0);
            ev_io_stop(EV_A_ &c->io_b2f1);
#else
        if (c->buf_f2b.n == 0) {
#endif
            ev_io_stop(EV_A_ &c->io_txb);
            infox("client %08x: backend connection closed (rx=%zu tx=%zu)",
                    c->id, c->brx, c->btx);
            shutdown(c->fd_b, SHUT_RDWR);
            close(c->fd_b);
            c->fd_b = -1;
        } else
            ev_io_start(EV_A_ &c->io_txb);
    }

    if (c->fd_b == -1 && c->fd_f == -1) {
        debugx("client %08x: removed", c->id);
#if HAVE_SPLICE
        close(c->fd_b2f[0]);
        close(c->fd_b2f[1]);
        close(c->fd_f2b[0]);
        close(c->fd_f2b[1]);
#endif
#if defined(USE_GNUTLS)
        if (c->tls)
            gnutls_deinit(c->tls);
        if (c->cred)
            gnutls_certificate_free_credentials(c->cred);
#elif defined(USE_OPENSSL)
        if (c->ssl)
            SSL_free(c->ssl);
#elif defined(USE_MBEDTLS)
        mbedtls_x509_crt_free(&c->crt);
        mbedtls_pk_free(&c->key);
        mbedtls_ssl_free(&c->ssl);
        mbedtls_ssl_config_free(&c->cnf);
#endif
        ev_timer_stop(EV_A_ &c->timer);
        SGLIB_DL_LIST_DELETE(client_t, g.clients, c, prev, next);
        free(c);
    }
}

#if defined(USE_GNUTLS)
static ssize_t tls_pull_func(gnutls_transport_ptr_t p, void *data, size_t size)
{
    client_t *c = (client_t *)p;
    if (!c) {
        gnutls_transport_set_errno(c->tls, EINVAL);
        return -1;
    }
#if EV_MULTIPLICITY
    EV_P = c->loop;
#endif
    ssize_t s = recv(c->fd_f, data, size,
            c->state == STATE_ACME ? 0 : MSG_PEEK);
    if (s == 0) {
        c->state = STATE_CLOSING;
        return 0;
    } else if (s == -1) {
        gnutls_transport_set_errno(c->tls, errno);
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("client %08x: frontend failed to read from %s:%s", c->id,
                    c->rhost_f, c->rserv_f);
            c->state = STATE_CLOSING;
        } else if (c->fd_f != -1 && c->state != STATE_DONE)
            ev_io_start(EV_A_ &c->io_rxf);
        return -1;
    }

    if (c->state == STATE_ACME) {
        c->frx += s;
        return s;
    }

#if HAVE_SPLICE
    s = write(c->fd_f2b[1], data, s);
    if (s > 0)
        c->n_f2b += s;
#else
    s = buf_put(&c->buf_f2b, data, s);
#endif
    if (s == -1) {
        gnutls_transport_set_errno(c->tls, errno);
        return -1;
    } else {
        ssize_t sr = recv(c->fd_f, data, s, 0);
        if (sr > 0)
            c->frx += sr;
        if (sr != s) {
            warn("client %08x: frontend failed to buffer data from %s:%s",
                    c->id, c->rhost_f, c->rserv_f);
            c->state = STATE_CLOSING;
            return 0;
        }
    }
    return s;
}

static ssize_t tls_push_func(gnutls_transport_ptr_t p, const void *data,
        size_t size)
{
    client_t *c = (client_t *)p;
    if (!c) {
        gnutls_transport_set_errno(c->tls, EINVAL);
        return -1;
    }
#if EV_MULTIPLICITY
    EV_P = c->loop;
#endif
    if (c->state != STATE_ACME) {
        // prevent sending data to client until PROXY/ACME decision
        gnutls_transport_set_errno(c->tls, EAGAIN);
        return -1;
    }

#if HAVE_SPLICE
    ssize_t s = write(c->fd_b2f[1], data, size);
    if (s > 0)
        c->n_b2f += s;
#else
    ssize_t s = buf_put(&c->buf_b2f, data, size);
#endif
    if (s == -1) {
        gnutls_transport_set_errno(c->tls, errno);
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("client %08x: frontend failed to buffer data from %s:%s",
                    c->id, c->rhost_f, c->rserv_f);
            c->state = STATE_CLOSING;
            return -1;
        }
    }
    if (c->fd_f != -1)
        ev_io_start(EV_A_ &c->io_txf);
    return s;
}

static int tls_post_client_hello_func(gnutls_session_t s)
{
    client_t *c = (client_t *)gnutls_session_get_ptr(s);

    unsigned int type;
    char name[0x100];
    size_t name_len = sizeof(name)-1;
    memset(name, 0, name_len);

    int rc = gnutls_server_name_get(c->tls, name, &name_len, &type, 0);
    if (rc != GNUTLS_E_SUCCESS)
        return rc;

    gnutls_datum_t protocol;
    rc = gnutls_alpn_get_selected_protocol(c->tls, &protocol);
    if (rc != GNUTLS_E_SUCCESS)
        return rc;

    if (protocol.size != strlen("acme-tls/1") ||
            memcmp("acme-tls/1", protocol.data, protocol.size))
        return GNUTLS_E_APPLICATION_ERROR_MAX;

    auth_t *auth = get_auth(name);
    if (!auth) {
        infox("client %08x: acme-tls/1 handshake: no auth for %s", c->id, name);
        return GNUTLS_E_APPLICATION_ERROR_MAX;
    }

    gnutls_certificate_free_keys(c->cred);
    gnutls_datum_t crt = { .data = auth->crt, .size = auth->crt_size };
    gnutls_datum_t key = { .data = auth->key, .size = auth->key_size };
    rc = gnutls_certificate_set_x509_key_mem(c->cred, &crt, &key,
            GNUTLS_X509_FMT_DER);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("client %08x: acme-tls/1 handshake with auth %s for %s failed: "
                "gnutls_certificate_set_x509_key_mem: %s", c->id, auth->auth,
                auth->ident, gnutls_strerror(rc));
        return rc;
    }

    rc = gnutls_credentials_set(c->tls, GNUTLS_CRD_CERTIFICATE, c->cred);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("client %08x: acme-tls/1 handshake with auth %s for %s failed: "
                "gnutls_credentials_set: %s", c->id, auth->auth, auth->ident,
                gnutls_strerror(rc));
        return rc;
    }

    safe_strncpy(c->auth, auth->auth, sizeof(c->auth));
    safe_strncpy(c->ident, auth->ident, sizeof(c->ident));

#if HAVE_SPLICE
    c->n_f2b = 0;
#else
    c->buf_f2b.n = 0;
    c->buf_f2b.rp = 0;
    c->buf_f2b.wp = 0;
#endif
    c->state = STATE_ACME;

    return GNUTLS_E_SUCCESS;
}
#elif defined(USE_OPENSSL)
static int bio_read(BIO *b, char *data, int size)
{
    client_t *c = (client_t *)BIO_get_ex_data(b, g.bio_idx);
    if (data == NULL)
        return 0;
    BIO_clear_retry_flags(b);
    if (!c) {
        errno = EINVAL;
        return -1;
    }
#if EV_MULTIPLICITY
    EV_P = c->loop;
#endif
    ssize_t s = recv(c->fd_f, data, size,
            c->state == STATE_ACME ? 0 : MSG_PEEK);
    if (s == 0) {
        c->state = STATE_CLOSING;
        return 0;
    } else if (s == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("client %08x: frontend failed to read from %s:%s", c->id,
                    c->rhost_f, c->rserv_f);
            c->state = STATE_CLOSING;
        } else if (c->fd_f != -1 && c->state != STATE_DONE) {
            ev_io_start(EV_A_ &c->io_rxf);
            BIO_set_retry_read(b);
        }
        return -1;
    }

    if (c->state == STATE_ACME) {
        c->frx += s;
        return s;
    }

#if HAVE_SPLICE
    s = write(c->fd_f2b[1], data, s);
    if (s > 0)
        c->n_f2b += s;
#else
    s = buf_put(&c->buf_f2b, data, s);
#endif
    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            BIO_set_retry_read(b);
        return -1;
    } else {
        ssize_t sr = recv(c->fd_f, data, s, 0);
        if (sr > 0)
            c->frx += sr;
        if (sr != s) {
            warn("client %08x: frontend failed to buffer data from %s:%s",
                    c->id, c->rhost_f, c->rserv_f);
            c->state = STATE_CLOSING;
            return 0;
        }
    }
    return s;
}

static int bio_write(BIO *b, const char *data, int size)
{
    client_t *c = (client_t *)BIO_get_ex_data(b, g.bio_idx);
    BIO_clear_retry_flags(b);
    if (!c) {
        errno = EINVAL;
        return -1;
    }
#if EV_MULTIPLICITY
    EV_P = c->loop;
#endif
    if (c->state != STATE_ACME) {
        // prevent sending data to client until PROXY/ACME decision
        BIO_set_retry_write(b);
        return -1;
    }

#if HAVE_SPLICE
    ssize_t s = write(c->fd_b2f[1], data, size);
    if (s > 0)
        c->n_b2f += s;
#else
    ssize_t s = buf_put(&c->buf_b2f, data, size);
#endif
    if (s == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("client %08x: frontend failed to buffer data from %s:%s",
                    c->id, c->rhost_f, c->rserv_f);
            c->state = STATE_CLOSING;
            return -1;
        }
        BIO_set_retry_write(b);
    }
    if (c->fd_f != -1)
        ev_io_start(EV_A_ &c->io_txf);
    return s;
}

static long bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    (void) b;
    (void) ptr;
    (void) num;
    switch (cmd) {
        case BIO_CTRL_SET_CLOSE:
        case BIO_CTRL_FLUSH:
        case BIO_CTRL_DUP:
            return 1;
        default:
            return 0;
    }
}

static const BIO_METHOD *BIO_s_ualpn(void)
{
    if (g.bio_meth == NULL) {
        int index = BIO_get_new_index();
        if (index == -1) {
            openssl_error("BIO_s_ualpn");
            return NULL;
        }
        g.bio_meth = BIO_meth_new(index | BIO_TYPE_SOURCE_SINK, "ualpn");
        if (g.bio_meth == NULL) {
            openssl_error("BIO_s_ualpn");
            return NULL;
        }
        BIO_meth_set_write(g.bio_meth, bio_write);
        BIO_meth_set_read(g.bio_meth, bio_read);
        BIO_meth_set_ctrl(g.bio_meth, bio_ctrl);
    }
    return g.bio_meth;
}

static int ssl_client_hello_cb(SSL *s, int *al, void *arg)
{
    client_t *c = (client_t *)SSL_get_ex_data(s, g.ssl_idx);
    auth_t *auth = NULL;
    bool alpn = false;
    char name[0x100];
    const unsigned char *ext = NULL;
    size_t ext_len = 0;
    size_t len;

    (void) al;
    (void) arg;
    if (!c)
        return SSL_CLIENT_HELLO_RETRY;

    if (!SSL_client_hello_get0_ext(s,
                TLSEXT_TYPE_application_layer_protocol_negotiation,
                &ext, &ext_len) || ext_len < 3)
        return SSL_CLIENT_HELLO_RETRY;
    len = *ext++ << 8;
    len += *ext++;
    ext_len -= 2;
    if (len != ext_len)
        return SSL_CLIENT_HELLO_RETRY;
    while (ext_len > 0) {
        len = ext[0];
        if (len + 1 > ext_len)
            return SSL_CLIENT_HELLO_RETRY;
        if (len == strlen("acme-tls/1") &&
                memcmp("acme-tls/1", &ext[1], len) == 0) {
            alpn = true;
            break;
        }
        ext_len -= len + 1;
        ext += len + 1;
    }
    if (!alpn)
        return SSL_CLIENT_HELLO_RETRY;

    if (!SSL_client_hello_get0_ext(s, TLSEXT_TYPE_server_name,
                &ext, &ext_len) || ext_len < 5)
        return SSL_CLIENT_HELLO_RETRY;
    len = *ext++ << 8;
    len += *ext++;
    ext_len -= 2;
    if (len != ext_len)
        return SSL_CLIENT_HELLO_RETRY;
    memset(name, 0, sizeof(name));
    while (ext_len > 2) {
        len = (ext[1] << 8) + ext[2];
        if (len + 3 > ext_len)
            return SSL_CLIENT_HELLO_RETRY;
        if (ext[0] == TLSEXT_NAMETYPE_host_name) {
            memcpy(name, &ext[3], len < sizeof(name) ? len : sizeof(name) - 1);
            break;
        }
        ext_len -= len + 3;
        ext += len + 3;
    }

    if (strlen(name) == 0)
        return SSL_CLIENT_HELLO_RETRY;

    auth = get_auth(name);
    if (!auth) {
        infox("client %08x: acme-tls/1 handshake: no auth for %s", c->id, name);
        return SSL_CLIENT_HELLO_RETRY;
    }

    if (!SSL_use_certificate_ASN1(s, auth->crt, auth->crt_size)) {
        warnx("client %08x: acme-tls/1 handshake with auth %s for %s failed: "
                "SSL_use_certificate_ASN1: %s", c->id, auth->auth,
                auth->ident, ERR_error_string(ERR_get_error(), NULL));
        ERR_clear_error();
        return SSL_CLIENT_HELLO_RETRY;
    }

    if (!SSL_use_PrivateKey_ASN1(EVP_PKEY_EC, s, auth->key, auth->key_size)) {
        warnx("client %08x: acme-tls/1 handshake with auth %s for %s failed: "
                "SSL_use_certificate_ASN1: %s", c->id, auth->auth,
                auth->ident, ERR_error_string(ERR_get_error(), NULL));
        ERR_clear_error();
        return SSL_CLIENT_HELLO_RETRY;
    }

    safe_strncpy(c->auth, auth->auth, sizeof(c->auth));
    safe_strncpy(c->ident, auth->ident, sizeof(c->ident));

    return SSL_CLIENT_HELLO_SUCCESS;
}

static int ssl_alpn_select_cb(SSL *s,
        const unsigned char **out, unsigned char *out_len,
        const unsigned char *in, unsigned int in_len, void *arg)
{
    client_t *c = (client_t *)SSL_get_ex_data(s, g.ssl_idx);
    const unsigned char *proto;
    unsigned int proto_len = 0;

    (void) arg;
    if (!c)
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    for (proto = in; proto < in + in_len; proto += proto_len) {
        proto_len = *proto++;
        if (in + in_len < proto + proto_len)
            break;
        if (proto_len == strlen("acme-tls/1") &&
                memcmp(proto, "acme-tls/1", proto_len) == 0) {
            *out = proto;
            *out_len = proto_len;
#if HAVE_SPLICE
            c->n_f2b = 0;
#else
            c->buf_f2b.n = 0;
            c->buf_f2b.rp = 0;
            c->buf_f2b.wp = 0;
#endif
            c->state = STATE_ACME;
            return SSL_TLSEXT_ERR_OK;
        }
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}
#elif defined(USE_MBEDTLS)
static int bio_read(void *ctx, unsigned char *data, size_t size)
{
    client_t *c = (client_t *)ctx;
    if (data == NULL)
        return 0;
    if (!c)
        return -1;

#if EV_MULTIPLICITY
    EV_P = c->loop;
#endif
    ssize_t s = recv(c->fd_f, data, size,
            c->state == STATE_ACME ? 0 : MSG_PEEK);
    if (s == 0) {
        c->state = STATE_CLOSING;
        return 0;
    } else if (s == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("client %08x: frontend failed to read from %s:%s", c->id,
                    c->rhost_f, c->rserv_f);
            c->state = STATE_CLOSING;
            return -1;
        } else if (c->fd_f != -1 && c->state != STATE_DONE) {
            ev_io_start(EV_A_ &c->io_rxf);
        }
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    if (c->state == STATE_ACME) {
        c->frx += s;
        return s;
    }

#if HAVE_SPLICE
    s = write(c->fd_f2b[1], data, s);
    if (s > 0)
        c->n_f2b += s;
#else
    s = buf_put(&c->buf_f2b, data, s);
#endif
    if (s == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        ssize_t sr = recv(c->fd_f, data, s, 0);
        if (sr > 0)
            c->frx += sr;
        if (sr != s) {
            warn("client %08x: frontend failed to buffer data from %s:%s",
                    c->id, c->rhost_f, c->rserv_f);
            c->state = STATE_CLOSING;
            return 0;
        }
    }
    return s;
}

static int bio_write(void *ctx, const unsigned char *data, size_t size)
{
    client_t *c = (client_t *)ctx;
    if (!c)
        return -1;
#if EV_MULTIPLICITY
    EV_P = c->loop;
#endif
    if (c->state != STATE_ACME) {
        // prevent sending data to client until PROXY/ACME decision
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }

#if HAVE_SPLICE
    ssize_t s = write(c->fd_b2f[1], data, size);
    if (s > 0)
        c->n_b2f += s;
#else
    ssize_t s = buf_put(&c->buf_b2f, data, size);
#endif
    if (s == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("client %08x: frontend failed to buffer data from %s:%s",
                    c->id, c->rhost_f, c->rserv_f);
            c->state = STATE_CLOSING;
            return -1;
        } else
            s = MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    if (c->fd_f != -1)
        ev_io_start(EV_A_ &c->io_txf);
    return s;
}

static int sni_callback(void *p, mbedtls_ssl_context *ssl,
        const unsigned char *name, size_t name_len)
{
    client_t *c = (client_t *)p;
    if (!c || ssl != &c->ssl)
        return -1;

    memset(c->ident, 0, sizeof(c->ident));
    if (name_len > sizeof(c->ident) - 1)
        name_len = sizeof(c->ident) - 1;
    memcpy(c->ident, name, name_len);
    return 0;
}

#if MBEDTLS_VERSION_NUMBER >= 0x02170000
int ext_callback(void *ctx, mbedtls_x509_crt const *crt,
        mbedtls_x509_buf const *oid, int critical, const unsigned char *p,
        const unsigned char *end)
{
    (void) ctx;
    (void) crt;
    (void) critical;
    (void) p;
    (void) end;

    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKIX "\x01\x1F", oid))
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    else
        return 0;
}
#endif

int cert_select(client_t *c)
{
    const char *proto = mbedtls_ssl_get_alpn_protocol(&c->ssl);
    if (proto && strcmp(proto, "acme-tls/1") == 0) {
        int rc;
        auth_t *auth = get_auth(c->ident);
        if (!auth) {
            infox("client %08x: acme-tls/1 handshake: no auth for %s",
                    c->id, c->ident);
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }

        mbedtls_x509_crt_free(&c->crt);
#if MBEDTLS_VERSION_NUMBER >= 0x02170000
        rc = mbedtls_x509_crt_parse_der_with_ext_cb(&c->crt, auth->crt,
                auth->crt_size, 1, ext_callback, NULL);
        if (rc) {
            warnx("client %08x: mbedtls_x509_crt_parse_der_with_ext_cb"
                    " for %s: %s",
                    c->id, c->ident, _mbedtls_strerror(rc));
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }
#else
        rc = mbedtls_x509_crt_parse_der(&c->crt, auth->crt,
                auth->crt_size);
        if (rc) {
            warnx("client %08x: mbedtls_x509_crt_parse_der for %s: %s",
                    c->id, c->ident, _mbedtls_strerror(rc));
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }
#endif
        mbedtls_pk_free(&c->key);
        rc = mbedtls_pk_parse_key(&c->key, auth->key,
                auth->key_size, NULL, 0
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
                , mbedtls_ctr_drbg_random, &g.ctr_drbg
#endif
                );
        if (rc) {
            warnx("client %08x: mbedtls_pk_parse_key for %s: %s",
                    c->id, c->ident, _mbedtls_strerror(rc));
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }

        rc = mbedtls_ssl_set_hs_own_cert(&c->ssl, &c->crt, &c->key);
        if (rc) {
            warnx("client %08x: mbedtls_ssl_set_hs_own_cert for %s: %s",
                    c->id, c->ident, _mbedtls_strerror(rc));
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }

        safe_strncpy(c->auth, auth->auth, sizeof(c->auth));
#if HAVE_SPLICE
        c->n_f2b = 0;
#else
        c->buf_f2b.n = 0;
        c->buf_f2b.rp = 0;
        c->buf_f2b.wp = 0;
#endif
        c->state = STATE_ACME;
        return 0;
    } else
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
}

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
int cert_callback(mbedtls_ssl_context *ssl)
{
    client_t *c = (client_t *)mbedtls_ssl_get_user_data_p(ssl);
    if (!c || ssl != &c->ssl)
        return -1;

    return cert_select(c);
}
#endif

static int do_handshake(client_t *c)
{
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    return mbedtls_ssl_handshake(&c->ssl);
#else
    int rc = 0;
    while (c->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
        rc = mbedtls_ssl_handshake_step(&c->ssl);
        if (rc)
            break;
        if (c->state == STATE_ACME)
            continue;
        if (c->ssl.state > MBEDTLS_SSL_CLIENT_HELLO) {
            rc = cert_select(c);
            if (rc)
                break;
        }
    }
    return rc;
#endif
}
#endif

static int tls_session_init(client_t *c, uint8_t *buf, size_t buf_len)
{
    if (buf_len > 0 && buf[0] != 0x16)
        return -1;
    if (buf_len > 1 && buf[1] != 0x03)
        return -1;
    if (buf_len > 2 && (buf[2] < 0x01 || buf[2] > 0x03))
        return -1;

#if defined(USE_GNUTLS)
    int rc = gnutls_init(&c->tls, GNUTLS_SERVER | GNUTLS_NONBLOCK);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("client %08x: gnutls_init: %s", c->id, gnutls_strerror(rc));
        return -1;
    }
    gnutls_session_set_ptr(c->tls, c);
    gnutls_transport_set_ptr(c->tls, c);
    gnutls_transport_set_push_function(c->tls, tls_push_func);
    gnutls_transport_set_pull_function(c->tls, tls_pull_func);
    gnutls_handshake_set_post_client_hello_function(c->tls,
            tls_post_client_hello_func);
    gnutls_certificate_server_set_request(c->tls, GNUTLS_CERT_IGNORE);
    gnutls_datum_t proto = {
        .data = (void *)"acme-tls/1",
        .size = strlen("acme-tls/1")
    };
    rc = gnutls_alpn_set_protocols(c->tls, &proto, 1, GNUTLS_ALPN_MAND);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("client %08x: gnutls_alpn_set_protocols: %s", c->id,
                gnutls_strerror(rc));
        return -1;
    }
    rc = gnutls_set_default_priority(c->tls);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("client %08x: gnutls_set_default_priority: %s", c->id,
                gnutls_strerror(rc));
        return -1;
    }
    rc = gnutls_certificate_allocate_credentials(&c->cred);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("client %08x: failed to allocate TLS credentials: %s", c->id,
                gnutls_strerror(rc));
        gnutls_deinit(c->tls);
        return -1;
    }
#elif defined(USE_OPENSSL)
    c->ssl = SSL_new(g.ssl_ctx);
    if (!c->ssl || !SSL_set_ex_data(c->ssl, g.ssl_idx, c)) {
        char buf[32];
        snprintf(buf, sizeof(buf), "client %08x:", c->id);
        openssl_error(buf);
        return -1;
    }
    BIO *bio = BIO_new(BIO_s_ualpn());
    if (!bio || !BIO_set_ex_data(bio, g.bio_idx, c)) {
        char buf[32];
        snprintf(buf, sizeof(buf), "client %08x:", c->id);
        openssl_error(buf);
        return -1;
    }
    BIO_up_ref(bio);
    SSL_set0_rbio(c->ssl, bio);
    SSL_set0_wbio(c->ssl, bio);
    SSL_set_accept_state(c->ssl);
#elif defined(USE_MBEDTLS)
    mbedtls_ssl_config_init(&c->cnf);
    int rc = mbedtls_ssl_config_defaults(&c->cnf, MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc) {
        warnx("client %08x: mbedtls_ssl_config_defaults: %s", c->id,
                _mbedtls_strerror(rc));
        return -1;
    }
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_ssl_conf_min_tls_version(&c->cnf, MBEDTLS_SSL_VERSION_TLS1_2);
#else
    mbedtls_ssl_conf_min_version(&c->cnf, MBEDTLS_SSL_MAJOR_VERSION_3,
            MBEDTLS_SSL_MINOR_VERSION_3);
#endif
    static const char *protos[] = { "acme-tls/1", NULL };
    rc = mbedtls_ssl_conf_alpn_protocols(&c->cnf, protos);
    if (rc) {
        warnx("client %08x: mbedtls_ssl_conf_alpn_protocols: %s", c->id,
                _mbedtls_strerror(rc));
        return -1;
    }
    mbedtls_ssl_conf_rng(&c->cnf, mbedtls_ctr_drbg_random, &g.ctr_drbg);
    mbedtls_ssl_conf_sni(&c->cnf, sni_callback, c);
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_ssl_conf_cert_cb(&c->cnf, cert_callback);
#endif
    mbedtls_x509_crt_init(&c->crt);
#if MBEDTLS_VERSION_NUMBER >= 0x02170000
    rc = mbedtls_x509_crt_parse_der_with_ext_cb(&c->crt, g.crt, g.crt_len,
            1, ext_callback, NULL);
    if (rc) {
        warnx("client %08x: mbedtls_x509_crt_parse_der_with_ext_cb: %s", c->id,
                _mbedtls_strerror(rc));
        return -1;
    }
#else
    rc = mbedtls_x509_crt_parse_der(&c->crt, g.crt, g.crt_len);
    if (rc == MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        critx("client %08x: mbedTLS is most likely built without "
                "MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION, "
                "terminating", c->id);
        g_shm->shutdown = true;
        return -1;
    } else if (rc) {
        warnx("client %08x: mbedtls_x509_crt_parse_der: %s", c->id,
                _mbedtls_strerror(rc));
        return -1;
    }
#endif
    mbedtls_pk_init(&c->key);
    rc = mbedtls_pk_parse_key(&c->key, g.key, g.key_len, NULL, 0
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
            , mbedtls_ctr_drbg_random, &g.ctr_drbg
#endif
            );
    if (rc) {
        warnx("client %08x: mbedtls_pk_parse_key: %s", c->id,
                _mbedtls_strerror(rc));
        return -1;
    }
    rc = mbedtls_ssl_conf_own_cert(&c->cnf, &c->crt, &c->key);
    if (rc) {
        warnx("client %08x: mbedtls_ssl_conf_own_cert: %s", c->id,
                _mbedtls_strerror(rc));
        return -1;
    }
    mbedtls_ssl_init(&c->ssl);
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_ssl_set_user_data_p(&c->ssl, c);
#endif
    rc = mbedtls_ssl_setup(&c->ssl, &c->cnf);
    if (rc) {
        warnx("client %08x: mbedtls_ssl_setup: %s", c->id,
                _mbedtls_strerror(rc));
        return -1;
    }
    rc = mbedtls_ssl_session_reset(&c->ssl);
    if (rc) {
        warnx("client %08x: mbedtls_ssl_session_reset: %s", c->id,
                _mbedtls_strerror(rc));
        return -1;
    }
    mbedtls_ssl_set_bio(&c->ssl, c, bio_write, bio_read, NULL);
#endif
    return 0;
}

#if HAVE_SPLICE
static void cb_client_b2f0(EV_P_ ev_io *w, int revents)
{
    client_t *c = (client_t *)(((uint8_t *)w) - offsetof(client_t, io_b2f0));

    if ((revents & EV_READ) == 0)
        return;

    ev_io_stop(EV_A_ w);
    if (c->fd_f != -1)
        ev_io_start(EV_A_ &c->io_txf);
}

static void cb_client_b2f1(EV_P_ ev_io *w, int revents)
{
    client_t *c = (client_t *)(((uint8_t *)w) - offsetof(client_t, io_b2f1));

    if ((revents & EV_WRITE) == 0)
        return;

    ev_io_stop(EV_A_ w);
    if (c->fd_b != -1 && c->state != STATE_DONE)
        ev_io_start(EV_A_ &c->io_rxb);
}

static void cb_client_f2b0(EV_P_ ev_io *w, int revents)
{
    client_t *c = (client_t *)(((uint8_t *)w) - offsetof(client_t, io_f2b0));

    if ((revents & EV_READ) == 0)
        return;

    ev_io_stop(EV_A_ w);
    if (c->fd_b != -1)
        ev_io_start(EV_A_ &c->io_txb);
}

static void cb_client_f2b1(EV_P_ ev_io *w, int revents)
{
    client_t *c = (client_t *)(((uint8_t *)w) - offsetof(client_t, io_f2b1));

    if ((revents & EV_WRITE) == 0)
        return;

    ev_io_stop(EV_A_ w);
    if (c->fd_f != -1 && c->state != STATE_DONE)
        ev_io_start(EV_A_ &c->io_rxf);
}
#endif

static void cb_client_rxb(EV_P_ ev_io *w, int revents)
{
    client_t *c = (client_t *)(((uint8_t *)w) - offsetof(client_t, io_rxb));

    if ((revents & EV_READ) == 0)
        return;

    c->timestamp = ev_now(EV_A);

#if HAVE_SPLICE
    ssize_t s = splice(c->fd_b, NULL, c->fd_b2f[1], NULL, 4*PIPE_BUF,
                SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    switch (s) {
        case 0:
            client_done(EV_A_ c, DRAIN_BACKEND);
            return;

        case -1:
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                warn("client %08x: backend failed to splice from %s:%s",
                        c->id, c->rhost_b, c->rserv_b);
                client_done(EV_A_ c, DRAIN_BACKEND);
                return;
            }
            ev_io_stop(EV_A_ &c->io_rxb);
            ev_io_start(EV_A_ &c->io_b2f1);
            break;

        default:
            c->n_b2f += s;
            c->brx += s;
            break;
    }
#else
    ssize_t s = buf_readv(c->fd_b, &c->buf_b2f);
    switch (s) {
        case 0:
            client_done(EV_A_ c, DRAIN_BACKEND);
            return;

        case -1:
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                warn("client %08x: backend failed to read from %s:%s",
                        c->id, c->rhost_b, c->rserv_b);
                client_done(EV_A_ c, DRAIN_BACKEND);
                return;
            }
            break;

        case -2:
            ev_io_stop(EV_A_ &c->io_rxb);
            break;

        default:
            c->brx += s;
            break;
    }
#endif
    if (c->fd_f == -1)
        return;
    ev_io_start(EV_A_ &c->io_txf);
    if (!c->backend_initialized && c->state != STATE_DONE) {
        int z = 0;
        if (setsockopt(c->fd_f, IPPROTO_TCP, TCP_NODELAY, &z, sizeof(z)))
            warn("client %08x: failed to set TCP_NODELAY on frontend socket",
                    c->id);
        if (setsockopt(c->fd_b, IPPROTO_TCP, TCP_NODELAY, &z, sizeof(z)))
            warn("client %08x: failed to set TCP_NODELAY on backend socket",
                    c->id);
        c->backend_initialized = true;
    }
}

static int connect_backend(client_t *c)
{
    int rc, one = 1;
    struct addrinfo *ai;
    const int flags = AI_NUMERICHOST | AI_NUMERICSERV;

    for (str_t *s = g.connect; s; s = s->next) {
        str_t *last = NULL;
        rc = parse_addr(s->str, flags, g.family, &ai);
        if (rc != 0) {
            warnx("client %08x: failed to parse backend address '%s': %s",
                    c->id, s->str,
                    rc == EAI_SYSTEM ? strerror(errno) : gai_strerror(rc));
            continue;
        }

        rc = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                c->rhost_b, sizeof(c->rhost_b),
                c->rserv_b, sizeof(c->rserv_b),
                NI_NUMERICHOST | NI_NUMERICSERV);
        if (rc != 0) {
            warnx("client %08x: failed to get backend address info: %s", c->id,
                    rc == EAI_SYSTEM ? strerror(errno) : gai_strerror(rc));
            freeaddrinfo(ai);
            continue;
        }

        if (strcmp(c->lhost_f, c->rhost_b) == 0 &&
                strcmp(c->lserv_f, c->rserv_b) == 0) {
            critx("client %08x: loop detected: connection back to self "
                    "(%s:%s), terminating", c->id, c->rhost_b, c->rserv_b);
            freeaddrinfo(ai);
            g_shm->shutdown = true;
            return -1;
        }

        c->fd_b = socket(ai->ai_family, SOCK_STREAM, 0);
        if (c->fd_b == -1) {
            warn("client %08x: failed to create backend socket", c->id);
            freeaddrinfo(ai);
            continue;
        }

        if (set_nonblocking(c->fd_b) == -1) {
            warn("client %08x: failed to set O_NONBLOCK on backend socket ",
                    c->id);
            close(c->fd_b);
            c->fd_b = -1;
            freeaddrinfo(ai);
            continue;
        }

        if (setsockopt(c->fd_b, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)))
            warn("client %08x: failed to set TCP_NODELAY on backend socket",
                    c->id);

        if (setsockopt(c->fd_b, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
            warn("client %08x: failed to set SO_REUSEADDR on backend socket",
                    c->id);

        rc = connect(c->fd_b, ai->ai_addr, ai->ai_addrlen);
        if (rc == -1 && errno != EINPROGRESS) {
            warn("client %08x: backend failed to connect to %s:%s", c->id,
                    c->rhost_b, c->rserv_b);
            close(c->fd_b);
            c->fd_b = -1;
            freeaddrinfo(ai);
            continue;
        }

        freeaddrinfo(ai);

        debugx("client %08x: backend initiated connection to %s:%s", c->id,
                c->rhost_b, c->rserv_b);

        SGLIB_DL_LIST_GET_LAST(str_t, g.connect, prev, next, last);
        if (last != s) {
            SGLIB_DL_LIST_DELETE(str_t, g.connect, s, prev, next);
            SGLIB_DL_LIST_ADD_AFTER(str_t, last, s, prev, next);
        }
        return 0;
    }

    warnx("client %08x: all backend connections failed", c->id);
    return -1;
}

static void cb_client_txb(EV_P_ ev_io *w, int revents)
{
    client_t *c = (client_t *)(((uint8_t *)w) - offsetof(client_t, io_txb));

    if ((revents & EV_WRITE) == 0)
        return;

    if (c->state == STATE_PROXY_INIT) {
        struct sockaddr_storage addr;
        socklen_t len = sizeof(struct sockaddr_storage);
        memset(&addr, 0, len);
        if (getpeername(c->fd_b, (struct sockaddr *)&addr, &len) == -1) {
            if (++c->backend_retries > 3)
                warn("client %08x: backend failed to connect to %s:%s", c->id,
                        c->rhost_b, c->rserv_b);
            else {
                debug("client %08x: backend failed to connect to %s:%s", c->id,
                        c->rhost_b, c->rserv_b);
                close(c->fd_b);
                c->fd_b = -1;
                ev_io_stop(EV_A_ &c->io_rxb);
                ev_io_stop(EV_A_ &c->io_txb);
                if (connect_backend(c) == 0) {
                    ev_io_init(&c->io_rxb, cb_client_rxb, c->fd_b, EV_READ);
                    ev_io_init(&c->io_txb, cb_client_txb, c->fd_b, EV_WRITE);
                    ev_io_start(EV_A_ &c->io_txb);
                    return;
                }
            }
            client_done(EV_A_ c, DRAIN_BACKEND);
            return;
        }
        ev_io_start(EV_A_ &c->io_rxb);
        noticex("client %08x: backend connected to %s:%s", c->id,
                c->rhost_b, c->rserv_b);
        c->state = STATE_PROXY;
    }

    if (c->state == STATE_PROXY || c->state == STATE_DONE) {
#if HAVE_SPLICE
        ssize_t s = splice(c->fd_f2b[0], NULL, c->fd_b, NULL, 4*PIPE_BUF,
                SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        switch (s) {
            case 0:
                warnx("client %08x: backend failed to splice to %s:%s",
                        c->id, c->rhost_b, c->rserv_b);
                client_done(EV_A_ c, DRAIN_BACKEND);
                return;

            case -1:
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    warn("client %08x: backend failed to splice to %s:%s",
                        c->id, c->rhost_b, c->rserv_b);
                    client_done(EV_A_ c, DRAIN_BACKEND);
                    return;
                }
                ev_io_stop(EV_A_ &c->io_txb);
                ev_io_start(EV_A_ &c->io_f2b0);
                break;

            default:
                c->n_f2b -= s;
                c->btx += s;
                break;
        }
#else
        ssize_t s = buf_writev(c->fd_b, &c->buf_f2b);
        switch (s) {
            case 0:
                ev_io_stop(EV_A_ &c->io_txb);
                break;

            case -1:
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    warn("client %08x: backend failed to write to %s:%s",
                            c->id, c->rhost_b, c->rserv_b);
                    client_done(EV_A_ c, DRAIN_BACKEND);
                    return;
                }
                break;

            default:
                c->btx += s;
                break;
        }
#endif
    }
    if (c->state == STATE_DONE)
        client_done(EV_A_ c, DRAIN_NONE);
    else if (c->fd_f != -1)
        ev_io_start(EV_A_ &c->io_rxf);
    return;
}

static void cb_client_rxf(EV_P_ ev_io *w, int revents)
{
    client_t *c = (client_t *)(((uint8_t *)w) - offsetof(client_t, io_rxf));

    if ((revents & EV_READ) == 0)
        return;

    c->timestamp = ev_now(EV_A);

    if (c->state == STATE_INIT) {
        uint8_t buf[3];
        ssize_t len = recv(c->fd_f, buf, sizeof(buf), MSG_PEEK);
        if (len == 0) {
            client_done(EV_A_ c, DRAIN_FRONTEND);
            return;
        } else if (len == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                warn("client %08x: frontend failed to read from %s:%s",
                        c->id, c->rhost_f, c->rserv_f);
                client_done(EV_A_ c, DRAIN_FRONTEND);
            }
            return;
        } else if (tls_session_init(c, buf, len) == 0)
            c->state = STATE_ACME_MAYBE;
        else if (connect_backend(c) == 0) {
            c->state = STATE_PROXY_INIT;
            ev_io_init(&c->io_rxb, cb_client_rxb, c->fd_b, EV_READ);
            ev_io_init(&c->io_txb, cb_client_txb, c->fd_b, EV_WRITE);
            ev_io_start(EV_A_ &c->io_txb);
        } else {
            client_done(EV_A_ c, DRAIN_BACKEND);
            return;
        }
    }

    if (c->state == STATE_ACME_MAYBE || c->state == STATE_ACME) {
        int rc;
#if defined(USE_GNUTLS)
        rc = gnutls_handshake(c->tls);
        if (c->state == STATE_CLOSING) {
            client_done(EV_A_ c, DRAIN_FRONTEND);
            return;
        }
        if (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN)
            return;
        if (c->state == STATE_ACME) {
            if (rc == GNUTLS_E_SUCCESS)
                noticex("client %08x: acme-tls/1 handshake with auth %s for %s "
                        "completed", c->id, c->auth, c->ident);
            else
                warnx("client %08x: acme-tls/1 handshake with auth %s for %s "
                        "failed: %s", c->id, c->auth, c->ident,
                        gnutls_strerror(rc));
            client_done(EV_A_ c, DRAIN_NONE);
            return;
        }
#elif defined(USE_OPENSSL)
        rc = SSL_get_error(c->ssl, SSL_do_handshake(c->ssl));
        if (c->state == STATE_CLOSING) {
            client_done(EV_A_ c, DRAIN_FRONTEND);
            return;
        }
        if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE)
            return;
        if (c->state == STATE_ACME) {
            if (rc == SSL_ERROR_NONE)
                noticex("client %08x: acme-tls/1 handshake with auth %s for %s "
                        "completed", c->id, c->auth, c->ident);
            else {
                warnx("client %08x: acme-tls/1 handshake with auth %s for %s "
                        "failed: %s", c->id, c->auth, c->ident,
                        ERR_error_string(ERR_get_error(), NULL));
                ERR_clear_error();
            }
            client_done(EV_A_ c, DRAIN_NONE);
            return;
        }
#elif defined(USE_MBEDTLS)
        rc = do_handshake(c);
        if (c->state == STATE_CLOSING) {
            client_done(EV_A_ c, DRAIN_FRONTEND);
            return;
        }
        if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                rc == MBEDTLS_ERR_SSL_WANT_WRITE ||
                rc == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
                rc == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
            return;
        if (c->state == STATE_ACME) {
            if (rc == 0)
                noticex("client %08x: acme-tls/1 handshake with auth %s for %s "
                        "completed", c->id, c->auth, c->ident);
            else
                warnx("client %08x: acme-tls/1 handshake with auth %s for %s "
                        "failed: %s", c->id, c->auth, c->ident,
                        _mbedtls_strerror(rc));
            client_done(EV_A_ c, DRAIN_NONE);
            return;
        }
#endif
        if (c->state != STATE_DONE) {
            if (connect_backend(c) == 0) {
                c->state = STATE_PROXY_INIT;
                ev_io_init(&c->io_rxb, cb_client_rxb, c->fd_b, EV_READ);
                ev_io_init(&c->io_txb, cb_client_txb, c->fd_b, EV_WRITE);
                ev_io_start(EV_A_ &c->io_txb);
            } else {
                client_done(EV_A_ c, DRAIN_BACKEND);
                return;
            }
        }
    }

    if (c->state == STATE_PROXY_INIT || c->state == STATE_PROXY) {
#if HAVE_SPLICE
        ssize_t s = splice(c->fd_f, NULL, c->fd_f2b[1], NULL, 4*PIPE_BUF,
                SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        switch (s) {
            case 0:
                client_done(EV_A_ c, DRAIN_FRONTEND);
                return;

            case -1:
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    warn("client %08x: frontend failed to splice from %s:%s",
                            c->id, c->rhost_f, c->rserv_f);
                    client_done(EV_A_ c, DRAIN_FRONTEND);
                    return;
                }
                ev_io_stop(EV_A_ &c->io_rxf);
                ev_io_start(EV_A_ &c->io_f2b1);
                break;

            default:
                c->n_f2b += s;
                c->frx += s;
                break;
        }
#else
        ssize_t s = buf_readv(c->fd_f, &c->buf_f2b);
        switch (s) {
            case 0:
                client_done(EV_A_ c, DRAIN_FRONTEND);
                return;

            case -1:
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    warn("client %08x: frontend failed to read from %s:%s",
                            c->id, c->rhost_f, c->rserv_f);
                    client_done(EV_A_ c, DRAIN_FRONTEND);
                    return;
                }
                break;

            case -2:
                ev_io_stop(EV_A_ &c->io_rxf);
                break;

            default:
                c->frx += s;
                break;
        }
#endif
        if (c->fd_b != -1)
            ev_io_start(EV_A_ &c->io_txb);
    }
}

static void cb_client_txf(EV_P_ ev_io *w, int revents)
{
    client_t *c = (client_t *)(((uint8_t *)w) - offsetof(client_t, io_txf));

    if ((revents & EV_WRITE) == 0)
        return;

#if HAVE_SPLICE
    ssize_t s = splice(c->fd_b2f[0], NULL, c->fd_f, NULL, 4*PIPE_BUF,
                SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    switch (s) {
        case 0:
            warnx("client %08x: frontend failed to splice to %s:%s",
                    c->id, c->rhost_f, c->rserv_f);
            client_done(EV_A_ c, DRAIN_FRONTEND);
            return;

        case -1:
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                warnx("client %08x: frontend failed to splice to %s:%s",
                        c->id, c->rhost_f, c->rserv_f);
                client_done(EV_A_ c, DRAIN_FRONTEND);
                return;
            }
            ev_io_stop(EV_A_ &c->io_txf);
            ev_io_start(EV_A_ &c->io_b2f0);
            break;

        default:
            c->n_b2f -= s;
            c->ftx += s;
            break;
    }
#else
    ssize_t s = buf_writev(c->fd_f, &c->buf_b2f);
    switch (s) {
        case 0:
            ev_io_stop(EV_A_ &c->io_txf);
            break;

        case -1:
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                warnx("client %08x: frontend failed to write to %s:%s",
                        c->id, c->rhost_f, c->rserv_f);
                client_done(EV_A_ c, DRAIN_FRONTEND);
                return;
            }
            break;

        default:
            c->ftx += s;
            break;
    }
#endif
    if (c->state == STATE_DONE) {
        client_done(EV_A_ c, DRAIN_NONE);
        return;
    } else if (c->fd_b != -1)
        ev_io_start(EV_A_ &c->io_rxb);

    if (c->state == STATE_ACME) {
        int rc;
#if defined(USE_GNUTLS)
        rc = gnutls_handshake(c->tls);
        if (c->state == STATE_CLOSING) {
            client_done(EV_A_ c, DRAIN_FRONTEND);
            return;
        }
        if (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN)
            return;
        if (rc == GNUTLS_E_SUCCESS)
            noticex("client %08x: acme-tls/1 handshake with auth %s for %s "
                    "completed", c->id, c->auth, c->ident);
        else
            warnx("client %08x: acme-tls/1 handshake with auth %s for %s "
                    "failed: %s", c->id, c->auth, c->ident,
                    gnutls_strerror(rc));
#elif defined(USE_OPENSSL)
        rc = SSL_get_error(c->ssl, SSL_do_handshake(c->ssl));
        if (c->state == STATE_CLOSING) {
            client_done(EV_A_ c, DRAIN_FRONTEND);
            return;
        }
        if (rc == SSL_ERROR_WANT_READ || rc == SSL_ERROR_WANT_WRITE)
            return;
        else if (rc == SSL_ERROR_NONE)
            noticex("client %08x: acme-tls/1 handshake with auth %s for %s "
                    "completed", c->id, c->auth, c->ident);
        else {
            warnx("client %08x: acme-tls/1 handshake with auth %s for %s "
                    "failed: %s", c->id, c->auth, c->ident,
                    ERR_error_string(ERR_get_error(), NULL));
            ERR_clear_error();
        }
#elif defined(USE_MBEDTLS)
        rc = do_handshake(c);
        if (c->state == STATE_CLOSING) {
            client_done(EV_A_ c, DRAIN_FRONTEND);
            return;
        }
        if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
                rc == MBEDTLS_ERR_SSL_WANT_WRITE ||
                rc == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
                rc == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS)
            return;
        else if (rc == 0)
            noticex("client %08x: acme-tls/1 handshake with auth %s for %s "
                    "completed", c->id, c->auth, c->ident);
        else
            warnx("client %08x: acme-tls/1 handshake with auth %s for %s "
                    "failed: %s", c->id, c->auth, c->ident,
                    _mbedtls_strerror(rc));
#endif
        client_done(EV_A_ c, DRAIN_NONE);
        return;
    }
}

static void cb_client_timer(EV_P_ ev_timer *w, int revents)
{
    client_t *c = (client_t *)(((uint8_t *)w) - offsetof(client_t, timer));

    if ((revents & EV_TIMER) == 0)
        return;

    ev_tstamp after = c->timestamp - ev_now(EV_A) + 60;
    if (after < 0.0) {
        infox("client %08x: closing due to activity timeout", c->id);
        client_done(EV_A_ c, DRAIN_BOTH);
        return;
    } else {
        ev_timer_set(w, after, 0.0);
        ev_timer_start(EV_A_ w);
    }
}

static void cb_client_accept(EV_P_ ev_io *w, int revents)
{
    int fd, rc;
    uaddr_t addr[2];
    char rhost[MAXHOST];
    char rserv[MAXSERV];
    char lhost[MAXHOST];
    char lserv[MAXSERV];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(fd))];
    struct iovec iov = { .iov_base = addr, .iov_len = sizeof(addr) };
    (void) EV_A;

    if ((revents & EV_READ) == 0)
        return;

    if (g_shm->shutdown) {
        ev_io_stop(EV_A_ w);
        return;
    }

    addr[0].len = sizeof(addr[0].addr);
    addr[1].len = sizeof(addr[1].addr);

    fd = accept(w->fd, &addr[0].addr.sa, &addr[0].len);
    if (fd == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            warn("frontend failed to accept");
        return;
    }

    if (getsockname(fd, &addr[1].addr.sa, &addr[1].len) != 0) {
        warn("accept: getsockname");
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    rc = getnameinfo(&addr[0].addr.sa, addr[0].len, rhost, sizeof(rhost),
            rserv, sizeof(rserv), NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        warnx("accept: getnameinfo: %s", rc == EAI_SYSTEM ? strerror(errno) :
                gai_strerror(rc));
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    rc = getnameinfo(&addr[1].addr.sa, addr[1].len, lhost, sizeof(lhost),
            lserv, sizeof(lserv), NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        warnx("accept: getnameinfo: %s", rc == EAI_SYSTEM ? strerror(errno) :
                gai_strerror(rc));
        shutdown(fd, SHUT_RDWR);
        close(fd);
        return;
    }

    infox("new frontend connection to %s:%s from %s:%s",
            lhost, lserv, rhost, rserv);

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    msg.msg_controllen = cmsg->cmsg_len;

    for (worker_t *worker = g.workers; worker; worker = worker->next) {
        debugx("forwarding connection to worker %ld", (long)worker->pid);
        if (sendmsg(worker->sv[1], &msg, 0) != -1) {
            worker_t *last = NULL;
            SGLIB_DL_LIST_GET_LAST(worker_t, g.workers, prev, next, last);
            if (last != worker) {
                SGLIB_DL_LIST_DELETE(worker_t, g.workers, worker, prev, next);
                SGLIB_DL_LIST_ADD_AFTER(worker_t, last, worker, prev, next);
            }
            close(fd);
            return;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("accept: sendmsg to worker %ld failed", (long)worker->pid);
        }
    }
    warnx("accept: all workers busy, connection from %s:%s closed",
            rhost, rserv);
    shutdown(fd, SHUT_RDWR);
    close(fd);
}

static void cb_cleanup(EV_P_ ev_cleanup *w, int revents)
{
#if EV_MULTIPLICITY
    (void) EV_A;
#endif
    (void) w;
    (void) revents;

    while (g.controllers) {
        controller_t *ctrl = g.controllers;
        SGLIB_DL_LIST_DELETE(controller_t, g.controllers, ctrl, prev, next);
        ev_io_stop(EV_A_ &ctrl->io_send);
        ev_io_stop(EV_A_ &ctrl->io_recv);
        ev_timer_stop(EV_A_ &ctrl->timer);
        if (ctrl->fd != -1)
            close(ctrl->fd);
        free(ctrl);
    }

    while (g.listeners) {
        listener_t *listener = g.listeners;
        SGLIB_LIST_DELETE(listener_t, g.listeners, listener, next);
        ev_io_stop(EV_A_ &listener->io);
        close(listener->io.fd);
        free(listener);
    }

    while (g.workers) {
        worker_t *worker = g.workers;
        SGLIB_DL_LIST_DELETE(worker_t, g.workers, worker, prev, next);
        ev_io_stop(EV_A_ &worker->io);
        ev_child_stop(EV_A_ &worker->child);
        ev_timer_stop(EV_A_ &worker->timer);
        ev_signal_stop(EV_A_ &worker->sigint);
        ev_signal_stop(EV_A_ &worker->sigterm);
        if (worker->sv[0] != -1)
            close(worker->sv[0]);
        if (worker->sv[1] != -1)
            close(worker->sv[1]);
        free(worker);
    }

    while (g.clients) {
        client_t *client = g.clients;
        if (client->fd_f != -1) {
            infox("client %08x: frontend connection closed (rx=%zu tx=%zu)",
                    client->id, client->frx, client->ftx);
            shutdown(client->fd_f, SHUT_RDWR);
            close(client->fd_f);
            ev_io_stop(EV_A_ &client->io_txf);
            ev_io_stop(EV_A_ &client->io_rxf);
        }
        if (client->fd_b != -1) {
            infox("client %08x: backend connection closed (rx=%zu tx=%zu)",
                    client->id, client->brx, client->btx);
            shutdown(client->fd_b, SHUT_RDWR);
            close(client->fd_b);
            ev_io_stop(EV_A_ &client->io_txb);
            ev_io_stop(EV_A_ &client->io_rxb);
        }
#if HAVE_SPLICE
        close(client->fd_b2f[0]);
        close(client->fd_b2f[1]);
        close(client->fd_f2b[0]);
        close(client->fd_f2b[1]);
        ev_io_stop(EV_A_ &client->io_f2b0);
        ev_io_stop(EV_A_ &client->io_f2b1);
        ev_io_stop(EV_A_ &client->io_b2f0);
        ev_io_stop(EV_A_ &client->io_b2f1);
#endif
        ev_timer_stop(EV_A_ &client->timer);
#if defined(USE_GNUTLS)
        if (client->tls)
            gnutls_deinit(client->tls);
        if (client->cred)
            gnutls_certificate_free_credentials(client->cred);
#elif defined(USE_OPENSSL)
        if (client->ssl)
            SSL_free(client->ssl);
#endif
        SGLIB_DL_LIST_DELETE(client_t, g.clients, client, prev, next);
        free(client);
    }
}

static int client_new(EV_P_ int fd, uaddr_t *addr)
{
    union {
        char buf[108];
        struct {
            uint8_t sig[12];
            uint8_t ver_cmd;
            uint8_t fam;
            uint16_t len;
            union {
                struct {
                    struct in_addr src_addr;
                    struct in_addr dst_addr;
                    in_port_t src_port;
                    in_port_t dst_port;
                } v4;
                struct {
                    struct in6_addr src_addr;
                    struct in6_addr dst_addr;
                    in_port_t src_port;
                    in_port_t dst_port;
                } v6;
            } addr;
        } v2;
    } proxy = {
        .v2 = {
            .sig = { 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d,
                     0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a },
            .ver_cmd = 0x21, .fam = 0, .len = 0,
            .addr = { .v4 = { {INADDR_NONE}, {INADDR_NONE}, 0, 0 } }
        }
    };
    ssize_t proxy_len = 0;
    int one = 1;
    int rc;

    if (fd < 0) {
        warnx("client_new: invalid socket descriptor");
        return -1;
    }

    client_t *c = calloc(1, sizeof(client_t));
    if (!c) {
        warn("client_new: calloc");
        close(fd);
        return -1;
    }
    c->id = 0xFFFFFFFF & (unsigned int)random();

    rc = getnameinfo(&addr[0].addr.sa, addr[0].len,
            c->rhost_f, sizeof(c->rhost_f), c->rserv_f, sizeof(c->rserv_f),
            NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        warnx("client_new: getnameinfo: %s", rc == EAI_SYSTEM ?
                strerror(errno) : gai_strerror(rc));
        close(fd);
        free(c);
        return -1;
    }

    rc = getnameinfo(&addr[1].addr.sa, addr[1].len,
            c->lhost_f, sizeof(c->lhost_f), c->lserv_f, sizeof(c->lserv_f),
            NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        warnx("client_new: getnameinfo: %s", rc == EAI_SYSTEM ?
                strerror(errno) : gai_strerror(rc));
        close(fd);
        free(c);
        return -1;
    }

    noticex("new client %08x: frontend connection to %s:%s from %s:%s",
            c->id, c->lhost_f, c->lserv_f, c->rhost_f, c->rserv_f);

#if EV_MULTIPLICITY
    c->loop = EV_A;
#endif

    if (addr[0].addr.sa.sa_family == AF_INET &&
            addr[1].addr.sa.sa_family == AF_INET) {
        if (g.proxy == 1) {
            snprintf(proxy.buf, sizeof(proxy.buf),
                    "PROXY TCP4 %.15s %.15s %.5s %.5s\r\n",
                    c->rhost_f, c->lhost_f, c->rserv_f, c->lserv_f);
            proxy_len = strlen(proxy.buf);
        } else if (g.proxy == 2) {
            proxy_len = 16 + 12;
            proxy.v2.fam = 0x11;
            proxy.v2.len = htons(12);
            proxy.v2.addr.v4.src_addr = addr[0].addr.v4.sin_addr;
            proxy.v2.addr.v4.src_port = addr[0].addr.v4.sin_port;
            proxy.v2.addr.v4.dst_addr = addr[1].addr.v4.sin_addr;
            proxy.v2.addr.v4.dst_port = addr[1].addr.v4.sin_port;
        }
    } else if (addr[0].addr.sa.sa_family == AF_INET6 &&
                addr[1].addr.sa.sa_family == AF_INET6) {
        if (g.proxy == 1) {
            snprintf(proxy.buf, sizeof(proxy.buf),
                    "PROXY TCP6 %.39s %.39s %.5s %.5s\r\n",
                    c->rhost_f, c->lhost_f, c->rserv_f, c->lserv_f);
            proxy_len = strlen(proxy.buf);
        } else if (g.proxy == 2) {
            proxy_len = 16 + 36;
            proxy.v2.fam = 0x21;
            proxy.v2.len = htons(36);
            proxy.v2.addr.v6.src_addr = addr[0].addr.v6.sin6_addr;
            proxy.v2.addr.v6.src_port = addr[0].addr.v6.sin6_port;
            proxy.v2.addr.v6.dst_addr = addr[1].addr.v6.sin6_addr;
            proxy.v2.addr.v6.dst_port = addr[1].addr.v6.sin6_port;
        }
    } else {
        warnx("client %08x: unsupported protocol", c->id);
        close(fd);
        free(c);
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)))
        warn("client %08x: failed to set TCP_NODELAY on frontend socket",
                c->id);

#if HAVE_SPLICE
    if (pipe(c->fd_b2f)) {
        warn("client %08x: failed to create pipe", c->id);
        close(fd);
        free(c);
        return -1;
    }

    if (pipe(c->fd_f2b)) {
        warn("client %08x: failed to create pipe", c->id);
        close(c->fd_b2f[0]);
        close(c->fd_b2f[1]);
        close(fd);
        free(c);
        return -1;
    }

    if (set_nonblocking(fd)
            || set_nonblocking(c->fd_b2f[0]) || set_nonblocking(c->fd_b2f[1])
            || set_nonblocking(c->fd_f2b[0]) || set_nonblocking(c->fd_f2b[1])) {
        warn("client %08x: failed to set nonblocking mode", c->id);
        close(c->fd_b2f[0]);
        close(c->fd_b2f[1]);
        close(c->fd_f2b[0]);
        close(c->fd_f2b[1]);
#else
    if (set_nonblocking(fd)) {
        warn("client %08x: failed to set nonblocking mode", c->id);
#endif
        close(fd);
        free(c);
        return -1;
    }

    if (proxy_len > 0) {
#if HAVE_SPLICE
        ssize_t s = write(c->fd_f2b[1], &proxy, proxy_len);
        if (s == -1)
            warn("client %08x: failed to write proxy header to pipe", c->id);
        else if (s != proxy_len)
            warnx("client %08x: failed to write proxy header to pipe", c->id);
        if (s != proxy_len) {
            close(fd);
            close(c->fd_b2f[0]);
            close(c->fd_b2f[1]);
            close(c->fd_f2b[0]);
            close(c->fd_f2b[1]);
            free(c);
            return -1;
        }
        c->n_f2b += s;
#else
        buf_put(&c->buf_f2b, &proxy, proxy_len);
#endif
    }

    c->fd_f = fd;
    c->fd_b = -1;

    c->timestamp = ev_now(EV_A);
    ev_init(&c->timer, cb_client_timer);
    ev_set_priority(&c->timer, -1);
    ev_invoke(EV_A_ &c->timer, EV_TIMER);

    ev_io_init(&c->io_rxf, cb_client_rxf, c->fd_f, EV_READ);
    ev_io_init(&c->io_txf, cb_client_txf, c->fd_f, EV_WRITE);
    ev_io_start(EV_A_ &c->io_rxf);

#if HAVE_SPLICE
    ev_io_init(&c->io_b2f0, cb_client_b2f0, c->fd_b2f[0], EV_READ);
    ev_io_init(&c->io_b2f1, cb_client_b2f1, c->fd_b2f[1], EV_WRITE);
    ev_io_init(&c->io_f2b0, cb_client_f2b0, c->fd_f2b[0], EV_READ);
    ev_io_init(&c->io_f2b1, cb_client_f2b1, c->fd_f2b[1], EV_WRITE);
#endif

    SGLIB_DL_LIST_ADD(client_t, g.clients, c, prev, next);
    return 0;
}

static void cb_worker_ping(EV_P_ ev_io *w, int revents)
{
    worker_t *worker = (worker_t *)(((uint8_t *)w) - offsetof(worker_t, io));
    char buf[0x10];

    if ((revents & EV_READ) == 0)
        return;

    ssize_t s = recv(worker->sv[1], buf, sizeof(buf), 0);
    if (s == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
        warn("failed to receive ping from worker %ld, killing it",
                (long)worker->pid);
        kill(worker->pid, SIGKILL);
    } else if (s == 0) {
        warnx("worker %ld closed socket, terminating it", (long)worker->pid);
        kill(worker->pid, SIGTERM);
    } else if (send(worker->sv[1], "pong", 4, MSG_NOSIGNAL) == -1 &&
            errno != EAGAIN && errno != EWOULDBLOCK) {
        warn("failed to send pong to worker %ld, killing it",
                (long)worker->pid);
        kill(worker->pid, SIGKILL);
    } else
        worker->timestamp = ev_now(EV_A);
}

static void cb_worker_io(EV_P_ ev_io *w, int revents)
{
    worker_t *worker = (worker_t *)(((uint8_t *)w) - offsetof(worker_t, io));
    uaddr_t addr[2];
    int fd;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(fd))];
    struct iovec iov = { .iov_base = addr, .iov_len = sizeof(addr) };

    if ((revents & EV_READ) == 0)
        return;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    ssize_t r = recvmsg(worker->sv[0], &msg, 0);
    if (r == -1) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("recvmsg failed");
            worker->terminate = true;
        }
    } else if (r == 0) {
        warn("parent closed socket");
        worker->terminate = true;
    } else {
        worker->timestamp = ev_now(EV_A);
        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg) {
            if (cmsg->cmsg_len != CMSG_LEN(sizeof(int)) ||
                    cmsg->cmsg_level != SOL_SOCKET ||
                    cmsg->cmsg_type != SCM_RIGHTS) {
                warn("recvmsg protocol failure");
                return;
            }
            memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
            debugx("new forwarded connection");
            client_new(EV_A_ fd, addr);
        }
    }
}

static void cb_worker_timer(EV_P_ ev_timer *w, int revents)
{
    worker_t *worker = (worker_t *)(((uint8_t *)w) - offsetof(worker_t, timer));
    if ((revents & EV_TIMER) == 0)
        return;

    if (g_shm->shutdown || worker->shutdown) {
        for (client_t *client = g.clients; client; ) {
            client_t *next = client->next;
            client_done(EV_A_ client, DRAIN_NONE);
            client = next;
        }
        if (!g.clients)
            ev_break(EV_A_ EVBREAK_ALL);
    } else if (ev_now(EV_A) - worker->timestamp > 10) {
        warnx("parent not sending pong");
        worker->terminate = true;
    } else if (send(worker->sv[0], "ping", 4, MSG_NOSIGNAL) == -1 &&
            errno != EAGAIN && errno != EWOULDBLOCK) {
        warn("failed to send ping to parent");
        worker->terminate = true;
    }

    if (worker->terminate && !g.clients)
        ev_break(EV_A_ EVBREAK_ALL);
}

static void cb_worker_signal(EV_P_ ev_signal *w, int revents)
{
    worker_t *worker;

    if (revents & EV_SIGNAL) {
        switch (w->signum) {
            case SIGINT:
                worker = (worker_t *)(((uint8_t *)w) -
                        offsetof(worker_t, sigint));
                warnx("caught SIGINT, shutting down");
                worker->terminate = true;
                break;

            case SIGTERM:
                worker = (worker_t *)(((uint8_t *)w) -
                        offsetof(worker_t, sigterm));
                warnx("caught SIGTERM, shutting down");
                worker->shutdown = true;
                break;

            default:
                return;
        }
        ev_signal_stop(EV_A_ &worker->sigint);
        ev_signal_stop(EV_A_ &worker->sigterm);
    }
}

static void cb_child(EV_P_ ev_child *w, int revents)
{
    worker_t *worker = (worker_t *)(((uint8_t *)w) - offsetof(worker_t, child));

    if ((revents & EV_CHILD) == 0)
        return;

    ev_child_stop(EV_A_ &worker->child);
    ev_io_stop(EV_A_ &worker->io);
    close(worker->sv[1]);
    worker->sv[1] = -1;
    SGLIB_DL_LIST_DELETE(worker_t, g.workers, worker, prev, next);
    noticex("worker %ld terminated with status %d", (long)worker->pid,
            w->rstatus);
    free(worker);
}

static void cleanup_and_exit(int stage, int return_code)
{
    if (return_code != EXIT_SUCCESS && g.logfilename) {
        fprintf(stderr, "%s/%ld: [ERR] exiting due to failure, check %s\n",
                g.progname, (long)getpid(), g.logfilename);
    }

    switch (stage) {
        default:
        case 4:
            ev_loop_destroy(EV_DEFAULT_UC);
            if (g.pidfile && !g.chroot)
                unlink(g.pidfile);
            sem_destroy(&g_shm->logsem);
            //intentional fallthrough
        case 3:
            sem_destroy(&g_shm->sem);
            //intentional fallthrough
        case 2:
            munmap(g_shm, g_shm_size);
            //intentional fallthrough
        case 1:
#if HAVE_MAP_DEVZERO
            if (g.devzero != -1)
                close(g.devzero);
#endif
#if defined(USE_GNUTLS)
            gnutls_global_deinit();
#elif defined(USE_OPENSSL)
            if (g.ssl_ctx)
                SSL_CTX_free(g.ssl_ctx);
            if (g.bio_meth)
                BIO_meth_free(g.bio_meth);
#elif defined(USE_MBEDTLS)
            mbedtls_ctr_drbg_free(&g.ctr_drbg);
            mbedtls_entropy_free(&g.entropy);
            free(g.key);
            free(g.crt);
#endif
            //intentional fallthrough
        case 0:
            if (g.sockfd != -1) {
                close(g.sockfd);
                if (g.socket && !g.chroot)
                    unlink(g.socket);
            }
            if (g.daemon && g.pipefd[1] != -1) {
                for (int i = 0; i < 3; i++) {
                    if (write(g.pipefd[1], "ERR", 3) == 3)
                        break;
                    else
                        sleep(1);
                }
                close(g.pipefd[1]);
            }
            if (g.logfile && g.logfile != stderr)
                fclose(g.logfile);
            free(g.progname);
            free(g.logfilename);
            free(g.user);
            free(g.socket);
            free(g.pidfile);
            free(g.chroot);
            while (g.bind) {
                str_t *s = g.bind;
                g.bind = g.bind->next;
                free(s->str);
                free(s);
            }
            while (g.connect) {
                str_t *s = g.connect;
                SGLIB_DL_LIST_DELETE(str_t, g.connect, s, prev, next);
                free(s->str);
                free(s);
            }
    }
    exit(return_code);
}

static void spawn_worker(ev_tstamp timestamp)
{
    worker_t *worker = calloc(1, sizeof(worker_t));
    if (!worker) {
        warn("spawn_worker: calloc");
        return;
    }
    worker->timestamp = timestamp;

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, worker->sv)) {
        err("spawn_worker: failed to create socket pair");
        free(worker);
        return;
    }

    if (set_nonblocking(worker->sv[0]) || set_nonblocking(worker->sv[1])) {
        err("spawn_worker: failed to set O_NONBLOCK on socket pair");
        close(worker->sv[0]);
        close(worker->sv[1]);
        free(worker);
        return;
    }

    if (set_closeonexec(worker->sv[0]) || set_closeonexec(worker->sv[1])) {
        err("spawn_worker: failed to set FD_CLOEXEC on socket pair");
        close(worker->sv[0]);
        close(worker->sv[1]);
        free(worker);
        return;
    }

    worker->pid = fork();
    if (worker->pid == -1) {
        err("spawn_worker: fork failed");
        close(worker->sv[0]);
        close(worker->sv[1]);
        free(worker);
    } else if (worker->pid != 0) {
        // parent
        infox("new worker %ld started", (long)worker->pid);

        close(worker->sv[0]);
        worker->sv[0] = -1;

        ev_child_init(&worker->child, cb_child, worker->pid, 0);
        ev_child_start(EV_DEFAULT_ &worker->child);

        ev_io_init(&worker->io, cb_worker_ping, worker->sv[1], EV_READ);
        ev_io_start(EV_DEFAULT_ &worker->io);

        SGLIB_DL_LIST_ADD(worker_t, g.workers, worker, prev, next);
    } else {
        // child
        ev_cleanup cleanup;
#if HAVE_SETPROCTITLE
        setproctitle("%s worker", g.progname);
#elif linux
        char *last = g.argv[0] + strlen(g.argv[0]) + 1;
        for (int i = 1; g.argv[i]; i++) {
            if (last == g.argv[i])
                last += strlen(g.argv[i]) + 1;
            memset(g.argv[i], 0, strlen(g.argv[i]));
            g.argv[i] = NULL;
        }
        snprintf(g.argv[0], last - g.argv[0], "%s worker", g.progname);
#endif
        signal(SIGPIPE, SIG_IGN);
        signal(SIGABRT, SIG_IGN);

        worker->pid = getpid();
        srand(worker->pid ^ time(NULL));

        if (g.daemon && !g.logfilename)
            syslog_init();

        noticex("new worker starting");

        close(worker->sv[1]);
        worker->sv[1] = -1;

        close(g.sockfd);
        g.sockfd = -1;

        free(g.pidfile);
        g.pidfile = NULL;

        ev_io_stop(EV_DEFAULT_ &g.controller);
        ev_signal_stop(EV_DEFAULT_ &g.sigint);
        ev_signal_stop(EV_DEFAULT_ &g.sigterm);
        ev_timer_stop(EV_DEFAULT_ &g.timer);
        ev_loop_destroy(EV_DEFAULT);

        ev_io_init(&worker->io, cb_worker_io, worker->sv[0], EV_READ);
        ev_io_start(EV_DEFAULT_ &worker->io);

        ev_signal_init(&worker->sigint, cb_worker_signal, SIGINT);
        ev_signal_start(EV_DEFAULT_ &worker->sigint);

        ev_signal_init(&worker->sigterm, cb_worker_signal, SIGTERM);
        ev_signal_start(EV_DEFAULT_ &worker->sigterm);

        ev_timer_init(&worker->timer, cb_worker_timer,
                1.0 + (float)random()/(float)RAND_MAX, 1.0);
        ev_set_priority(&worker->timer, +2);
        ev_timer_start(EV_DEFAULT_ &worker->timer);

        ev_cleanup_init(&cleanup, cb_cleanup);
        ev_cleanup_start(EV_DEFAULT_ &cleanup);

        ev_run(EV_DEFAULT_ 0);

        ev_loop_destroy(EV_DEFAULT_UC);

        close(worker->sv[0]);
        free(worker);

        noticex("worker terminating");
        cleanup_and_exit(UINT_MAX, 0);
    }
}

static void cb_timer(EV_P_ ev_timer *w, int revents)
{
    static struct sglib_auth_t_iterator it;
    static auth_t *a = NULL;
    (void) w;

    if ((revents & EV_TIMER) == 0)
        return;

    if (!a || g.auths_touched) {
        a = sglib_auth_t_it_init_inorder(&it, g_shm->auths);
        g.auths_touched = false;
    }

    if (a) {
        if (ev_now(EV_A) - a->timestamp > 60*60) {
            if (auth_lock(10) == 0) {
                sglib_auth_t_delete(&g_shm->auths, a);
                SGLIB_DL_LIST_ADD(auth_t, g_shm->avail, a, left, right);
                g.auths_touched = true;
                infox("removed expired auth for %s", a->ident);
                auth_unlock();
            }
        } else
            a = sglib_auth_t_it_next(&it);
    }

    if (g_shm->shutdown) {
        for (controller_t *c = g.controllers; c; ) {
            controller_t *next = c->next;
            controller_done(EV_A_ g.controllers, false);
            c = next;
        }
        if (!g.workers && !g.controllers)
            ev_break(EV_A_ EVBREAK_ALL);
    } else {
        unsigned n = 0;
        for (worker_t *worker = g.workers; worker; ) {
            worker_t *next = worker->next;
            if (ev_now(EV_A) - worker->timestamp > 10) {
                warnx("worker %ld not pinging, killing it", (long)worker->pid);
                kill(worker->pid, SIGKILL);
            }
            worker = next;
            n++;
        }
        while (n++ < g.num_workers)
            spawn_worker(ev_now(EV_A));
    }
}

static void cb_signal(EV_P_ ev_signal *w, int revents)
{
    if (revents & EV_SIGNAL) {
        switch (w->signum) {
            case SIGINT:
                warnx("caught SIGINT, shutting down");
                break;

            case SIGTERM:
                warnx("caught SIGTERM, shutting down");
                break;

            default:
                return;
        }
        ev_signal_stop(EV_A_ w);
        g_shm->shutdown = true;
    }
}

static void log_function(int priority, const char *format, ...)
{
    struct timespec t;
    char ts[0x20];
    char *buf = NULL;
    size_t buf_size = 0;
    int r;
    FILE *f;
    const char *pr;
    va_list ap;

    switch (priority) {
        case LOG_DEBUG:
            if (g.loglevel < 3)
                return;
            pr = "DEBUG";
            break;
        case LOG_INFO:
            if (g.loglevel < 2)
                return;
            pr = "INFO";
            break;
        case LOG_NOTICE:
            if (g.loglevel < 1)
                return;
            pr = "NOTICE";
            break;
        case LOG_WARNING:
            pr = "WARNING";
            break;
        case LOG_ERR:
            pr = "ERR";
            break;
        case LOG_CRIT:
            pr = "CRIT";
            break;
        default:
            pr = "UNKNOWN";
    }
    if (g.logfile) {
        if (g_shm)
            sem_wait(&g_shm->logsem);
        clock_gettime(CLOCK_REALTIME, &t);
        strftime(ts, sizeof(ts), "%b %d %T", localtime(&t.tv_sec));
        r = fprintf(g.logfile, "%s %s/%ld: [%s] ", ts, g.progname,
                (long)getpid(), pr);
        if (r > 0) {
            va_start(ap, format);
            r = vfprintf(g.logfile, format, ap);
            va_end(ap);
        }
        if (r < 0 || fputc('\n', g.logfile) == EOF || fflush(g.logfile)) {
            fprintf(stderr, "%s/%ld: [CRIT] failed to write to log file: %s\n",
                    g.progname, (long)getpid(), strerror(errno));
        }
        if (g_shm)
            sem_post(&g_shm->logsem);
    }
    if (g.syslog) {
        va_start(ap, format);
        f = open_memstream(&buf, &buf_size);
        if (!f) {
            syslog(LOG_CRIT, "log_function: open_memstream failed: %s",
                    strerror(errno));
        } else if (vfprintf(f, format, ap) < 0) {
            syslog(LOG_CRIT, "log_function: vfprintf failed: %s",
                    strerror(errno));
        } else if (fflush(f) != 0) {
            syslog(LOG_CRIT, "log_function: fflush failed: %s",
                    strerror(errno));
        } else
            syslog(priority, "[%s] %s", pr, buf);
        if (f)
            fclose(f);
        free(buf);
        va_end(ap);
    }
}

void usage(void)
{
    fprintf(stderr,
        "usage: %s [-?|--help] [-V|--version] [-4|--ipv4] [-6|--ipv6]\n"
        "\t[-b|--bind address[@port] [-c|--connect address[@port]\n"
        "\t[-d|--daemon] [-l|--logfile file] [-m|--max-auths N]\n"
        "\t[-n|--num-workers N] [-p|--pidfile file] [-P|--proxy N]\n"
        "\t[-r|--chroot dir] [-s|--sock path] [-S|--sock-mode mode]\n"
        "\t[-t|--terminate] [-u|--user user[:group]] [-v|--verbose ...]\n",
        g.progname);
}

void version(void)
{
    fprintf(stderr, "%s: version " PACKAGE_VERSION "\n"
            "Copyright (C) 2019-2026 Nicola Di Lieto\n\n"
            "%s is free software: you can redistribute and/or modify\n"
            "it under the terms of the GNU General Public License as\n"
            "published by the Free Software Foundation, either version 3\n"
            "of the License, or (at your option) any later version.\n\n"
            "%s is distributed in the hope that it will be useful, but\n"
            "WITHOUT ANY WARRANTY; without even the implied warranty of\n"
            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n"
            "See https://www.gnu.org/licenses/gpl.html for more details.\n",
            g.progname, g.progname, g.progname);
}

int main(int argc, char **argv)
{
    static struct option options[] = {
        {"ipv4",        no_argument,        NULL,   '4'},
        {"ipv6",        no_argument,        NULL,   '6'},
        {"bind",        required_argument,  NULL,   'b'},
        {"connect",     required_argument,  NULL,   'c'},
        {"daemon",      no_argument,        NULL,   'd'},
        {"logfile",     required_argument,  NULL,   'l'},
        {"max-auths",   required_argument,  NULL,   'm'},
        {"num-workers", required_argument,  NULL,   'n'},
        {"pidfile",     required_argument,  NULL,   'p'},
        {"proxy",       required_argument,  NULL,   'P'},
        {"chroot",      required_argument,  NULL,   'r'},
        {"sock",        required_argument,  NULL,   's'},
        {"sock-mode",   required_argument,  NULL,   'S'},
        {"user",        required_argument,  NULL,   'u'},
        {"terminate",   no_argument,        NULL,   't'},
        {"verbose",     no_argument,        NULL,   'v'},
        {"version",     no_argument,        NULL,   'V'},
        {"help",        no_argument,        NULL,   '?'},
        {NULL,          0,                  NULL,   0}
    };
    FILE *f;
    long n;
    int fd = -1, rc, one = 1;
    pid_t pid;
    str_t *str;
    char host[NI_MAXHOST];
    char port[NI_MAXSERV];
    struct addrinfo *ai = NULL;
    const int flags = AI_NUMERICHOST | AI_NUMERICSERV;
    struct sockaddr_un sock_addr;
    mode_t mask;
    struct rlimit rl;
    bool server_mode = false;

    g.argv = argv;

    srand(getpid() ^ time(NULL));

    g.progname = strdup(basename(argv[0]));
    if (!g.progname) {
        err("strdup");
        return EXIT_FAILURE;
    }

    g.logfile = stderr;
    set_log_func(log_function);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    while (1) {
        char *endptr;
        int option_index;
        int c = getopt_long(argc, argv, "46b:c:dl:m:n:p:P:r:s:S:tu:vVh?",
                options, &option_index);
        if (c == -1)
            break;
        switch (c) {
            case '4':
                server_mode = true;
                if (g.family == AF_INET6)
                    g.family = AF_UNSPEC;
                else
                    g.family = AF_INET;
                break;

            case '6':
                server_mode = true;
                if (g.family == AF_INET)
                    g.family = AF_UNSPEC;
                else
                    g.family = AF_INET6;
                break;

            case 'b':
                server_mode = true;
                rc = parse_addr(optarg, flags | AI_PASSIVE, AF_UNSPEC, &ai);
                if (rc != 0) {
                    warnx("failed to parse address '%s': %s", optarg,
                            rc == EAI_SYSTEM ? strerror(errno) :
                            gai_strerror(rc));
                    cleanup_and_exit(0, EXIT_FAILURE);
                } else
                    freeaddrinfo(ai);
                str = calloc(1, sizeof(str_t));
                if (!str) {
                    err("calloc");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                str->str = strdup(optarg);
                if (!str->str) {
                    err("strdup");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                SGLIB_LIST_ADD(str_t, g.bind, str, next)
                break;

            case 'c':
                server_mode = true;
                rc = parse_addr(optarg, flags, AF_UNSPEC, &ai);
                if (rc != 0) {
                    warnx("failed to parse address '%s': %s", optarg,
                            rc == EAI_SYSTEM ? strerror(errno) :
                            gai_strerror(rc));
                    cleanup_and_exit(0, EXIT_FAILURE);
                } else
                    freeaddrinfo(ai);
                str = calloc(1, sizeof(str_t));
                if (!str) {
                    err("calloc");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                str->str = strdup(optarg);
                if (!str->str) {
                    err("strdup");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                SGLIB_DL_LIST_ADD(str_t, g.connect, str, prev, next)
                break;

            case 'd':
                if (g.stop) {
                    errx("-d,--daemon and -t,--stop are mutually exclusive");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                server_mode = true;
                g.daemon = true;
                break;

            case 'l':
                if (g.logfilename) {
                    errx("-l,--logfile can only be specified once");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                f = fopen(optarg, "a+");
                if (!f) {
                    err("failed to open %s", optarg);
                    cleanup_and_exit(0, EXIT_FAILURE);
                } else {
                    g.logfilename = strdup(optarg);
                    if (!g.logfilename) {
                        fclose(f);
                        err("strdup");
                        cleanup_and_exit(0, EXIT_FAILURE);
                    }
                    noticex("logging to file %s", optarg);
                    g.logfile = f;
                }
                break;

            case 'm':
                n = strtol(optarg, &endptr, 10);
                if (*endptr != 0 || n <= 0) {
                    warnx("-m,--max-auths: N must be a positive integer");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                g.max_auths = n;
                server_mode = true;
                break;

            case 'n':
                n = strtol(optarg, &endptr, 10);
                if (*endptr != 0 || n <= 0) {
                    warnx("-n,--num-workers: N must be a positive integer");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                g.num_workers = n;
                server_mode = true;
                break;

            case 'p':
                if (g.pidfile) {
                    errx("-p,--pidfile can only be specified once");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                g.pidfile = strdup(optarg);
                if (!g.pidfile) {
                    err("strdup");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                break;

            case 'P':
                n = strtol(optarg, &endptr, 10);
                if (*endptr != 0 || n < 0 || n > 2) {
                    warnx("-P,--proxy: must be 0 (disabled), 1 or 2");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                server_mode = true;
                g.proxy = n;
                break;

            case 'r':
                if (g.chroot) {
                    errx("-r,--chroot can only be specified once");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                if (geteuid() != 0)
                    warnx("-r,--chroot requires running as root - ignored");
                else {
                    g.chroot = strdup(optarg);
                    if (!g.chroot) {
                        err("strdup");
                        cleanup_and_exit(0, EXIT_FAILURE);
                    }
                    server_mode = true;
                }
                break;

            case 's':
                if (g.socket) {
                    errx("-s,--sock can only be specified once");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                g.socket = strdup(optarg);
                if (!g.socket) {
                    err("strdup");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                break;

            case 'S':
                n = strtol(optarg, &endptr, 8);
                if (*endptr != 0 || (n & 0777) != n) {
                    warnx("-S,--sock-mode: invalid mode");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                server_mode = true;
                g.sockmode = n;
                break;

            case 't':
                if (g.daemon) {
                    errx("-d,--daemon and -t,--stop are mutually exclusive");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                if (server_mode) {
                    errx("-t,--stop is incompatible with server mode");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                g.stop = true;
                break;

            case 'u':
                if (g.user) {
                    errx("-u,--user can only be specified once");
                    cleanup_and_exit(0, EXIT_FAILURE);
                }
                if (geteuid() != 0)
                    warnx("-u,--user requires running as root - ignored");
                else {
                    struct passwd *pwd;
                    struct group *grp;
                    g.user = strdup(optarg);
                    if (!g.user) {
                        err("strdup");
                        cleanup_and_exit(0, EXIT_FAILURE);
                    }
                    g.group = strrchr(g.user, ':');
                    if (g.group != NULL) {
                        *g.group++ = 0;
                        grp = getgrnam(g.group);
                        if (!grp) {
                            errx("getgrnam(\"%s\") failed", g.group);
                            cleanup_and_exit(0, EXIT_FAILURE);
                        }
                        g.gid = grp->gr_gid;
                    }
                    pwd = getpwnam(g.user);
                    if (!pwd) {
                        errx("getpwnam(\"%s\") failed", g.user);
                        cleanup_and_exit(0, EXIT_FAILURE);
                    }
                    g.uid = pwd->pw_uid;
                    if (g.group == NULL) {
                        g.gid = pwd->pw_gid;
                        grp = getgrgid(g.gid);
                        if (!grp) {
                            errx("getgrgid(%d) failed", g.gid);
                            cleanup_and_exit(0, EXIT_FAILURE);
                        }
                        g.group = grp->gr_name;
                    }
                    server_mode = true;
                }
                break;

            case 'v':
                g.loglevel++;
                break;

            case 'V':
                version();
                cleanup_and_exit(0, EXIT_FAILURE);
                break;

            default:
                usage();
                cleanup_and_exit(0, EXIT_FAILURE);
        }
    }

    while (optind < argc)
        warnx("extra argument ignored: %s", argv[optind++]);

    if (!g.pidfile) {
        if (asprintf(&g.pidfile, RUNSTATEDIR "/%s.pid", g.progname) < 0) {
            g.pidfile = NULL;
            err("asprintf");
            cleanup_and_exit(0, EXIT_FAILURE);
        }
    }

    if (!g.socket) {
        if (asprintf(&g.socket, RUNSTATEDIR "/%s.sock", g.progname) < 0) {
            g.socket = NULL;
            err("asprintf");
            cleanup_and_exit(0, EXIT_FAILURE);
        }
    }

    if (strlen(g.socket) > sizeof(sock_addr.sun_path) - 1) {
        errx("socket name is too long (%s)", g.socket);
        cleanup_and_exit(0, EXIT_FAILURE);
    }

    memset(&sock_addr, 0, sizeof(sock_addr));
    safe_strncpy(sock_addr.sun_path, g.socket, sizeof(sock_addr.sun_path));
    sock_addr.sun_family = AF_UNIX;

    if (g.stop || server_mode) {
        f = fopen(g.pidfile, "r");
        if (!f) {
            if (g.stop || errno != ENOENT) {
                err("failed to open %s", g.pidfile);
                cleanup_and_exit(0, EXIT_FAILURE);
            }
        } else if (fscanf(f, "%ld", &n) != 1) {
            if (ferror(f))
                err("failed to read %s", g.pidfile);
            else
                errx("failed to parse %s", g.pidfile);
            fclose(f);
            cleanup_and_exit(0, EXIT_FAILURE);
        } else {
            fclose(f);
            if (g.stop) {
                for (int i = 0; i < 3; i++) {
                    if (i > 0)
                        infox("resending SIGTERM to process %ld", n);
                    if (kill(n, SIGTERM)) {
                        err("failed to send SIGTERM to process %ld", n);
                        cleanup_and_exit(0, EXIT_FAILURE);
                    }
                    for (int j = 0; j < 5; j++) {
                        sleep(1);
                        if (kill(n, 0) && errno == ESRCH) {
                            unlink(g.pidfile);
                            unlink(g.socket);
                            cleanup_and_exit(0, EXIT_SUCCESS);
                        }
                    }
                }
                warnx("failed to stop process %ld", n);
                cleanup_and_exit(0, EXIT_FAILURE);
            } else if (kill(n, 0) == 0 || errno != ESRCH) {
                errx("another instance (pid %ld) is already running", n);
                cleanup_and_exit(0, EXIT_FAILURE);
            }
        }
    }

    if (!server_mode) {
        char *line = NULL;
        size_t len = 0;

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd == -1) {
            err("failed to create socket");
            cleanup_and_exit(0, EXIT_FAILURE);
        }

        if (connect(fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr))) {
            err("failed to connect to unix://%s", g.socket);
            close(fd);
            cleanup_and_exit(0, EXIT_FAILURE);
        }

        f = fdopen(fd, "r+");
        if (!f) {
            err("fdopen failed");
            close(fd);
            cleanup_and_exit(0, EXIT_FAILURE);
        }

        rc = EXIT_SUCCESS;
        while (1) {
            ssize_t r = getline(&line, &len, stdin);
            if (r == -1) {
                if (!feof(stdin)) {
                    rc = EXIT_FAILURE;
                    err("failed to get line from stdin");
                }
                break;
            }
            if (fputs(line, f) < 0) {
                rc = EXIT_FAILURE;
                err("failed to write to %s", g.socket);
                break;
            }
            r = getline(&line, &len, f);
            if (r == -1) {
                if (!feof(f)) {
                    rc = EXIT_FAILURE;
                    err("failed to read from %s", g.socket);
                }
                break;
            }
            if (fputs(line, stdout) < 0) {
                rc = EXIT_FAILURE;
                err("failed to write to stdout");
                break;
            }
        }
        free(line);
        fclose(f);
        cleanup_and_exit(0, rc);
    }

    if (g.connect == NULL) {
        errx("-c,--connect must be specified at least once in server mode");
        cleanup_and_exit(0, EXIT_FAILURE);
    } else {
        SGLIB_DL_LIST_REVERSE(str_t, g.connect, prev, next);
        while (g.connect->prev)
            g.connect = g.connect->prev;
    }

    if (g.bind == NULL) {
        str_t *s = calloc(1, sizeof(str_t));
        if (!s) {
            err("calloc");
            cleanup_and_exit(0, EXIT_FAILURE);
        }
        SGLIB_LIST_ADD(str_t, g.bind, s, next)
#if defined(IPV6_V6ONLY)
        if (g.family == AF_UNSPEC) {
            s = calloc(1, sizeof(str_t));
            if (!s) {
                err("calloc");
                cleanup_and_exit(0, EXIT_FAILURE);
            }
            SGLIB_LIST_ADD(str_t, g.bind, s, next)
        }
#endif
    } else {
        SGLIB_LIST_REVERSE(str_t, g.bind, next);
        while (g.bind->prev)
            g.bind = g.bind->prev;
    }

    if (g.daemon) {
        if (pipe(g.pipefd)) {
            err("failed to create pipe");
            cleanup_and_exit(0, EXIT_FAILURE);
        }
        pid = fork();
        if (pid == -1) {
            err("fork failed");
            close(g.pipefd[0]);
            g.pipefd[0] = -1;
            close(g.pipefd[1]);
            g.pipefd[1] = -1;
            cleanup_and_exit(0, EXIT_FAILURE);
        } else if (pid != 0) {
            // parent
            char buf[0x10];
            n = read(g.pipefd[0], buf, sizeof(buf));
            close(g.pipefd[0]);
            g.pipefd[0] = -1;
            close(g.pipefd[1]);
            g.pipefd[1] = -1;
            if (n != 2 || strncmp(buf, "OK", 2) != 0) {
                errx("daemon failed to start");
                cleanup_and_exit(0, EXIT_FAILURE);
            }
            else {
                noticex("daemon started (pid %ld)", (long)pid);
                cleanup_and_exit(0, EXIT_SUCCESS);
            }
        } else {
            // child
            close(g.pipefd[0]);
            g.pipefd[0] = -1;

            if (!g.logfilename) {
                infox("logging to syslog");
                syslog_init();
            }

            if (setsid() == -1) {
                err("setsid failed");
                cleanup_and_exit(0, EXIT_FAILURE);
            }

            mask = umask(0);
            fd = open("/dev/null", O_RDWR);
            umask(mask);
            if (fd == -1) {
                err("open(\"/dev/null\") failed");
                cleanup_and_exit(0, EXIT_FAILURE);
            }

            if (dup2(fd, STDIN_FILENO) == -1) {
                err("dup2(STDIN_FILENO) failed");
                close(fd);
                cleanup_and_exit(0, EXIT_FAILURE);
            }

            if (dup2(fd, STDOUT_FILENO) == -1) {
                err("dup2(STDOUT_FILENO) failed");
                close(fd);
                cleanup_and_exit(0, EXIT_FAILURE);
            }

            if (close(fd) == -1) {
                err("close failed");
                cleanup_and_exit(0, EXIT_FAILURE);
            }
        }
    }

#if defined(USE_GNUTLS)
    if (!gnutls_check_version("3.3.30"))
    {
        errx("GnuTLS version 3.3.30 or later is required");
        cleanup_and_exit(0, EXIT_FAILURE);
    }
    gnutls_global_init();
#elif defined(USE_OPENSSL)
    if (OpenSSL_version_num() < 0x1010100fL) {
        errx("OpenSSL version 1.1.1 or later is required");
        cleanup_and_exit(0, EXIT_FAILURE);
    }
    g.ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g.ssl_ctx) {
        openssl_error("main");
        cleanup_and_exit(0, EXIT_FAILURE);
    }
    if (!SSL_CTX_set_min_proto_version(g.ssl_ctx, TLS1_2_VERSION)) {
        openssl_error("main");
        cleanup_and_exit(1, EXIT_FAILURE);
    }
    g.ssl_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (g.ssl_idx < 0) {
        openssl_error("main");
        cleanup_and_exit(1, EXIT_FAILURE);
    }
    g.bio_idx = BIO_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (g.bio_idx < 0) {
        openssl_error("main");
        cleanup_and_exit(1, EXIT_FAILURE);
    }
    SSL_CTX_set_client_hello_cb(g.ssl_ctx, ssl_client_hello_cb, NULL);
    SSL_CTX_set_alpn_select_cb(g.ssl_ctx, ssl_alpn_select_cb, NULL);
#elif defined(USE_MBEDTLS)
#if defined(MBEDTLS_VERSION_C)
    if (mbedtls_version_get_number() < 0x02100000) {
        errx("mbedTLS version 2.16 or later is required");
        cleanup_and_exit(0, EXIT_FAILURE);
    }
#if MBEDTLS_VERSION_NUMBER < 0x02170000
#if defined(MBEDTLS_VERSION_FEATURES)
    if (mbedtls_version_check_feature(
                "MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION")) {
        errx("mbedTLS earlier than version 2.23 configured without "
                "MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION");
        cleanup_and_exit(0, EXIT_FAILURE);
    }
#else
#warning mbedTLS runtime feature check disabled. Consider reconfiguring \
    mbedTLS with MBEDTLS_VERSION_FEATURES
#endif
#endif
#else
#warning mbedTLS runtime version check disabled. Consider reconfiguring \
    mbedTLS with MBEDTLS_VERSION_C
#endif
    mbedtls_entropy_init(&g.entropy);
    mbedtls_ctr_drbg_init(&g.ctr_drbg);
    rc = mbedtls_ctr_drbg_seed(&g.ctr_drbg, mbedtls_entropy_func,
            &g.entropy, NULL, 0);
    if (rc) {
        errx("mbedtls_ctr_dbg_seed failed: %s", _mbedtls_strerror(rc));
        cleanup_and_exit(1, EXIT_FAILURE);
    }
    const unsigned char id[] = {0x4, 0x1, 0x0};
    if (auth_crt("dummy", id, sizeof(id), &g.crt, &g.crt_len,
                &g.key, &g.key_len))
        cleanup_and_exit(1, EXIT_FAILURE);
#endif

    g.sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g.sockfd == -1) {
        err("failed to create socket");
        cleanup_and_exit(1, EXIT_FAILURE);
    }

    rc = connect(g.sockfd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
    if (rc == 0) {
        errx("another instance is already listening to unix://%s", g.socket);
        close(g.sockfd);
        g.sockfd = -1;
        cleanup_and_exit(1, EXIT_FAILURE);
    }

    if (unlink(g.socket) && errno != ENOENT) {
        err("failed to unlink %s", g.socket);
        cleanup_and_exit(1, EXIT_FAILURE);
    }

    if (setsockopt(g.sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
        warn("failed to set SO_REUSEADDR on unix://%s", g.socket);

    mask = umask(~g.sockmode &
            (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH));
    rc = bind(g.sockfd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
    umask(mask);
    if (rc) {
        err("failed to bind to unix://%s", g.socket);
        cleanup_and_exit(1, EXIT_FAILURE);
    }

    if (listen(g.sockfd, SOMAXCONN)) {
        err("failed to listen to unix://%s", g.socket);
        cleanup_and_exit(1, EXIT_FAILURE);
    }

    if (strstr(PACKAGE_VERSION, "-dev-")) {
        warnx("development version " PACKAGE_VERSION " starting");
        warnx("please use for testing only; releases are available at "
                "https://github.com/ndilieto/uacme/tree/upstream/latest");
    } else
        noticex("version " PACKAGE_VERSION " starting");

    noticex("control interface listening to unix://%s", g.socket);

    g_shm_size = sizeof(struct shm) + (g.max_auths - 1)*sizeof(auth_t);
#if HAVE_MAP_DEVZERO
    g.devzero = open("/dev/zero", O_RDWR);
    if (g.devzero == -1) {
        err("open(\"/dev/zero\") failed");
        cleanup_and_exit(1, EXIT_FAILURE);
    }
    g_shm = (struct shm *)mmap(NULL, g_shm_size, PROT_READ | PROT_WRITE,
            MAP_SHARED, g.devzero, 0);
#elif HAVE_MAP_ANON
#if !defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON
#endif
    g_shm = (struct shm *)mmap(NULL, g_shm_size, PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS|MAP_SHARED, -1, 0);
#endif
    if (g_shm == MAP_FAILED) {
        err("mmap failed");
        cleanup_and_exit(1, EXIT_FAILURE);
    }

    memset(g_shm, 0, g_shm_size);
    for (size_t n = 0; n < g.max_auths; n++)
        SGLIB_DL_LIST_ADD(auth_t, g_shm->avail, g_shm->pool + n, left, right);
    if (sem_init(&g_shm->sem, 1, 1)) {
        err("sem_init failed");
        cleanup_and_exit(2, EXIT_FAILURE);
    }

    if (sem_init(&g_shm->logsem, 1, 1)) {
        err("sem_init failed");
        cleanup_and_exit(3, EXIT_FAILURE);
    }

    if (g.pidfile) {
        f = fopen(g.pidfile, "w");
        if (!f) {
            err("failed to create %s", g.pidfile);
            cleanup_and_exit(4, EXIT_FAILURE);
        }
        if (fprintf(f, "%ld", (long)getpid()) < 0) {
            err("failed to write to %s", g.pidfile);
            fclose(f);
            cleanup_and_exit(4, EXIT_FAILURE);
        }
        if (fclose(f)) {
            err("failed to close %s", g.pidfile);
            cleanup_and_exit(4, EXIT_FAILURE);
        }
    }

    if (getrlimit(RLIMIT_NOFILE, &rl))
        warn("getrlimit failed");
    else {
        struct rlimit rl2 = { rl.rlim_max, rl.rlim_max };
        if (setrlimit(RLIMIT_NOFILE, &rl2))
            warn("setrlimit failed");
        else
            rl = rl2;
        if (rl.rlim_cur != RLIM_INFINITY)
            infox("open file descriptor limit: %lld", (long long)rl.rlim_cur);
    }

    for (n = 0; n < 9; n++) {
        const char *backends[] = {
            "SELECT", "POLL", "EPOLL", "KQUEUE",
            "DEVPOLL", "PORT", "LINUXAIO", "IOURING", "unknown"
        };
        if (n == 8 || (ev_backend(EV_DEFAULT) & (1 << n))) {
            infox("libev initialized (backend %s)", backends[n]);
            break;
        }
    }

    ev_io_init(&g.controller, cb_controller_accept, g.sockfd, EV_READ);
    ev_set_priority(&g.controller, +2);
    ev_io_start(EV_DEFAULT_ &g.controller);

    ev_signal_init(&g.sigint, cb_signal, SIGINT);
    ev_signal_start(EV_DEFAULT_ &g.sigint);

    ev_signal_init(&g.sigterm, cb_signal, SIGTERM);
    ev_signal_start(EV_DEFAULT_ &g.sigterm);

    ev_timer_init(&g.timer, cb_timer, 0.1, 1.0);
    ev_set_priority(&g.timer, +2);
    ev_timer_start(EV_DEFAULT_ &g.timer);

    ev_cleanup_init(&g.cleanup, cb_cleanup);
    ev_cleanup_start(EV_DEFAULT_ &g.cleanup);

    for (str = g.bind; str; str = str->next) {
        int family = g.family;
        if (!str->str && g.family == AF_UNSPEC) {
#if defined(IPV6_V6ONLY)
            family = (str == g.bind) ? AF_INET6 : AF_INET;
#else
            family = AF_INET6;
#endif
        }
        rc = parse_addr(str->str, flags | AI_PASSIVE, family, &ai);
        if (rc != 0) {
            warnx("failed to parse address '%s': %s", str->str,
                    rc == EAI_SYSTEM ? strerror(errno) : gai_strerror(rc));
            continue;
        }
        for (struct addrinfo *a = ai; a; a = a->ai_next) {
            rc = getnameinfo(a->ai_addr, a->ai_addrlen, host, sizeof(host),
                    port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
            if (rc) {
                warn("getnameinfo failed: %s", rc == EAI_SYSTEM ?
                        strerror(errno) : gai_strerror(rc));
                continue;
            }

            fd = socket(a->ai_family, SOCK_STREAM, 0);
            if (fd == -1) {
                warn("failed to create socket for %s:%s", host, port);
                continue;
            }
#if defined(IPV6_V6ONLY)
            if ((a->ai_family == AF_INET6 && setsockopt(fd, IPPROTO_IPV6,
                            IPV6_V6ONLY, &one, sizeof(one)))) {
                warn("failed to set IPV6_V6ONLY for %s:%s", host, port);
                close(fd);
                continue;
            }
#endif
            if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
                warn("failed to set SO_REUSEADDR for %s:%s", host, port);
                close(fd);
                continue;
            }

            if (bind(fd, a->ai_addr, a->ai_addrlen)) {
                warn("failed to bind to %s:%s", host, port);
                close(fd);
                continue;
            }

            if (listen(fd, SOMAXCONN)) {
                warn("failed to listen to %s:%s", host, port);
                close(fd);
                continue;
            }

            if (set_nonblocking(fd)) {
                warn("failed to set O_NONBLOCK on %s:%s", host, port);
                close(fd);
                continue;
            }

            listener_t *l = calloc(1, sizeof(*l));
            if (!l) {
                warn("calloc failed for %s:%s", host, port);
                close(fd);
                continue;
            }

            ev_io_init(&l->io, cb_client_accept, fd, EV_READ);
            ev_set_priority(&l->io, +1);
            ev_io_start(EV_DEFAULT_ &l->io);

            SGLIB_LIST_ADD(listeners_t, g.listeners, l, next);
            noticex("frontend listening to %s:%s", host, port);
            break;
        }
        freeaddrinfo(ai);
    }

    if (g.user) {
        if (g.socket && chown(g.socket, g.uid, g.gid))
            warn("failed to change owner/group of %s", g.socket);
        if (g.pidfile && chown(g.pidfile, g.uid, g.gid))
            warn("failed to change owner/group of %s", g.pidfile);
        if (g.logfilename && chown(g.logfilename, g.uid, g.gid))
            warn("failed to change owner/group of %s", g.logfilename);
    }

    if (g.chroot) {
        if (chdir(g.chroot)) {
            err("chdir(\"%s\") failed", g.chroot);
            cleanup_and_exit(4, EXIT_FAILURE);
        }
        noticex("changing root directory (%s)", g.chroot);
        if (g.daemon && !g.logfilename) {
            struct stat st;
            if (stat("dev/log", &st)) {
                if (errno == ENOENT)
                    warnx("%s/dev/log missing, logging will probably not work",
                            g.chroot);
                else {
                    err("stat(\"%s/dev/log\") failed", g.chroot);
                    cleanup_and_exit(4, EXIT_FAILURE);
                }
            } else if (!S_ISSOCK(st.st_mode))
                warnx("%s/dev/log is no socket, logging will probably not work",
                            g.chroot);
        }
        if (chroot(".")) {
            err("chroot(\"%s\") failed", g.chroot);
            cleanup_and_exit(4, EXIT_FAILURE);
        }
    }

    if (g.group) {
        noticex("changing group (%s)", g.group);
        if (setgid(g.gid) != 0) {
            err("setgid(%d) failed", g.gid);
            cleanup_and_exit(4, EXIT_FAILURE);
        }
        if (initgroups(g.user, g.gid) != 0) {
            warn("initgroups(\"%s\", %d) failed", g.user, g.gid);
        }
    }

    if (g.user) {
        noticex("changing user (%s)", g.user);
        if (setuid(g.uid) != 0) {
            err("setuid(%d) failed", g.uid);
            cleanup_and_exit(4, EXIT_FAILURE);
        }
    }

    if (g.listeners) {
        if (g.daemon) {
            if (write(g.pipefd[1], "OK", 2) != 2) {
                err("failed to write to pipe");
                cleanup_and_exit(4, EXIT_FAILURE);
            }
            close(g.pipefd[1]);
            g.pipefd[1] = -1;
            if (dup2(STDOUT_FILENO, STDERR_FILENO) == -1) {
                err("dup2(STDERR_FILENO) failed");
                cleanup_and_exit(4, EXIT_FAILURE);
            }
            if (!g.logfilename)
                g.logfile = NULL;
        }
        ev_run(EV_DEFAULT_ 0);
        cleanup_and_exit(UINT_MAX, EXIT_SUCCESS);
    } else {
        errx("failed to listen to all address");
        cleanup_and_exit(UINT_MAX, EXIT_FAILURE);
    }

    // it should never get here
    return EXIT_FAILURE;
}

