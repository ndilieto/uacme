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

#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "base64.h"
#include "crypto.h"
#include "curlwrap.h"
#include "json.h"
#include "msg.h"
#if !defined(USE_OPENSSL)
#include "read-file.h"
#endif

#if defined(USE_GNUTLS)
#include <gnutls/crypto.h>
#include <gnutls/ocsp.h>
#if HAVE_GNUTLS_X509_CRQ_SET_TLSFEATURES
#include <gnutls/x509-ext.h>
#endif
#if !HAVE_GNUTLS_DECODE_RS_VALUE
#include <libtasn1.h>
#endif
#elif defined(USE_OPENSSL)
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ocsp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#elif defined(USE_MBEDTLS)
#include <mbedtls/asn1write.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/sha1.h>
#include <mbedtls/version.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#endif

#if defined(USE_GNUTLS)
#if GNUTLS_VERSION_NUMBER < 0x03031e
#error GnuTLS version 3.3.30 or later is required
#endif

bool crypto_init(void)
{
#if HAVE_GNUTLS_DECODE_RS_VALUE
    if (!gnutls_check_version("3.6.0")) {
        warnx("crypto_init: GnuTLS version 3.6.0 or later is required");
#elif HAVE_GNUTLS_X509_CRQ_SET_TLSFEATURES
    if (!gnutls_check_version("3.5.1")) {
        warnx("crypto_init: GnuTLS version 3.5.1 or later is required");
#else
    if (!gnutls_check_version("3.3.30")) {
        warnx("crypto_init: GnuTLS version 3.3.30 or later is required");
#endif
        return false;
    }
    gnutls_global_init();
    return true;
}

void crypto_deinit(void)
{
    gnutls_global_deinit();
}
#elif defined(USE_OPENSSL)
#if OPENSSL_VERSION_NUMBER < 0x1010100fL
#error OpenSSL version 1.1.1 or later is required
#endif
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3040200fL
#error LibreSSL version 3.4.2 or later is required
#endif

bool crypto_init(void)
{
    if (OpenSSL_version_num() < 0x1010100fL) {
        warnx("crypto_init: openssl version 1.1.1 or later is required");
        return false;
    }
    return true;
}

void crypto_deinit(void)
{
}

static void openssl_error(const char *prefix)
{
    unsigned long e;
    while ((e = ERR_get_error()) != 0) {
        warnx("%s: openssl %s", prefix, ERR_error_string(e, NULL));
        return;
    }
}

static bool openssl_hash_fast(const EVP_MD *type,
        const void *input, size_t len, unsigned char *output)
{
    bool success = false;
    EVP_MD_CTX *emc = EVP_MD_CTX_create();
    if (!emc) {
        openssl_error("openssl_hash_fast");
        goto out;
    }
    if (!EVP_DigestInit_ex(emc, type, NULL)) {
        openssl_error("openssl_hash_fast");
        goto out;
    }
    if (!EVP_DigestUpdate(emc, input, len)) {
        openssl_error("openssl_hash_fast");
        goto out;
    }
    if (!EVP_DigestFinal_ex(emc, output, NULL)) {
        openssl_error("openssl_hash_fast");
        goto out;
    }
    success = true;
out:
    if (emc)
        EVP_MD_CTX_destroy(emc);
    return success;
}

static bool openssl_hmac_fast(const EVP_MD *type, const void *key,
        size_t keylen, const void *input, size_t len, unsigned char *output)
{
    if (HMAC(type, key, keylen, input, len, output, NULL) == NULL) {
        openssl_error("openssl_hmac_fast");
        return false;
    }
    return true;
}
#elif defined(USE_MBEDTLS)
#if MBEDTLS_VERSION_NUMBER < 0x02100000
#error mbedTLS 2.x version 2.16 or later is required
#endif
#if MBEDTLS_VERSION_NUMBER >= 0x03000000 && MBEDTLS_VERSION_NUMBER < 0x03020000
#error mbedTLS 3.x version 3.2 or later is required
#endif

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static const char *_mbedtls_strerror(int code)
{
    static char buf[0x100];
    mbedtls_strerror(code, buf, sizeof(buf));
    return buf;
}

bool crypto_init(void)
{
#if defined(MBEDTLS_VERSION_C)
    unsigned int version = mbedtls_version_get_number();
    if (version < 0x02100000) {
        warnx("crypto_init: mbedTLS 2.x version 2.16 or later is required");
        return false;
    }
    if (version >= 0x03000000 && version < 0x03020000) {
        warnx("crypto_init: mbedTLS 3.x version 3.2 or later is required");
        return false;
    }
#endif
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
            &entropy, NULL, 0);
    if (r) {
        warnx("crypto_init: mbedtls_ctr_dbg_seed failed: %s",
                _mbedtls_strerror(r));
        return false;
    }
    return true;
}

void crypto_deinit(void)
{
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

static int mbedtls_hash_fast(mbedtls_md_type_t md_type,
        const void *input, size_t len, unsigned char *output)
{
    const mbedtls_md_info_t *mdi = mbedtls_md_info_from_type(md_type);
    if (!mdi) {
        warnx("mbedtls_hash_fast: md_info not found");
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }
    return mbedtls_md(mdi, input, len, output);
}

static int mbedtls_hmac_fast(mbedtls_md_type_t md_type, const void *key,
        size_t keylen, const void *input, size_t len, unsigned char *output)
{
    const mbedtls_md_info_t *mdi = mbedtls_md_info_from_type(md_type);
    if (!mdi) {
        warnx("mbedtls_hmac_fast: md_info not found");
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }
    return mbedtls_md_hmac(mdi, key, keylen, input, len, output);
}
#endif

#if !HAVE_STRCASESTR
char *strcasestr(const char *haystack, const char *needle)
{
    char *ret = NULL;
    char *_haystack = strdup(haystack);
    char *_needle = strdup(needle);

    if (!_haystack || !_needle)
        warn("strcasestr: strdup failed");
    else {
        char *p;
        for (p = _haystack; *p; p++)
            *p = tolower(*p);
        for (p = _needle; *p; p++)
            *p = tolower(*p);
        ret = strstr(_haystack, _needle);
        if (ret)
            ret = (char *)haystack + (ret - _haystack);
    }
    free(_haystack);
    free(_needle);
    return ret;
}
#endif

char *sha2_base64url(size_t bits, const char *format, ...)
{
    char *input = NULL;
    size_t encoded_hash_len;
    char *encoded_hash = NULL;
    const unsigned int hash_len = (bits+7)/8;
    unsigned char *hash = NULL;
    va_list ap;
    va_start(ap, format);
    if (vasprintf(&input, format, ap) < 0) {
        warnx("sha2_base64url: vasprintf failed");
        input = NULL;
        goto out;
    }

    hash = calloc(1, hash_len);
    if (!hash) {
        warn("sha2_base64url: calloc failed");
        goto out;
    }

#if defined(USE_GNUTLS)
    gnutls_digest_algorithm_t type;
#elif defined(USE_OPENSSL)
    const EVP_MD *type;
#elif defined(USE_MBEDTLS)
    mbedtls_md_type_t type;
#endif
    switch (bits) {
        case 256:
#if defined(USE_GNUTLS)
            type = GNUTLS_DIG_SHA256;
#elif defined(USE_OPENSSL)
            type = EVP_sha256();
#elif defined(USE_MBEDTLS)
            type = MBEDTLS_MD_SHA256;
#endif
            break;

        case 384:
#if defined(USE_GNUTLS)
            type = GNUTLS_DIG_SHA384;
#elif defined(USE_OPENSSL)
            type = EVP_sha384();
#elif defined(USE_MBEDTLS)
            type = MBEDTLS_MD_SHA384;
#endif
            break;

        default:
            warnx("sha2_base64url: invalid hash bit length");
            goto out;
    }

#if defined(USE_GNUTLS)
    int r = gnutls_hash_fast(type, input, strlen(input), hash);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("sha2_base64url: gnutls_hash_fast failed: %s",
                gnutls_strerror(r));
        goto out;
    }
#elif defined(USE_OPENSSL)
    if (!openssl_hash_fast(type, input, strlen(input), hash)) {
        warnx("sha2_base64url: openssl_hash_fast failed");
        goto out;
    }
#elif defined(USE_MBEDTLS)
    int r = mbedtls_hash_fast(type, input, strlen(input), hash);
    if (r != 0) {
        warnx("sha2_base64url: mbedtls_hash_fast failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
#endif
    encoded_hash_len = base64_ENCODED_LEN(hash_len,
            base64_VARIANT_URLSAFE_NO_PADDING);
    encoded_hash = calloc(1, encoded_hash_len);
    if (!encoded_hash) {
        warn("sha2_base64url: calloc failed");
        goto out;
    }
    if (!bin2base64(encoded_hash, encoded_hash_len,
                hash, hash_len, base64_VARIANT_URLSAFE_NO_PADDING)) {
        warnx("sha2_base64url: bin2base64 failed");
        free(encoded_hash);
        encoded_hash = NULL;
        goto out;
    }
out:
    va_end(ap);
    free(input);
    free(hash);
    return encoded_hash;
}

char *hmac_base64url(size_t bits, const char *key, const char *format, ...)
{
    char *input = NULL;
    size_t encoded_hash_len;
    char *encoded_hash = NULL;
    const unsigned int hash_len = (bits+7)/8;
    unsigned char *hash = NULL;
    size_t keylen = strlen(key);
    void *keybin = NULL;
    va_list ap;
    va_start(ap, format);
    if (vasprintf(&input, format, ap) < 0) {
        warnx("hmac_base64url: vasprintf failed");
        input = NULL;
        goto out;
    }

    hash = calloc(1, hash_len);
    if (!hash) {
        warn("hmac_base64url: calloc failed");
        goto out;
    }

    keybin = calloc(1, keylen);
    if (!keybin) {
        warn("hmac_base64url: calloc failed");
        goto out;
    }

    if (base642bin(keybin, keylen, key, keylen, NULL, &keylen, NULL,
                    base64_VARIANT_URLSAFE_NO_PADDING)) {
        warnx("hmac_base64url: failed to decode key");
        goto out;
    }

#if defined(USE_GNUTLS)
    gnutls_mac_algorithm_t type;
#elif defined(USE_OPENSSL)
    const EVP_MD *type;
#elif defined(USE_MBEDTLS)
    mbedtls_md_type_t type;
#endif
    switch (bits) {
        case 256:
#if defined(USE_GNUTLS)
            type = GNUTLS_MAC_SHA256;
#elif defined(USE_OPENSSL)
            type = EVP_sha256();
#elif defined(USE_MBEDTLS)
            type = MBEDTLS_MD_SHA256;
#endif
            break;

        case 384:
#if defined(USE_GNUTLS)
            type = GNUTLS_MAC_SHA384;
#elif defined(USE_OPENSSL)
            type = EVP_sha384();
#elif defined(USE_MBEDTLS)
            type = MBEDTLS_MD_SHA384;
#endif
            break;

        case 512:
#if defined(USE_GNUTLS)
            type = GNUTLS_MAC_SHA512;
#elif defined(USE_OPENSSL)
            type = EVP_sha512();
#elif defined(USE_MBEDTLS)
            type = MBEDTLS_MD_SHA512;
#endif
            break;

        default:
            warnx("hmac_base64url: invalid hmac bit length");
            goto out;
    }

#if defined(USE_GNUTLS)
    int r = gnutls_hmac_fast(type, keybin, keylen, input, strlen(input), hash);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("hmac_base64url: gnutls_hmac_fast failed: %s",
                gnutls_strerror(r));
        goto out;
    }
#elif defined(USE_OPENSSL)
    if (!openssl_hmac_fast(type, keybin, keylen, input, strlen(input), hash)) {
        warnx("hmac_base64url: openssl_hmac_fast failed");
        goto out;
    }
#elif defined(USE_MBEDTLS)
    int r = mbedtls_hmac_fast(type, keybin, keylen, input, strlen(input), hash);
    if (r != 0) {
        warnx("hmac_base64url: mbedtls_hmac_fast failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
#endif
    encoded_hash_len = base64_ENCODED_LEN(hash_len,
            base64_VARIANT_URLSAFE_NO_PADDING);
    encoded_hash = calloc(1, encoded_hash_len);
    if (!encoded_hash) {
        warn("hmac_base64url: calloc failed");
        goto out;
    }
    if (!bin2base64(encoded_hash, encoded_hash_len,
                hash, hash_len, base64_VARIANT_URLSAFE_NO_PADDING)) {
        warnx("hmac_base64url: bin2base64 failed");
        free(encoded_hash);
        encoded_hash = NULL;
        goto out;
    }
out:
    va_end(ap);
    free(input);
    free(hash);
    free(keybin);
    return encoded_hash;
}

static char *bn2str(const unsigned char *data, size_t data_len, size_t pad_len)
{
    char *ret = NULL;
    unsigned char *buf = NULL;

    while (data_len && !*data) {
        data++;
        data_len--;
    }

    if (pad_len == 0)
        pad_len = data_len;
    else if (pad_len < data_len) {
        warnx("bn2str: insufficient pad_len");
        goto out;
    }

    buf = calloc(1, pad_len);
    if (!buf) {
        warn("bn2str: calloc failed");
        goto out;
    }
    memcpy(buf + pad_len - data_len, data, data_len);

    size_t encoded_len = base64_ENCODED_LEN(pad_len,
            base64_VARIANT_URLSAFE_NO_PADDING);
    ret = calloc(1, encoded_len);
    if (!ret) {
        warn("bn2str: calloc failed");
        goto out;
    }
    if (!bin2base64(ret, encoded_len, buf, pad_len,
                base64_VARIANT_URLSAFE_NO_PADDING)) {
        free(ret);
        ret = NULL;
    }
out:
    free(buf);
    return ret;
}

static bool rsa_params(privkey_t key, char **m, char **e)
{
    int r;
    char *_m = NULL;
    char *_e = NULL;
#if defined(USE_GNUTLS)
    gnutls_datum_t mod = {NULL, 0};
    gnutls_datum_t exp = {NULL, 0};
    if (gnutls_privkey_get_pk_algorithm(key, NULL) != GNUTLS_PK_RSA) {
        warnx("rsa_params: not a RSA key");
        goto out;
    }
    r = gnutls_privkey_export_rsa_raw(key, &mod, &exp,
            NULL, NULL, NULL, NULL, NULL, NULL);
    if (r < 0) {
        warnx("rsa_params: gnutls_privkey_export_rsa_raw: %s",
                gnutls_strerror(r));
        goto out;
    }
    _m = bn2str(mod.data, mod.size, 0);
    if (!_m) {
        warnx("rsa_params: bn2str failed");
        goto out;
    }
    _e = bn2str(exp.data, exp.size, 0);
    if (!_e) {
        warnx("rsa_params: bn2str failed");
        goto out;
    }
#elif defined(USE_OPENSSL)
    unsigned char *data = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BIGNUM *bm = NULL;
    BIGNUM *be = NULL;
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &bm)) {
        openssl_error("rsa_params");
        goto out;
    }
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &be)) {
        openssl_error("rsa_params");
        goto out;
    }
#else
    const BIGNUM *bm = NULL;
    const BIGNUM *be = NULL;
    RSA *rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa) {
        openssl_error("rsa_params");
        goto out;
    }
    RSA_get0_key(rsa, &bm, &be, NULL);
#endif
    r = BN_num_bytes(bm);
    data = calloc(1, r);
    if (!data) {
        warn("rsa_params: calloc failed");
        goto out;
    }
    if (BN_bn2bin(bm, data) != r) {
        openssl_error("rsa_params");
        goto out;
    }
    _m = bn2str(data, r, 0);
    if (!_m) {
        warnx("rsa_params: bn2str failed");
        goto out;
    }
    free(data);
    r = BN_num_bytes(be);
    data = calloc(1, r);
    if (!data) {
        warn("rsa_params: calloc failed");
        goto out;
    }
    if (BN_bn2bin(be, data) != r) {
        openssl_error("rsa_params");
        goto out;
    }
    _e = bn2str(data, r, 0);
    if (!_e) {
        warnx("rsa_params: bn2str failed");
        goto out;
    }
#elif defined(USE_MBEDTLS)
    unsigned char *data = NULL;
    size_t len;
    mbedtls_mpi mn, me;
    mbedtls_mpi_init(&mn);
    mbedtls_mpi_init(&me);
    if (!mbedtls_pk_can_do(key, MBEDTLS_PK_RSA)) {
        warnx("rsa_params: not a RSA key");
        goto out;
    }
    const mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*key);
    r = mbedtls_rsa_export(rsa, &mn, NULL, NULL, NULL, &me);
    if (r) {
        warnx("rsa_params: mbedtls_rsa_export failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    len = mbedtls_mpi_size(&mn);
    data = calloc(1, len);
    if (!data) {
        warnx("rsa_params: calloc failed");
        goto out;
    }
    r = mbedtls_mpi_write_binary(&mn, data, len);
    if (r) {
        warnx("rsa_params: mbedtls_mpi_write_binary failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    _m = bn2str(data, len, 0);
    if (!_m) {
        warnx("rsa_params: bn2str failed");
        goto out;
    }
    free(data);
    len = mbedtls_mpi_size(&me);
    data = calloc(1, len);
    if (!data) {
        warnx("rsa_params: calloc failed");
        goto out;
    }
    r = mbedtls_mpi_write_binary(&me, data, len);
    if (r) {
        warnx("rsa_params: mbedtls_mpi_write_binary failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    _e = bn2str(data, len, 0);
    if (!_e) {
        warnx("rsa_params: bn2str failed");
        goto out;
    }
#endif
out:
#if defined(USE_GNUTLS)
    free(mod.data);
    free(exp.data);
#elif defined(USE_OPENSSL)
    free(data);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (bm)
        BN_free(bm);
    if (be)
        BN_free(be);
#endif
#elif defined(USE_MBEDTLS)
    free(data);
    mbedtls_mpi_free(&mn);
    mbedtls_mpi_free(&me);
#endif
    if (_e && _m) {
        if (e)
            *e = _e;
        else
            free(_e);
        if (m)
            *m = _m;
        else
            free(_m);
        return true;
    } else {
        free(_e);
        free(_m);
        return false;
    }
}

static size_t ec_params(privkey_t key, char **x, char **y)
{
    int r;
    size_t bits = 0;
    char *_x = NULL;
    char *_y = NULL;
#if defined(USE_GNUTLS)
    gnutls_ecc_curve_t curve;
    gnutls_datum_t dx = {NULL, 0};
    gnutls_datum_t dy = {NULL, 0};
    if (gnutls_privkey_get_pk_algorithm(key, NULL) != GNUTLS_PK_EC) {
        warnx("ec_params: not a EC key");
        goto out;
    }
    r = gnutls_privkey_export_ecc_raw(key, &curve, &dx, &dy, NULL);
    if (r < 0) {
        warnx("ec_params: gnutls_privkey_export_ecc_raw: %s",
                gnutls_strerror(r));
        goto out;
    }
    switch (curve) {
        case GNUTLS_ECC_CURVE_SECP256R1:
            bits = 256;
            break;

        case GNUTLS_ECC_CURVE_SECP384R1:
            bits = 384;
            break;

        default:
            warnx("ec_params: only \"prime256v1\" and \"secp384r1\" "
                    "Elliptic Curves supported");
            goto out;
    }
    _x = bn2str(dx.data, dx.size, (bits+7)/8);
    if (!_x) {
        warnx("ec_params: bn2str failed");
        goto out;
    }
    _y = bn2str(dy.data, dy.size, (bits+7)/8);
    if (!_y) {
        warnx("ec_params: bn2str failed");
        goto out;
    }
#elif defined(USE_OPENSSL)
    unsigned char *data = NULL;
    BIGNUM *bx = BN_new();
    BIGNUM *by = BN_new();
    if (!bx || !by) {
        openssl_error("ec_params");
        goto out;
    }
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    char group[0x20];
    if (!EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                group, sizeof(group), NULL)) {
        openssl_error("ec_params");
        goto out;
    }
    if (strcasecmp(group, "prime256v1") == 0)
        bits = 256;
    else if (strcasecmp(group, "secp384r1") == 0)
        bits = 384;
    else {
        warnx("ec_params: only \"prime256v1\" and \"secp384r1\" "
                "Elliptic Curves supported");
        goto out;
    }
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &bx)) {
        openssl_error("ec_params");
        goto out;
    }
    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &by)) {
        openssl_error("ec_params");
        goto out;
    }
#else
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(key);
    if (!ec) {
        openssl_error("ec_params");
        goto out;
    }
    const EC_GROUP *g = EC_KEY_get0_group(ec);
    if (!g) {
        openssl_error("ec_params");
    }
    switch (EC_GROUP_get_curve_name(g)) {
        case NID_X9_62_prime256v1:
            bits = 256;
            break;

        case NID_secp384r1:
            bits = 384;
            break;

        default:
            warnx("ec_params: only \"prime256v1\" and \"secp384r1\" "
                    "Elliptic Curves supported");
            goto out;
    }
    const EC_POINT *pubkey = EC_KEY_get0_public_key(ec);
    if (!pubkey) {
        openssl_error("ec_params");
        goto out;
    }
    if (!EC_POINT_get_affine_coordinates(g, pubkey, bx, by, NULL)) {
        openssl_error("ec_params");
        goto out;
    }
#endif
    r = BN_num_bytes(bx);
    data = calloc(1, r);
    if (!data) {
        warn("ec_params: calloc failed");
        goto out;
    }
    if (BN_bn2bin(bx, data) != r) {
        openssl_error("ec_params");
        goto out;
    }
    _x = bn2str(data, r, (bits+7)/8);
    if (!_x) {
        warnx("ec_params: bn2str failed");
        goto out;
    }
    free(data);
    r = BN_num_bytes(by);
    data = calloc(1, r);
    if (!data) {
        warn("ec_params: calloc failed");
        goto out;
    }
    if (BN_bn2bin(by, data) != r) {
        openssl_error("ec_params");
        goto out;
    }
    _y = bn2str(data, r, (bits+7)/8);
    if (!_y) {
        warnx("ec_params: bn2str failed");
        goto out;
    }
#elif defined(USE_MBEDTLS)
    unsigned char *data = NULL;
    size_t len, olen, plen;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    if (!mbedtls_pk_can_do(key, MBEDTLS_PK_ECKEY)) {
        warnx("ec_params: not a EC key");
        goto out;
    }
    const mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*key);
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_mpi d;
    mbedtls_mpi_init(&d);
    r = mbedtls_ecp_export(ec, &grp, &d, &Q);
    mbedtls_mpi_free(&d);
    if (r) {
        warnx("ec_params: mbedtls_ecp_export failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
#else
    r = mbedtls_ecp_group_copy(&grp, &ec->grp);
    if (r) {
        warnx("ec_params: mbedtls_ecp_group_copy failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    r = mbedtls_ecp_copy(&Q, &ec->Q);
    if (r) {
        warnx("ec_params: mbedtls_ecp_copy failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
#endif
    switch (grp.id) {
        case MBEDTLS_ECP_DP_SECP256R1:
            bits = 256;
            break;

        case MBEDTLS_ECP_DP_SECP384R1:
            bits = 384;
            break;

        default:
            warnx("ec_params: only \"prime256v1\" and \"secp384r1\" "
                    "Elliptic Curves supported");
            goto out;
    }
    plen = mbedtls_mpi_size(&grp.P);
    len = 1 + 2 * plen;
    data = calloc(1, len);
    if (!data) {
        warnx("ec_params: calloc failed");
        goto out;
    }
    r = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
            &olen, data, len);
    if (r) {
        warnx("ec_params: mbedtls_ecp_point_write_binary failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    if (olen != len) {
        warnx("ec_params: wrong length (actual %zu, expected %zu)", olen, len);
        goto out;
    }
    if (data[0] != 0x04) {
        warnx("ec_params: key data corruption");
        goto out;
    }
    _x = bn2str(data + 1, plen, (bits+7)/8);
    if (!_x) {
        warnx("ec_params: bn2str failed");
        goto out;
    }
    _y = bn2str(data + 1 + plen, plen, (bits+7)/8);
    if (!_y) {
        warnx("ec_params: bn2str failed");
        goto out;
    }
#endif
out:
#if defined(USE_GNUTLS)
    free(dx.data);
    free(dy.data);
#elif defined(USE_OPENSSL)
    if (bx)
        BN_free(bx);
    if (by)
        BN_free(by);
    free(data);
#elif defined(USE_MBEDTLS)
    free(data);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
#endif
    if (_x && _y) {
        if (x)
            *x = _x;
        else
            free(_x);
        if (y)
            *y = _y;
        else
            free(_y);
        return bits;
    } else {
        free(_x);
        free(_y);
        return 0;
    }
}

keytype_t key_type(privkey_t key)
{
#if defined(USE_GNUTLS)
    switch (gnutls_privkey_get_pk_algorithm(key, NULL)) {
        case GNUTLS_PK_RSA:
            return PK_RSA;
        case GNUTLS_PK_EC:
            return PK_EC;
#elif defined(USE_OPENSSL)
    switch (EVP_PKEY_base_id(key)) {
        case EVP_PKEY_RSA:
            return PK_RSA;
        case EVP_PKEY_EC:
            return PK_EC;
#elif defined(USE_MBEDTLS)
    switch (mbedtls_pk_get_type(key)) {
        case MBEDTLS_PK_RSA:
            return PK_RSA;
        case MBEDTLS_PK_ECKEY:
            return PK_EC;
#endif
        default:
            return PK_NONE;
    }
}

char *jws_jwk(privkey_t key, const char **crv, const char **alg)
{
    char *ret = NULL;
    char *p1 = NULL;
    char *p2 = NULL;
    const char *_crv = NULL;
    switch (key_type(key)) {
        case PK_RSA:
            if (!rsa_params(key, &p1, &p2)) {
                warnx("jws_jwk: rsa_params failed");
                goto out;
            }
            if (asprintf(&ret, "{\"kty\":\"RSA\",\"n\":\"%s\",\"e\":\"%s\"}",
                        p1, p2) < 0) {
                warnx("jws_jwk: asprintf failed");
                ret = NULL;
                goto out;
            }
            if (alg) *alg = "RS256";
            break;

        case PK_EC:
            switch (ec_params(key, &p1, &p2)) {
                case 0:
                    warnx("jws_jwk: ec_params failed");
                    goto out;

                case 256:
                    _crv = "P-256";
                    if (crv) *crv = _crv;
                    if (alg) *alg = "ES256";
                    break;

                case 384:
                    _crv = "P-384";
                    if (crv) *crv = _crv;
                    if (alg) *alg = "ES384";
                    break;

                default:
                    warnx("jws_jwk: unsupported EC curve");
                    goto out;
            }
            if (asprintf(&ret, "{\"kty\":\"EC\",\"crv\":\"%s\","
                        "\"x\":\"%s\",\"y\":\"%s\"}", _crv, p1, p2) < 0) {
                warnx("jws_jwk: asprintf failed");
                ret = NULL;
                goto out;
            }
            break;

        default:
            warnx("jws_jwk: only RSA/EC keys are supported");
            goto out;
    }
 out:
    free(p1);
    free(p2);
    return ret;
}

char *jws_protected_jwk(const char *nonce, const char *url,
        privkey_t key)
{
    char *ret = NULL;
    const char *crv = NULL;
    const char *alg = NULL;
    char *jwk = jws_jwk(key, &crv, &alg);
    if (!jwk) {
        warnx("jws_protected_jwk: jws_jwk failed");
        goto out;
    }

    if (nonce) {
        if (asprintf(&ret, "{\"alg\":\"%s\",\"nonce\":\"%s\","
                    "\"url\":\"%s\",\"jwk\":%s}", alg, nonce, url, jwk) < 0) {
            warnx("jws_protected_jwk: asprintf failed");
            ret = NULL;
        }
    } else {
        if (asprintf(&ret, "{\"alg\":\"%s\",\"url\":\"%s\",\"jwk\":%s}",
                    alg, url, jwk) < 0) {
            warnx("jws_protected_jwk: asprintf failed");
            ret = NULL;
        }
    }
out:
    free(jwk);
    return ret;
}

char *jws_protected_kid(const char *nonce, const char *url,
        const char *kid, privkey_t key)
{
    char *ret = NULL;
    const char *alg = NULL;
    switch (key_type(key)) {
        case PK_RSA:
            alg = "RS256";
            break;

        case PK_EC:
            switch (ec_params(key, NULL, NULL)) {
                case 0:
                    warnx("jws_protected_kid: ec_params failed");
                    goto out;

                case 256:
                    alg = "ES256";
                    break;

                case 384:
                    alg = "ES384";
                    break;

                default:
                    warnx("jws_protected_kid: unsupported EC curve");
                    goto out;
            }
            break;

        default:
            warnx("jws_protected_kid: only RSA/EC keys are supported");
            goto out;
    }
    if (asprintf(&ret, "{\"alg\":\"%s\",\"nonce\":\"%s\","
                "\"url\":\"%s\",\"kid\":\"%s\"}", alg, nonce, url, kid) < 0) {
        warnx("jws_protected_kid: asprintf failed");
        ret = NULL;
    }
out:
    return ret;
}

char *jws_protected_eab(size_t bits, const char *keyid, const char *url)
{
    char *ret = NULL;
    if (asprintf(&ret, "{\"alg\":\"HS%zu\",\"kid\":\"%s\",\"url\":\"%s\"}",
            bits, keyid, url) < 0) {
        warnx("jws_protected_eab: asprintf failed");
        ret = NULL;
    }
    return ret;
}

char *jws_thumbprint(privkey_t key)
{
    char *ret = NULL;
    char *p1 = NULL;
    char *p2 = NULL;
    const char *crv = NULL;
    switch (key_type(key)) {
        case PK_RSA:
            if (!rsa_params(key, &p1, &p2)) {
                warnx("jws_thumbprint: rsa_params failed");
                goto out;
            }
            ret = sha2_base64url(256, "{\"e\":\"%s\",\"kty\":\"RSA\","
                    "\"n\":\"%s\"}", p2, p1);
            if (!ret)
                warnx("jws_thumbprint: sha2_base64url failed");
            break;

        case PK_EC:
            switch (ec_params(key, &p1, &p2)) {
                case 0:
                    warnx("jws_thumbprint: ec_params failed");
                    goto out;

                case 256:
                    crv = "P-256";
                    break;

                case 384:
                    crv = "P-384";
                    break;

                default:
                    warnx("jws_thumbprint: unsupported EC curve");
                    goto out;
            }
            ret = sha2_base64url(256, "{\"crv\":\"%s\",\"kty\":\"EC\","
                    "\"x\":\"%s\",\"y\":\"%s\"}", crv, p1, p2);
            if (!ret)
                warnx("jws_thumbprint: sha2_base64url failed");
            break;

        default:
            warnx("jws_thumbprint: only RSA/EC keys are supported");
            goto out;
    }
out:
    free(p1);
    free(p2);
    return ret;
}

#if defined(USE_GNUTLS)
static unsigned char *gnutls_datum_data(gnutls_datum_t *d, bool free)
{
    unsigned char *ret = malloc(d->size);
    if (!ret) {
        warn("gnutls_datum2mem: malloc failed");
        goto out;
    }
    memcpy(ret, d->data, d->size);
    if (free) {
        gnutls_free(d->data);
        d->data = NULL;
    }
out:
    return ret;
}
#endif

bool ec_decode(size_t hash_size, unsigned char **sig, size_t *sig_size)
{
    int r;
#if defined(USE_GNUTLS)
#if HAVE_GNUTLS_DECODE_RS_VALUE
    gnutls_datum_t dr = {NULL, 0};
    gnutls_datum_t ds = {NULL, 0};
    gnutls_datum_t dsig = {*sig, *sig_size};
    r = gnutls_decode_rs_value(&dsig, &dr, &ds);
    if (r < 0) {
        warnx("ec_decode: gnutls_decode_rs_value: %s", gnutls_strerror(r));
        return false;
    }
    unsigned char *tmp = calloc(1, 2*hash_size);
    if (!tmp) {
        warn("ec_decode: calloc failed");
        gnutls_free(dr.data);
        gnutls_free(ds.data);
        return false;
    }
    if (dr.size >= hash_size)
        memcpy(tmp, dr.data + dr.size - hash_size, hash_size);
    else
        memcpy(tmp + hash_size - dr.size, dr.data, dr.size);
    if (ds.size >= hash_size)
        memcpy(tmp + hash_size, ds.data + ds.size - hash_size, hash_size);
    else
        memcpy(tmp + 2*hash_size - ds.size, ds.data, ds.size);
    gnutls_free(dr.data);
    gnutls_free(ds.data);
#else
    int len;
    const unsigned char *p = *sig;
    int ps = *sig_size;
    unsigned long tag;
    unsigned char cls;

    r = asn1_get_tag_der(p, ps, &cls, &len, &tag);
    if (r != ASN1_SUCCESS) {
        warnx("ec_decode: asn1_get_tag_der: %s", asn1_strerror(r));
        return false;
    }
    if (cls != ASN1_CLASS_STRUCTURED || tag != ASN1_TAG_SEQUENCE) {
        warnx("ec_decode: unexpected ASN1 tag");
        return false;
    }
    p += len;
    ps -= len;

    r = asn1_get_length_der(p, ps, &len);
    if (r < 0) {
        warnx("ec_decode: asn1_get_length_der: %d", r);
        return false;
    }
    p += len;
    ps -= len;

    if (p + r != *sig + *sig_size) {
        warnx("ec_decode: signature lenght mismatch");
        return false;
    }

    unsigned char *tmp = calloc(1, 2*hash_size);
    if (!tmp) {
        warn("ec_decode: calloc failed");
        return false;
    }

    r = asn1_get_tag_der(p, ps, &cls, &len, &tag);
    if (r != ASN1_SUCCESS) {
        warnx("ec_decode: asn1_get_tag_der: %s", asn1_strerror(r));
        free(tmp);
        return false;
    }
    if (cls != ASN1_CLASS_UNIVERSAL || tag != ASN1_TAG_INTEGER) {
        warnx("ec_decode: unexpected ASN1 tag");
        free(tmp);
        return false;
    }
    p += len;
    ps -= len;

    r = asn1_get_length_der(p, ps, &len);
    if (r < 0) {
        warnx("ec_decode: asn1_get_length_der: %d", r);
        free(tmp);
        return false;
    }
    p += len;
    ps -= len;

    if (r >= (int)hash_size)
        memcpy(tmp, p + r - hash_size, hash_size);
    else
        memcpy(tmp + hash_size - r, p, r);
    p += r;
    ps -= r;

    r = asn1_get_tag_der(p, ps, &cls, &len, &tag);
    if (r != ASN1_SUCCESS) {
        warnx("ec_decode: asn1_get_tag_der: %s", asn1_strerror(r));
        free(tmp);
        return false;
    }
    if (cls != ASN1_CLASS_UNIVERSAL || tag != ASN1_TAG_INTEGER) {
        warnx("ec_decode: unexpected ASN1 tag");
        free(tmp);
        return false;
    }
    p += len;
    ps -= len;

    r = asn1_get_length_der(p, ps, &len);
    if (r < 0) {
        warnx("ec_decode: asn1_get_length_der: %d", r);
        free(tmp);
        return false;
    }
    p += len;
    ps -= len;

    if (r >= (int)hash_size)
        memcpy(tmp + hash_size, p + r - hash_size, hash_size);
    else
        memcpy(tmp + 2*hash_size - r, p, r);
    p += r;
    ps -= r;

    if (ps != 0) {
        warnx("ec_decode: signature lenght mismatch");
        free(tmp);
        return false;
    }
#endif
#elif defined(USE_OPENSSL)
    const unsigned char *p = *sig;
    const BIGNUM *br = NULL;
    const BIGNUM *bs = NULL;
    ECDSA_SIG *s = d2i_ECDSA_SIG(NULL, &p, *sig_size);
    if (!s) {
        openssl_error("ec_decode");
        return false;
    }
    ECDSA_SIG_get0(s, &br, &bs);
    unsigned char *tmp = calloc(1, 2*hash_size);
    if (!tmp) {
        warn("ec_decode: calloc failed");
        ECDSA_SIG_free(s);
        return false;
    }
    r = BN_num_bytes(br);
    unsigned char *data = calloc(1, r);
    if (!data) {
        warn("ec_decode: calloc failed");
        ECDSA_SIG_free(s);
        free(tmp);
        return false;
    }
    if (BN_bn2bin(br, data) != r) {
        openssl_error("ec_decode");
        ECDSA_SIG_free(s);
        free(data);
        free(tmp);
        return false;
    }
    if (r >= (int)hash_size)
        memcpy(tmp, data + r - hash_size, hash_size);
    else
        memcpy(tmp + hash_size - r, data, r);
    free(data);

    r = BN_num_bytes(bs);
    data = calloc(1, r);
    if (!data) {
        warn("ec_decode: calloc failed");
        ECDSA_SIG_free(s);
        free(tmp);
        return false;
    }
    if (BN_bn2bin(bs, data) != r) {
        openssl_error("ec_decode");
        ECDSA_SIG_free(s);
        free(data);
        free(tmp);
        return false;
    }
    if (r >= (int)hash_size)
        memcpy(tmp + hash_size, data + r - hash_size, hash_size);
    else
        memcpy(tmp + 2*hash_size - r, data, r);

    ECDSA_SIG_free(s);
    free(data);
#elif defined(USE_MBEDTLS)
    unsigned char *p = *sig;
    const unsigned char *end = p + *sig_size;
    size_t len;
    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r != 0) {
        warnx("ec_decode: mbedtls_asn1_get_tag failed: %s",
                _mbedtls_strerror(r));
        return false;
    }
    if (p + len != end) {
        warnx("ec_decode: signature lenght mismatch");
        return false;
    }
    unsigned char *tmp = calloc(1, 2*hash_size);
    if (!tmp) {
        warn("ec_decode: calloc failed");
        return false;
    }
    r = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER);
    if (r != 0) {
        warnx("ec_decode: mbedtls_asn1_get_tag failed: %s",
                _mbedtls_strerror(r));
        free(tmp);
        return false;
    }
    if (len >= hash_size)
        memcpy(tmp, p + len - hash_size, hash_size);
    else
        memcpy(tmp + hash_size - len, p, len);
    p += len;

    r = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER);
    if (r != 0) {
        warnx("ec_decode: mbedtls_asn1_get_tag failed: %s",
                _mbedtls_strerror(r));
        free(tmp);
        return false;
    }
    if (len >= hash_size)
        memcpy(tmp + hash_size, p + len - hash_size, hash_size);
    else
        memcpy(tmp + 2*hash_size - len, p, len);
#endif
    free(*sig);
    *sig = tmp;
    *sig_size = 2*hash_size;
    return true;
}

char *jws_encode(const char *protected, const char *payload,
    privkey_t key)
{
    char *jws = NULL;
    char *encoded_payload = encode_base64url(payload);
    char *encoded_protected = encode_base64url(protected);
    char *encoded_combined = NULL;
    unsigned char *signature = NULL;
    size_t signature_size = 0;
    char *encoded_signature = NULL;
    size_t hash_size = 0;
#if defined(USE_GNUTLS)
    gnutls_digest_algorithm_t hash_type;
#elif defined(USE_OPENSSL)
    EVP_MD_CTX *emc = NULL;
    const EVP_MD *hash_type;
    unsigned int len;
#elif defined(USE_MBEDTLS)
    mbedtls_md_type_t hash_type;
    unsigned char *hash = NULL;
#endif

    if (!encoded_payload || !encoded_protected) {
        warnx("jws_encode: encode_base64url failed");
        goto out;
    }
    if (asprintf(&encoded_combined, "%s.%s", encoded_protected,
                encoded_payload) < 0) {
        warnx("jws_encode: asprintf failed");
        encoded_combined = NULL;
        goto out;
    }

    switch (key_type(key)) {
        case PK_RSA:
            hash_size = 32;
#if defined(USE_GNUTLS)
            hash_type = GNUTLS_DIG_SHA256;
#elif defined(USE_OPENSSL)
            hash_type = EVP_sha256();
#elif defined(USE_MBEDTLS)
            hash_type = MBEDTLS_MD_SHA256;
#endif
            break;

        case PK_EC:
            switch (ec_params(key, NULL, NULL)) {
                case 0:
                    warnx("jws_encode: ec_params failed");
                    goto out;

                case 256:
                    hash_size = 32;
#if defined(USE_GNUTLS)
                    hash_type = GNUTLS_DIG_SHA256;
#elif defined(USE_OPENSSL)
                    hash_type = EVP_sha256();
#elif defined(USE_MBEDTLS)
                    hash_type = MBEDTLS_MD_SHA256;
#endif
                    break;

                case 384:
                    hash_size = 48;
#if defined(USE_GNUTLS)
                    hash_type = GNUTLS_DIG_SHA384;
#elif defined(USE_OPENSSL)
                    hash_type = EVP_sha384();
#elif defined(USE_MBEDTLS)
                    hash_type = MBEDTLS_MD_SHA384;
#endif
                    break;

                default:
                    warnx("jws_encode: unsupported EC curve");
                    goto out;
            }
            break;

        default:
            warnx("jws_encode: only RSA/EC keys are supported");
            goto out;
    }

#if defined(USE_GNUTLS)
    gnutls_datum_t data = {
        (unsigned char *)encoded_combined, strlen(encoded_combined)};
    gnutls_datum_t sign = {NULL, 0};
    int r = gnutls_privkey_sign_data(key, hash_type, 0, &data, &sign);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("jws_encode: gnutls_privkey_sign_data: %s", gnutls_strerror(r));
        goto out;
    }
    signature_size = sign.size;
    signature = gnutls_datum_data(&sign, true);
    if (!signature) {
        warnx("jws_encode: gnutls_datum_data failed");
        goto out;
    }
#elif defined(USE_OPENSSL)
    emc = EVP_MD_CTX_create();
    if (!emc) {
        openssl_error("jws_encode");
        goto out;
    }
    signature = calloc(1, EVP_PKEY_size(key));
    if (!signature) {
        warn("jws_encode: calloc failed");
        goto out;
    }
    if (!EVP_SignInit_ex(emc, hash_type, NULL)) {
        openssl_error("jws_encode");
        goto out;
    }
    if (!EVP_SignUpdate(emc, encoded_combined, strlen(encoded_combined))) {
        openssl_error("jws_encode");
        goto out;
    }
    if (!EVP_SignFinal(emc, signature, &len, key)) {
        openssl_error("jws_encode");
        goto out;
    }
    signature_size = len;
#elif defined(USE_MBEDTLS)
    hash = calloc(1, hash_size);
    if (!hash) {
        warn("jws_encode: calloc failed");
        goto out;
    }
    int r = mbedtls_hash_fast(hash_type, encoded_combined,
            strlen(encoded_combined), hash);
    if (r != 0) {
        warnx("jws_encode: mbedtls_hash_fast failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    switch (mbedtls_pk_get_type(key)) {
        case MBEDTLS_PK_RSA:
            signature_size = mbedtls_pk_get_len(key);
            signature = calloc(1, signature_size);
            break;

        case MBEDTLS_PK_ECKEY:
            signature_size = 9+2*mbedtls_pk_get_len(key);
            signature = calloc(1, signature_size);
            break;

        default:
            warnx("jws_encode: only RSA/EC keys are supported");
            goto out;
    }
    if (!signature) {
        warn("jws_encode: calloc failed");
        goto out;
    }
    r = mbedtls_pk_sign(key, hash_type, hash, hash_size, signature,
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
            signature_size,
#endif
            &signature_size, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (r != 0) {
        warnx("jws_encode: mbedtls_pk_sign failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
#endif
    if (key_type(key) == PK_EC && !ec_decode(hash_size, &signature,
                &signature_size)) {
        warnx("jws_encode: ec_decode failed");
        goto out;
    }
    size_t encoded_signature_len = base64_ENCODED_LEN(signature_size,
            base64_VARIANT_URLSAFE_NO_PADDING);
    encoded_signature = calloc(1, encoded_signature_len);
    if (!encoded_signature) {
        warn("jws_encode: calloc failed");
        goto out;
    }
    if (!bin2base64(encoded_signature, encoded_signature_len, signature,
                signature_size, base64_VARIANT_URLSAFE_NO_PADDING)) {
        warnx("jws_encode: bin2base64 failed");
        goto out;
    }
    if (asprintf(&jws,
                "{\"protected\":\"%s\","
                "\"payload\":\"%s\","
                "\"signature\":\"%s\"}",
                encoded_protected,
                encoded_payload,
                encoded_signature) < 0) {
        warnx("jws_encode: asprintf failed");
        jws = NULL;
    }
out:
#if defined(USE_OPENSSL)
    if (emc)
        EVP_MD_CTX_destroy(emc);
#elif defined(USE_MBEDTLS)
    free(hash);
#endif
    free(encoded_payload);
    free(encoded_protected);
    free(encoded_combined);
    free(encoded_signature);
    free(signature);
    return jws;
}

char *jws_encode_hmac(const char *protected, const char *payload,
    size_t bits, const char *key)
{
    char *jws = NULL;
    char *encoded_payload = encode_base64url(payload);
    char *encoded_protected = encode_base64url(protected);
    char *encoded_signature = NULL;

    if (!encoded_payload || !encoded_protected) {
        warnx("jws_encode_hmac: encode_base64url failed");
        goto out;
    }

    encoded_signature = hmac_base64url(bits, key, "%s.%s",
            encoded_protected, encoded_payload);
    if (!encoded_signature) {
        warnx("jws_encode_hmac: hmac_base64url failed");
        goto out;
    }
    if (asprintf(&jws,
                "{\"protected\":\"%s\","
                "\"payload\":\"%s\","
                "\"signature\":\"%s\"}",
                encoded_protected,
                encoded_payload,
                encoded_signature) < 0) {
        warnx("jws_encode_hmac: asprintf failed");
        jws = NULL;
    }
out:
    free(encoded_payload);
    free(encoded_protected);
    free(encoded_signature);
    return jws;
}

static bool key_gen(keytype_t type, int bits, const char *keyfile)
{
    bool success = false;
    int r;
#if !defined(USE_OPENSSL)
    void *pem_data = NULL;
    size_t pem_size = 0;
#endif
#if defined(USE_GNUTLS)
    gnutls_x509_privkey_t key = NULL;
    r = gnutls_x509_privkey_init(&key);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("key_gen: gnutls_x509_privkey_init: %s",
                gnutls_strerror(r));
        goto out;
    }
    switch (type) {
        case PK_RSA:
            msg(1, "generating new %d-bit RSA key", bits);
            r = gnutls_x509_privkey_generate(key, GNUTLS_PK_RSA, bits, 0);
            break;

        case PK_EC:
            switch (bits) {
                case 256:
                    msg(1, "generating new %d-bit EC key", bits);
                    r = gnutls_x509_privkey_generate(key, GNUTLS_PK_EC,
                        GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0);
                    break;

                case 384:
                    msg(1, "generating new %d-bit EC key", bits);
                    r = gnutls_x509_privkey_generate(key, GNUTLS_PK_EC,
                        GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP384R1), 0);
                    break;

                default:
                    warnx("key_gen: EC key size must be either 256 or 384");
                    goto out;
            }
            break;

        default:
            warnx("key_gen: only RSA/EC keys are supported");
            goto out;
    }
    if (r != GNUTLS_E_SUCCESS) {
        warnx("key_gen: gnutls_x509_privkey_generate: %s",
                gnutls_strerror(r));
        goto out;
    }
    gnutls_datum_t data = {NULL, 0};
    r = gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_PEM, &data);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("key_gen: gnutls_x509_privkey_export2: %s",
                gnutls_strerror(r));
        goto out;
    }
    pem_size = data.size;
    pem_data = gnutls_datum_data(&data, true);
    if (!pem_data) {
        warnx("key_gen: gnutls_datum_data failed");
        goto out;
    }
#elif defined(USE_OPENSSL)
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *epc = NULL;
    switch (type) {
        case PK_RSA:
            epc = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            break;

        case PK_EC:
            epc = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            break;

        default:
            warnx("key_gen: only RSA/EC keys are supported");
            goto out;
    }
    if (!epc) {
        openssl_error("key_gen");
        goto out;
    }
    if (!EVP_PKEY_keygen_init(epc)) {
        openssl_error("key_gen");
        goto out;
    }
    switch (type) {
        case PK_RSA:
            msg(1, "generating new %d-bit RSA key", bits);
            if (!EVP_PKEY_CTX_set_rsa_keygen_bits(epc, bits)) {
                openssl_error("key_gen");
                goto out;
            }
            break;

        case PK_EC:
            switch (bits) {
                case 256:
                    msg(1, "generating new %d-bit EC key", bits);
                    if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(epc,
                                NID_X9_62_prime256v1)) {
                        openssl_error("key_gen");
                        goto out;
                    }
                    break;

                case 384:
                    msg(1, "generating new %d-bit EC key", bits);
                    if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(epc,
                                NID_secp384r1)) {
                        openssl_error("key_gen");
                        goto out;
                    }
                    break;

                default:
                    warnx("key_gen: EC key size must be either 256 or 384");
                    goto out;
            }
            break;

        default:
            warnx("key_gen: only RSA/EC keys are supported");
            goto out;
    }
    if (!EVP_PKEY_keygen(epc, &key)) {
        openssl_error("key_gen");
        goto out;
    }
 #elif defined(USE_MBEDTLS)
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    const mbedtls_pk_info_t *pki;
    switch (type) {
        case PK_RSA:
            pki = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
            break;

        case PK_EC:
            pki = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
            break;

        default:
            warnx("key_gen: only RSA/EC keys are supported");
            goto out;
    }
    if (!pki) {
        warnx("key_gen: mbedtls_pk_info_from_type failed");
        goto out;
    }
    r = mbedtls_pk_setup(&key, pki);
    if (r) {
        warnx("key_gen: mbedtls_pk_setup failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    switch (type) {
        case PK_RSA:
            msg(1, "generating new %d-bit RSA key", bits);
            r = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key),
                    mbedtls_ctr_drbg_random, &ctr_drbg, bits, 65537);
            if (r) {
                warnx("key_gen: mbedtls_rsa_gen_key failed: %s",
                        _mbedtls_strerror(r));
                goto out;
            }
            break;

        case PK_EC:
            switch (bits) {
                case 256:
                    msg(1, "generating new %d-bit EC key", bits);
                    r = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                            mbedtls_pk_ec(key), mbedtls_ctr_drbg_random,
                            &ctr_drbg);
                    break;

                case 384:
                    msg(1, "generating new %d-bit EC key", bits);
                    r = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP384R1,
                            mbedtls_pk_ec(key), mbedtls_ctr_drbg_random,
                            &ctr_drbg);
                    break;

                default:
                    warnx("key_gen: EC key size must be either 256 or 384");
                    goto out;
            }
            if (r) {
                warnx("key_gen: mbedtls_ecp_gen_key failed: %s",
                        _mbedtls_strerror(r));
                goto out;
            }
            break;

        default:
            warnx("key_gen: only RSA/EC keys are supported");
            goto out;
    }
    pem_size = 4096;
    while (1) {
        pem_data = calloc(1, pem_size);
        if (!pem_data) {
            warn("key_gen: calloc failed");
            goto out;
        }
        r = mbedtls_pk_write_key_pem(&key, pem_data, pem_size);
        if (r == 0)
            break;
        else if (r == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
            free(pem_data);
            pem_size *= 2;
        } else {
            warnx("key_gen: mbedtls_pk_write_key_pem failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
    }
    pem_size = strlen(pem_data);
#endif
    mode_t prev = umask((S_IWUSR | S_IXUSR) | S_IRWXG | S_IRWXO);
    FILE *f = fopen(keyfile, "w");
    umask(prev);
    if (!f) {
        warn("key_gen: failed to create %s", keyfile);
        goto out;
    }
#if defined(USE_OPENSSL)
    r = PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    if (!r) {
        openssl_error("key_gen");
        warnx("key_gen: failed to write %s", keyfile);
        unlink(keyfile);
        goto out;
    }
#else
    r = fwrite(pem_data, 1, pem_size, f);
    fclose(f);
    if (r != (int)pem_size) {
        warn("key_gen: failed to write to %s", keyfile);
        unlink(keyfile);
        goto out;
    }
#endif
    msg(1, "key saved to %s", keyfile);
    success = true;
out:
#if defined(USE_GNUTLS)
    gnutls_x509_privkey_deinit(key);
    free(pem_data);
#elif defined(USE_OPENSSL)
    if (key)
        EVP_PKEY_free(key);
    if (epc)
        EVP_PKEY_CTX_free(epc);
#elif defined(USE_MBEDTLS)
    mbedtls_pk_free(&key);
    free(pem_data);
#endif
    return success;
}

privkey_t key_load(keytype_t type, int bits, const char *format, ...)
{
    privkey_t key = NULL;
    char *keyfile = NULL;
#if !defined(USE_OPENSSL)
    int r;
    void *keydata = NULL;
    size_t keysize = 0;
#endif
    va_list ap;
    va_start(ap, format);
    if (vasprintf(&keyfile, format, ap) < 0)
        keyfile = NULL;
    va_end(ap);
    if (!keyfile) {
        warnx("key_load: vasprintf failed");
        goto out;
    }

    msg(1, "loading key from %s", keyfile);
#if defined(USE_OPENSSL)
    while (!key) {
        FILE *f = fopen(keyfile, "r");
        if (!f) {
            if (errno != ENOENT) {
                warn("key_load: failed to open %s", keyfile);
                goto out;
            } else {
                msg(1, "%s not found", keyfile);
                if (type == PK_NONE) {
                    warnx("key_load: %s does not exist", keyfile);
                    goto out;
                }
                if (!key_gen(type, bits, keyfile)) {
                    warnx("key_load: key_gen failed");
                    goto out;
                }
            }
        } else {
            key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
            fclose(f);
            if (!key) {
                openssl_error("key_load");
                warnx("key_load: failed to read %s", keyfile);
                goto out;
            }
        }
    }
#else
    while (!(keydata = read_file(keyfile, &keysize))) {
        if (errno != ENOENT) {
            warn("key_load: failed to read %s", keyfile);
            goto out;
        } else {
            msg(1, "%s not found", keyfile);
            if (type == PK_NONE) {
                warnx("key_load: %s does not exist", keyfile);
                goto out;
            }
            if (!key_gen(type, bits, keyfile)) {
                warnx("key_load: key_gen failed");
                goto out;
            }
        }
    }
#endif

#if defined(USE_GNUTLS)
    r = gnutls_privkey_init(&key);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("key_load: gnutls_privkey_import_x509_raw: %s",
                gnutls_strerror(r));
        goto out;
    }
    gnutls_datum_t data = {keydata, keysize};
    r = gnutls_privkey_import_x509_raw(key, &data,
            GNUTLS_X509_FMT_PEM, NULL, 0);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("key_load: gnutls_privkey_import_x509_raw: %s",
                gnutls_strerror(r));
        gnutls_privkey_deinit(key);
        key = NULL;
        goto out;
    }

    r = gnutls_privkey_verify_params(key);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("key_load: gnutls_privkey_verify_params: %s",
                gnutls_strerror(r));
        gnutls_privkey_deinit(key);
        key = NULL;
        goto out;
    }

#elif defined(USE_MBEDTLS)
    key = calloc(1, sizeof(*key));
    if (!key) {
        warn("key_load: calloc failed");
        goto out;
    }
    mbedtls_pk_init(key);
    r = mbedtls_pk_parse_key(key, keydata, keysize+1, NULL, 0
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
                , mbedtls_ctr_drbg_random, &ctr_drbg
#endif
            );
    if (r) {
        warnx("key_load: mbedtls_pk_parse failed: %s",
                _mbedtls_strerror(r));
        free(key);
        key = NULL;
        goto out;
    }
#endif
    switch (key_type(key)) {
        case PK_RSA:
            if (!rsa_params(key, NULL, NULL)) {
                warnx("key_load: invalid key");
                privkey_deinit(key);
                key = NULL;
            }
            break;

        case PK_EC:
            if (!ec_params(key, NULL, NULL)) {
                warnx("key_load: invalid key");
                privkey_deinit(key);
                key = NULL;
            }
            break;

        default:
            warnx("key_load: only RSA/EC keys are supported");
            privkey_deinit(key);
            key = NULL;
    }
out:
    free(keyfile);
#if !defined(USE_OPENSSL)
    free(keydata);
#endif
    return key;
}

bool is_ip(const char *s, unsigned char *ip, size_t *ip_len)
{
    bool ret = false;
    struct addrinfo hints, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(s, NULL, &hints, &ai) == 0) {
        if (ai->ai_family == AF_INET) {
            if (ip_len && *ip_len >= sizeof(struct in_addr)) {
                struct sockaddr_in *s = (struct sockaddr_in *)ai->ai_addr;
                *ip_len = sizeof(struct in_addr);
                if (ip)
                    memcpy(ip, &s->sin_addr, sizeof(struct in_addr));
            }
            ret = true;
        } else if (ai->ai_family == AF_INET6) {
            if (ip_len && *ip_len >= sizeof(struct in6_addr)) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;
                *ip_len = sizeof(struct in6_addr);
                if (ip)
                    memcpy(ip, &s->sin6_addr, sizeof(struct in6_addr));
            }
            ret = true;
        } else if (ip_len)
            *ip_len = 0;
        freeaddrinfo(ai);
    } else if (ip_len)
        *ip_len = 0;

    return ret;
}

char *csr_gen(char * const *names, bool status_req, bool no_key_usage,
        privkey_t key)
{
    char *req = NULL;
    unsigned char *csrdata = NULL;
    size_t csrsize = 0;
    int r;
#if !defined(USE_OPENSSL)
    unsigned char ip[16];
    size_t ip_len;
#endif
#if defined(USE_GNUTLS)
    unsigned int key_usage = 0;
    gnutls_digest_algorithm_t hash_type;
    gnutls_pubkey_t pubkey = NULL;
    gnutls_x509_crq_t crq = NULL;
#if HAVE_GNUTLS_X509_CRQ_SET_TLSFEATURES
    gnutls_x509_tlsfeatures_t tls_features = NULL;
#endif
#elif defined(USE_OPENSSL)
    const char *key_usage = NULL;
    const EVP_MD *hash_type;
    X509_REQ *crq = NULL;
    X509_NAME *name = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    char *san = NULL;
#elif defined(USE_MBEDTLS)
    unsigned int key_usage = 0;
    mbedtls_md_type_t hash_type;
    size_t buflen = 1024;
    unsigned char *buf = NULL;
    char *cn = NULL;
    mbedtls_x509write_csr csr;
    mbedtls_x509write_csr_init(&csr);
#endif

    switch (key_type(key)) {
        case PK_RSA:
#if defined(USE_GNUTLS)
            key_usage = GNUTLS_KEY_DIGITAL_SIGNATURE |
                GNUTLS_KEY_KEY_ENCIPHERMENT;
            hash_type = GNUTLS_DIG_SHA256;
#elif defined(USE_OPENSSL)
            key_usage = "critical, digitalSignature, keyEncipherment";
            hash_type = EVP_sha256();
#elif defined(USE_MBEDTLS)
            key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
            hash_type = MBEDTLS_MD_SHA256;
#endif
            break;

        case PK_EC:
#if defined(USE_GNUTLS)
            key_usage = GNUTLS_KEY_DIGITAL_SIGNATURE;
#elif defined(USE_OPENSSL)
            key_usage = "critical, digitalSignature";
#elif defined(USE_MBEDTLS)
            key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
#endif
            switch (ec_params(key, NULL, NULL)) {
                case 0:
                    warnx("csr_gen: ec_params failed");
                    goto out;

                case 256:
#if defined(USE_GNUTLS)
                    hash_type = GNUTLS_DIG_SHA256;
#elif defined(USE_OPENSSL)
                    hash_type = EVP_sha256();
#elif defined(USE_MBEDTLS)
                    hash_type = MBEDTLS_MD_SHA256;
#endif
                    break;

                case 384:
#if defined(USE_GNUTLS)
                    hash_type = GNUTLS_DIG_SHA384;
#elif defined(USE_OPENSSL)
                    hash_type = EVP_sha384();
#elif defined(USE_MBEDTLS)
                    hash_type = MBEDTLS_MD_SHA384;
#endif
                    break;

                default:
                    warnx("csr_gen: unsupported EC curve");
                    goto out;
            }
            break;

        default:
            warnx("csr_gen: only RSA/EC keys are supported");
            goto out;
    }

#if defined(USE_GNUTLS)
    r = gnutls_x509_crq_init(&crq);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("csr_gen: gnutls_x509_crq_init: %s", gnutls_strerror(r));
        goto out;
    }

    for (char * const *nm = names; *nm; nm++) {
        ip_len = sizeof(ip);
        if (is_ip(*nm, ip, &ip_len))
            r = gnutls_x509_crq_set_subject_alt_name(crq, GNUTLS_SAN_IPADDRESS,
                    ip, ip_len, GNUTLS_FSAN_APPEND);
        else {
            if (nm == names) {
                r = gnutls_x509_crq_set_dn_by_oid(crq,
                        GNUTLS_OID_X520_COMMON_NAME, 0, *nm, strlen(*nm));
                if (r != GNUTLS_E_SUCCESS) {
                    warnx("csr_gen: gnutls_x509_crq_set_dn_by_oid: %s",
                            gnutls_strerror(r));
                    goto out;
                }
            }
            r = gnutls_x509_crq_set_subject_alt_name(crq, GNUTLS_SAN_DNSNAME,
                    *nm, strlen(*nm), GNUTLS_FSAN_APPEND);
        }
        if (r != GNUTLS_E_SUCCESS) {
            warnx("csr_gen: gnutls_x509_set_subject_alt_name: %s",
                    gnutls_strerror(r));
            goto out;
        }
    }

    if (!no_key_usage) {
        r = gnutls_x509_crq_set_key_usage(crq, key_usage);
        if (r != GNUTLS_E_SUCCESS) {
            warnx("csr_gen: gnutls_x509_crq_set_key_usage: %s",
                    gnutls_strerror(r));
            goto out;
        }
    }

    if (status_req) {
#if HAVE_GNUTLS_X509_CRQ_SET_TLSFEATURES
        r = gnutls_x509_tlsfeatures_init(&tls_features);
        if (r != GNUTLS_E_SUCCESS) {
            warnx("csr_gen: gnutls_x509_tlsfeatures_init: %s",
                    gnutls_strerror(r));
            goto out;
        }

        // status_request TLS feature (OCSP Must-Staple)
        r = gnutls_x509_tlsfeatures_add(tls_features, 5);
        if (r != GNUTLS_E_SUCCESS) {
            warnx("csr_gen: gnutls_x509_tlsfeatures_add: %s",
                    gnutls_strerror(r));
            goto out;
        }

        r = gnutls_x509_crq_set_tlsfeatures(crq, tls_features);
        if (r != GNUTLS_E_SUCCESS) {
            warnx("csr_gen: gnutls_x509_set_tlsfeatures: %s",
                    gnutls_strerror(r));
            goto out;
        }
#else
        warnx("csr_gen: -m, --must-staple disabled at compile time "
                "- consider recompiling with GnuTLS 3.5.1 or later");
        goto out;
#endif
    }

    r = gnutls_pubkey_init(&pubkey);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("csr_gen: gnutls_pubkey_init: %s", gnutls_strerror(r));
        goto out;
    }

    r = gnutls_pubkey_import_privkey(pubkey, key, 0, 0);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("csr_gen: gnutls_pubkey_import_privkey: %s", gnutls_strerror(r));
        goto out;
    }

    r = gnutls_x509_crq_set_pubkey(crq, pubkey);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("csr_gen: gnutls_x509_crq_set_pubkey: %s", gnutls_strerror(r));
        goto out;
    }

    gnutls_digest_algorithm_t dig;
    unsigned int mand;
    r = gnutls_pubkey_get_preferred_hash_algorithm(pubkey, &dig, &mand);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("csr_gen: gnutls_pubkey_get_preferred_hash_algorithm: %s",
                gnutls_strerror(r));
        goto out;
    }
    if (mand == 0)
        dig = hash_type;
    else if (dig != hash_type) {
        warnx("csr_gen: unsupported message digest");
        goto out;
    }

    r = gnutls_x509_crq_privkey_sign(crq, key, dig, 0);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("csr_gen: gnutls_crq_privkey_sign: %s", gnutls_strerror(r));
        goto out;
    }

    gnutls_datum_t data = {NULL, 0};
    r = gnutls_x509_crq_export2(crq, GNUTLS_X509_FMT_DER, &data);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("csr_gen: gnutls_x509_crq_export2: %s", gnutls_strerror(r));
        goto out;
    }
    csrsize = data.size;
    csrdata = gnutls_datum_data(&data, true);
    if (!csrdata) {
        warnx("csr_gen: gnutls_datum_data failed");
        goto out;
    }
#elif defined(USE_OPENSSL)
    if (!(crq = X509_REQ_new())) {
        openssl_error("csr_gen");
        goto out;
    }
    if (!X509_REQ_set_pubkey(crq, key)) {
        openssl_error("csr_gen");
        goto out;
    }
    if (is_ip(*names, NULL, NULL)) {
        if (asprintf(&san, "IP:%s", *names) < 0) {
            warnx("csr_gen: asprintf failed");
            san = NULL;
            goto out;
        }
    } else {
        if (!(name = X509_NAME_new())) {
            openssl_error("csr_gen");
            goto out;
        }
        if (!X509_NAME_add_entry_by_txt(name, "CN",
                    MBSTRING_ASC, (unsigned char *)*names, -1, -1, 0)) {
            openssl_error("csr_gen");
            goto out;
        }
        if (!X509_REQ_set_subject_name(crq, name)) {
            openssl_error("csr_gen");
            goto out;
        }
        if (asprintf(&san, "DNS:%s", *names) < 0) {
            warnx("csr_gen: asprintf failed");
            san = NULL;
            goto out;
        }
    }
    while (*++names) {
        char *tmp = NULL;
        if (asprintf(&tmp, "%s,%s:%s", san,
                    is_ip(*names, NULL, NULL) ? "IP" : "DNS", *names) < 0) {
            warnx("csr_gen: asprintf failed");
            goto out;
        }
        free(san);
        san = tmp;
    }
    exts = sk_X509_EXTENSION_new_null();
    if (!exts) {
        openssl_error("csr_gen");
        goto out;
    }
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL,
            NID_subject_alt_name, san);
    if (!ext) {
        openssl_error("csr_gen");
        goto out;
    }
    sk_X509_EXTENSION_push(exts, ext);
    if (!no_key_usage) {
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, key_usage);
        if (!ext) {
            openssl_error("csr_gen");
            goto out;
        }
        sk_X509_EXTENSION_push(exts, ext);
    }
    if (status_req) {
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3050000fL
        warnx("csr_gen: -m, --must-staple is not supported by LibreSSL "
                "earlier than 3.5.0 - consider updating it");
        goto out;
#else
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_tlsfeature,
                "status_request");
        if (!ext) {
            openssl_error("csr_gen");
            goto out;
        }
        sk_X509_EXTENSION_push(exts, ext);
#endif
    }
    if (!X509_REQ_add_extensions(crq, exts)) {
        openssl_error("csr_gen");
        goto out;
    }
    if (!X509_REQ_sign(crq, key, hash_type)) {
        openssl_error("csr_gen");
        goto out;
    }
    r = i2d_X509_REQ(crq, NULL);
    if (r < 0) {
        openssl_error("csr_gen");
        goto out;
    }
    csrsize = r;
    csrdata = calloc(1, csrsize);
    if (!csrdata) {
        warn("csr_gen: calloc failed");
        goto out;
    }
    unsigned char *tmp = csrdata;
    if (i2d_X509_REQ(crq, &tmp) != (int)csrsize) {
        openssl_error("csr_gen");
        goto out;
    }
#elif defined(USE_MBEDTLS)
    mbedtls_x509write_csr_set_key(&csr, key);
    mbedtls_x509write_csr_set_md_alg(&csr, hash_type);

    if (!no_key_usage) {
        r = mbedtls_x509write_csr_set_key_usage(&csr, key_usage);
        if (r) {
            warnx("csr_gen: mbedtls_x509write_csr_set_key_usage failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
    }

    if (!is_ip(*names, NULL, NULL)) {
        if (asprintf(&cn, "CN=%s", *names) < 0) {
            warnx("csr_gen: asprintf failed");
            cn = NULL;
            goto out;
        }

        r = mbedtls_x509write_csr_set_subject_name(&csr, cn);
        if (r) {
            warnx("csr_gen: mbedtls_x509write_csr_set_subject_name failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
    }

    while (1) {
        buflen *= 2;
        free(buf);
        buf = calloc(1, buflen);
        if (!buf) {
            warn("csr_gen: calloc failed");
            goto out;
        }
        unsigned char *p = buf + buflen;
        size_t len = 0;
        size_t count = 0;
        while (names[count])
            count++;
        while (count--) {
            const unsigned char *data;
            size_t data_len;
            unsigned char tag;

            ip_len = sizeof(ip);
            if (is_ip(names[count], ip, &ip_len)) {
                tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7;
                data = ip;
                data_len = ip_len;
            } else {
                tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2;
                data = (const unsigned char *)names[count];
                data_len = strlen(names[count]);
            }

            r = mbedtls_asn1_write_raw_buffer(&p, buf, data, data_len);
            if (r >= 0)
                len += r;
            else if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
                break;
            else {
                warnx("csr_gen: mbedtls_asn1_write_raw_buffer failed: %s",
                        _mbedtls_strerror(r));
                goto out;
            }
            r = mbedtls_asn1_write_len(&p, buf, data_len);
            if (r >= 0)
                len += r;
            else if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
                break;
            else {
                warnx("csr_gen: mbedtls_asn1_write_len failed: %s",
                        _mbedtls_strerror(r));
                goto out;
            }
            r = mbedtls_asn1_write_tag(&p, buf, tag);
            if (r >= 0)
                len += r;
            else if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
                break;
            else {
                warnx("csr_gen: mbedtls_asn1_write_tag failed: %s",
                        _mbedtls_strerror(r));
                goto out;
            }
        }
        if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            continue;
        r = mbedtls_asn1_write_len(&p, buf, len);
        if (r >= 0)
            len += r;
        else if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            continue;
        else {
            warnx("csr_gen: mbedtls_asn1_write_len failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
        r = mbedtls_asn1_write_tag(&p, buf,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (r >= 0)
            len += r;
        else if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            continue;
        else {
            warnx("csr_gen: mbedtls_asn1_write_tag failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
        r = mbedtls_x509write_csr_set_extension(&csr,
                MBEDTLS_OID_SUBJECT_ALT_NAME,
                MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
                0,
#endif
                buf + buflen - len, len);
        if (r) {
            warnx("csr_gen: mbedtls_x509write_csr_set_extension failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
        if (!status_req)
            break;
        p = buf + buflen;
        len = 0;
        // status_request TLS feature (OCSP Must-Staple)
        r = mbedtls_asn1_write_int(&p, buf, 5);
        if (r >= 0)
            len += r;
        else if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            continue;
        else {
            warnx("csr_gen: mbedtls_asn1_write_int failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
        r = mbedtls_asn1_write_len(&p, buf, len);
        if (r >= 0)
            len += r;
        else if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            continue;
        else {
            warnx("csr_gen: mbedtls_asn1_write_len failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
        r = mbedtls_asn1_write_tag(&p, buf,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (r >= 0)
            len += r;
        else if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
            continue;
        else {
            warnx("csr_gen: mbedtls_asn1_write_tag failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
        r = mbedtls_x509write_csr_set_extension(&csr,
                // http://oid-info.com/get/1.3.6.1.5.5.7.1.24
                // pe(1) id-pe-tlsfeature(24)
                MBEDTLS_OID_PKIX "\x01\x18",
                MBEDTLS_OID_SIZE(MBEDTLS_OID_PKIX "\x01\x18"),
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
                0,
#endif
                buf + buflen - len, len);
        if (r) {
            warnx("csr_gen: mbedtls_x509write_csr_set_extension failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
        break;
    }

    while (1) {
        r = mbedtls_x509write_csr_der(&csr, buf, buflen,
                mbedtls_ctr_drbg_random, &ctr_drbg);
        if (r > 0)
            break;
        else if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
            free(buf);
            buflen *= 2;
            buf = calloc(1, buflen);
            if (!buf) {
                warn("csr_gen: calloc failed");
                goto out;
            }
        } else {
            warnx("csr_gen: mbedtls_x509write_csr_der failed: %s",
                    _mbedtls_strerror(r));
            goto out;
        }
    }
    csrsize = r;
    csrdata = calloc(1, csrsize);
    if (!csrdata) {
        warn("csr_gen: calloc failed");
        goto out;
    }
    memcpy(csrdata, buf + buflen - csrsize, csrsize);
#endif
    r = base64_ENCODED_LEN(csrsize, base64_VARIANT_URLSAFE_NO_PADDING);
    req = calloc(1, r);
    if (!req) {
        warn("csr_gen: calloc failed");
        goto out;
    }
    if (!bin2base64(req, r, csrdata, csrsize,
                base64_VARIANT_URLSAFE_NO_PADDING)) {
        warnx("csr_gen: bin2base64 failed");
        free(req);
        req = NULL;
        goto out;
    }
out:
#if defined(USE_GNUTLS)
    gnutls_pubkey_deinit(pubkey);
#if HAVE_GNUTLS_X509_CRQ_SET_TLSFEATURES
    if (tls_features)
        gnutls_x509_tlsfeatures_deinit(tls_features);
#endif
    gnutls_x509_crq_deinit(crq);
#elif defined(USE_OPENSSL)
    if (name)
        X509_NAME_free(name);
    if (crq)
        X509_REQ_free(crq);
    if (exts)
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    free(san);
#elif defined(USE_MBEDTLS)
    mbedtls_x509write_csr_free(&csr);
    free(buf);
    free(cn);
#endif
    free(csrdata);
    return req;
}

#if defined(USE_GNUTLS)
static char **csr_names(gnutls_x509_crq_t crq)
{
    int i, r = 0, n = 0, ncn = 0, nsan = 0;
    char **ret = NULL;
    char **names = NULL;
    char *buf = NULL;
    char *ip = NULL;
    size_t size = 0;
    bool cn = true;

    do {
        r = cn ?
            gnutls_x509_crq_get_dn_by_oid(crq, GNUTLS_OID_X520_COMMON_NAME,
                    ncn, 0, buf, &size) :
            gnutls_x509_crq_get_subject_alt_name(crq, nsan, buf, &size,
                    NULL, NULL);

        switch (r) {
            case GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE:
                if (cn) {
                    cn = false;
                    r = GNUTLS_E_SUCCESS;
                }
                break;

            case GNUTLS_E_SHORT_MEMORY_BUFFER:
                buf = calloc(1, size);
                if (!buf) {
                    warn("csr_names: calloc failed");
                    goto out;
                }
                break;

            case GNUTLS_SAN_IPADDRESS:
                ip = calloc(1, INET6_ADDRSTRLEN);
                if (!ip) {
                    warnx("csr_names: calloc failed");
                    goto out;
                }
                if (!inet_ntop(size == 4 ? AF_INET : AF_INET6, buf, ip,
                            INET6_ADDRSTRLEN)) {
                    warnx("csr_names: invalid IP address in Subj Alt Name");
                    free(ip);
                    ip = NULL;
                    continue;
                }
                free(buf);
                buf = ip;
                ip = NULL;
                // intentional fallthrough
            case GNUTLS_E_SUCCESS:
            case GNUTLS_SAN_DNSNAME:
                for (i = 0; i < n; i++) {
                    if (strcasecmp(buf, names[i]) == 0)
                        break;
                }
                if (i < n)
                    free(buf);
                else {
                    names = realloc(names, (n + 2) * sizeof(buf));
                    if (!names) {
                        warn("csr_names: realloc failed");
                        goto out;
                    }
                    names[n++] = buf;
                    names[n] = NULL;
                }
                buf = NULL;
                size = 0;
                if (cn)
                    ncn++;
                else
                    nsan++;
                break;

            default:
                if (r < 0) {
                    warnx("csr_names: %s: %s",
                            cn ? "gnutls_x509_crq_get_dn_by_oid" :
                            "gnutls_x509_crq_get_subject_alt_name",
                            gnutls_strerror(r));
                    goto out;
                }
        }
    } while (r != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

    if (n > 0) {
        ret = names;
        names = NULL;
    }

out:
    for (i = 0; names && names[i]; i++)
        free(names[i]);
    free(names);
    return ret;
}
#elif defined(USE_OPENSSL)
static char **csr_names(X509_REQ *crq)
{
    int i, n = 0, ncn = -1, nsan = 0;
    char **ret = NULL;
    char **names = NULL;
    bool cn = true;
    X509_NAME *name = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    GENERAL_NAMES* alts = NULL;

    name = X509_REQ_get_subject_name(crq);
    if (!name)
        cn = false;

    exts = X509_REQ_get_extensions(crq);
    if (exts)
        alts = X509V3_get_d2i(exts, NID_subject_alt_name, NULL, NULL);

    while (1) {
        char *nm = NULL;
        if (cn) {
            ncn = X509_NAME_get_index_by_NID(name, NID_commonName, ncn);
            if (ncn < 0) {
                cn = false;
                continue;
            }
            X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, ncn);
            if (!entry)
                continue;
            ASN1_STRING *str = X509_NAME_ENTRY_get_data(entry);
            if (!str)
                continue;
            unsigned char *buf = NULL;
            int size = ASN1_STRING_to_UTF8(&buf, str);
            if (size < 0) {
                openssl_error("csr_names");
                continue;
            }
            nm = strndup((const char *)buf, size);
            if (!nm) {
                warn("csr_names: strndup failed");
                OPENSSL_free(buf);
                goto out;
            }
            OPENSSL_free(buf);
        } else if (alts && nsan < sk_GENERAL_NAME_num(alts)) {
            int type;
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(alts, nsan++);
            if (!gn)
                continue;
            ASN1_STRING *value = GENERAL_NAME_get0_value(gn, &type);
            if (!value)
                continue;
            if (type == GEN_DNS) {
                unsigned char *buf = NULL;
                int size = ASN1_STRING_to_UTF8(&buf, value);
                if (size < 0) {
                    openssl_error("csr_names");
                    continue;
                }
                nm = strndup((const char *)buf, size);
                if (!nm) {
                    warn("csr_names: strndup failed");
                    OPENSSL_free(buf);
                    goto out;
                }
                OPENSSL_free(buf);
            } else if (type == GEN_IPADD) {
                int af;
                int len;
                switch (ASN1_STRING_length(value)) {
                    case 4:
                        af = AF_INET;
                        len = INET_ADDRSTRLEN;
                        break;
                    case 16:
                        af = AF_INET6;
                        len = INET6_ADDRSTRLEN;
                        break;
                    default:
                        warnx("csr_names: invalid IP address in Subj Alt Name");
                        continue;
                }
                nm = calloc(1, len);
                if (!nm) {
                    warnx("csr_names: calloc failed");
                    goto out;
                }
                if (!inet_ntop(af, ASN1_STRING_get0_data(value), nm, len)) {
                    warnx("csr_names: invalid IP address in Subj Alt Name");
                    free(nm);
                    continue;
                }
            }
        } else
            break;

        if (nm) {
            for (i = 0; i < n; i++) {
                if (strcasecmp(nm, names[i]) == 0)
                    break;
            }
            if (i < n)
                free(nm);
            else {
                char **tmp = realloc(names, (n + 2) * sizeof(nm));
                if (!tmp) {
                    warn("csr_names: realloc failed");
                    free(nm);
                    goto out;
                }
                names = tmp;
                names[n++] = nm;
                names[n] = NULL;
            }
        }
    }

    if (n > 0) {
        ret = names;
        names = NULL;
    }

out:
    if (names) {
        for (i = 0; names[i]; i++)
            free(names[i]);
        free(names);
    }
    if (exts)
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    if (alts)
        sk_GENERAL_NAME_pop_free(alts, GENERAL_NAME_free);
    return ret;
}
#elif defined(USE_MBEDTLS)
// Unlike the built-in mbedTLS parser this function supports IP identifiers
static int ext_san(unsigned char *p, size_t len, mbedtls_x509_sequence *san)
{
    unsigned char *end = p + len;
    unsigned char *end_ext;
    int r;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

    if (end != p + len)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
            MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

    while (p < end) {
        r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

        end_ext = p + len;

        r = mbedtls_asn1_get_tag(&p, end_ext, &len, MBEDTLS_ASN1_OID);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

        if (len != MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME) ||
                memcmp(MBEDTLS_OID_SUBJECT_ALT_NAME, p, len) != 0) {
            p = end_ext;
            continue;
        }

        p += len;

        int crit;
        r = mbedtls_asn1_get_bool(&p, end_ext, &crit);
        if (r && r != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

        r = mbedtls_asn1_get_tag(&p, end_ext, &len, MBEDTLS_ASN1_OCTET_STRING);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

        if (p + len != end_ext)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

        r = mbedtls_asn1_get_tag(&p, end_ext, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

        if (p + len != end_ext)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

        while (p < end_ext) {
            unsigned char tag = *p++;
            r = mbedtls_asn1_get_len(&p, end_ext, &len);
            if (r)
                return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

            if ((tag & MBEDTLS_ASN1_TAG_CLASS_MASK) !=
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC)
                return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                    MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;

            if (san->buf.p) {
                if (san->next)
                    return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

                san->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
                if (!san->next)
                    return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                        MBEDTLS_ERR_ASN1_ALLOC_FAILED;

                san = san->next;
            }

            san->buf.tag = tag;
            san->buf.len = len;
            san->buf.p = p;
            p += len;
        }

        san->next = NULL;
        if (p != end_ext)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    return 0;
}

static int csr_san(const mbedtls_x509_csr *crq, mbedtls_x509_sequence *san)
{
    unsigned char *p = crq->cri.p;
    size_t len = crq->cri.len;
    unsigned char *end = p + len;
    unsigned char *end_attr;
    int i = 0, r;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return MBEDTLS_ERR_X509_INVALID_FORMAT + r;

    r = mbedtls_asn1_get_int(&p, end, &i);
    if (r && r != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
        return MBEDTLS_ERR_X509_INVALID_VERSION + r;

    if (i != 0)
        return MBEDTLS_ERR_X509_UNKNOWN_VERSION;

    for (i = 0; i < 2; i++) {
        r = mbedtls_asn1_get_tag(&p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_FORMAT + r;
        p += len;
    }

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    if (r)
        return MBEDTLS_ERR_X509_INVALID_FORMAT + r;

    while (p < end) {
        r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_FORMAT + r;

        end_attr = p + len;

        r = mbedtls_asn1_get_tag(&p, end_attr, &len, MBEDTLS_ASN1_OID);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_FORMAT + r;

        if (len == MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS9_CSR_EXT_REQ) &&
                memcmp(MBEDTLS_OID_PKCS9_CSR_EXT_REQ, p, len) == 0) {
            p += len;

            r = mbedtls_asn1_get_tag(&p, end_attr, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
            if (r)
                return MBEDTLS_ERR_X509_INVALID_FORMAT + r;
            else
                return ext_san(p, len, san);
        }

        p = end_attr;
    }

    return 0;
}

static char **csr_names(mbedtls_x509_csr *crq)
{
    int i, n = 0;
    char **ret = NULL;
    char **names = NULL;

    mbedtls_x509_name *name = &crq->subject;
    mbedtls_x509_sequence sans, *san = &sans;
    memset(&sans, 0, sizeof(sans));

    i = csr_san(crq, san);
    if (i) {
        warnx("csr_names: csr_san failed: %s", _mbedtls_strerror(i));
        goto out;
    }

    while (1) {
        char *nm = NULL;
        if (name) {
            if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0) {
                nm = strndup((const char *)name->val.p, name->val.len);
                if (!nm) {
                    warn("csr_names: strndup failed");
                    goto out;
                }
            }
            name = name->next;
        } else if (san) {
            if (san->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2)) {
                nm = strndup((const char *)san->buf.p, san->buf.len);
                if (!nm) {
                    warn("csr_names: strndup failed");
                    goto out;
                }
            } else if (san->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7)) {
                int af;
                int len = 0;
                switch (san->buf.len) {
                    case 4:
                        af = AF_INET;
                        len = INET_ADDRSTRLEN;
                        break;
                    case 16:
                        af = AF_INET6;
                        len = INET6_ADDRSTRLEN;
                        break;
                    default:
                        warnx("csr_names: invalid IP address in Subj Alt Name");
                }
                if (len) {
                    nm = calloc(1, len);
                    if (!nm) {
                        warnx("csr_names: calloc failed");
                        goto out;
                    }
                    if (!inet_ntop(af, san->buf.p, nm, len)) {
                        warnx("csr_names: invalid IP address in Subj Alt Name");
                        free(nm);
                        nm = NULL;
                    }
                }
            }
            san = san->next;
        } else
            break;

        if (nm) {
            for (i = 0; i < n; i++) {
                if (strcasecmp(nm, names[i]) == 0)
                    break;
            }
            if (i < n)
                free(nm);
            else {
                char **tmp = realloc(names, (n + 2) * sizeof(nm));
                if (!tmp) {
                    warn("csr_names: realloc failed");
                    free(nm);
                    goto out;
                }
                names = tmp;
                names[n++] = nm;
                names[n] = NULL;
            }
        }
    }

    if (n > 0) {
        ret = names;
        names = NULL;
    }

out:
    if (names) {
        for (i = 0; names[i]; i++)
            free(names[i]);
        free(names);
    }
    while (sans.next) {
        san = sans.next;
        sans.next = san->next;
        mbedtls_free(san);
    }
    return ret;
}
#endif

char *csr_load(const char *file, char ***names)
{
    int r;
    char *ret = NULL;
    void *csrdata = NULL;
    size_t csrsize = 0;
#if defined(USE_GNUTLS)
    gnutls_x509_crq_t crq = NULL;
#elif defined(USE_MBEDTLS)
    mbedtls_x509_csr _crq, *crq = &_crq;
    mbedtls_x509_csr_init(crq);
#elif defined(USE_OPENSSL)
    X509_REQ *crq = NULL;
#endif

    msg(1, "loading certificate request from %s", file);

#if defined(USE_OPENSSL)
    FILE *f = NULL;
    if (!(f = fopen(file, "r"))) {
        warn("csr_load: failed to open %s", file);
        goto out;
    }
    crq = PEM_read_X509_REQ(f, NULL, NULL, NULL);
    fclose(f);
    if (!crq) {
        openssl_error("csr_load");
        warnx("csr_load: failed to load %s", file);
        goto out;
    }
    r = i2d_X509_REQ(crq, NULL);
    if (r < 0) {
        openssl_error("csr_load");
        goto out;
    }
    csrsize = r;
    csrdata = calloc(1, csrsize);
    if (!csrdata) {
        warn("csr_load: calloc failed");
        goto out;
    }
    unsigned char *tmp = csrdata;
    if (i2d_X509_REQ(crq, &tmp) != (int)csrsize) {
        openssl_error("csr_load");
        goto out;
    }
#else
    csrdata = read_file(file, &csrsize);
    if (!csrdata) {
        warn("csr_load: failed to read %s", file);
        goto out;
    }
#endif
#if defined(USE_GNUTLS)
    gnutls_datum_t data = {csrdata, csrsize};
    r = gnutls_x509_crq_init(&crq);
    if (r < 0) {
        warnx("csr_load: gnutls_x509_crq_init: %s", gnutls_strerror(r));
        goto out;
    }
    r = gnutls_x509_crq_import(crq, &data, GNUTLS_X509_FMT_PEM);
    if (r < 0) {
        warnx("csr_load: gnutls_x509_crq_import: %s", gnutls_strerror(r));
        goto out;
    }
    free(csrdata);
    csrdata = NULL;
    data.data = NULL;
    data.size = 0;
    r = gnutls_x509_crq_export2(crq, GNUTLS_X509_FMT_DER, &data);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("csr_load: gnutls_x509_crq_export2: %s", gnutls_strerror(r));
        goto out;
    }
    csrsize = data.size;
    csrdata = gnutls_datum_data(&data, true);
    if (!csrdata) {
        warnx("csr_load: gnutls_datum_data failed");
        goto out;
    }
#elif defined(USE_MBEDTLS)
    r = mbedtls_x509_csr_parse(crq, csrdata, csrsize+1);
    if (r < 0) {
        warnx("csr_load: mbedtls_x509_csr_parse failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    mbedtls_pem_context ctx;
    mbedtls_pem_init(&ctx);
    size_t len;
    r = mbedtls_pem_read_buffer(&ctx,
            "-----BEGIN CERTIFICATE REQUEST-----",
            "-----END CERTIFICATE REQUEST-----",
            csrdata, NULL, 0, &len);
    if (r) {
        warnx("csr_load: mbedtls_pem_read_buffer failed: %s",
                _mbedtls_strerror(r));
        mbedtls_pem_free(&ctx);
        goto out;
    }
    free(csrdata);
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    const unsigned char *csrbuf = mbedtls_pem_get_buffer(&ctx, &csrsize);
    if (!csrbuf) {
        warn("csr_load: mbedtls_pem_get_buffer failed");
        goto out;
    }
#else
    const unsigned char *csrbuf = ctx.buf;
    csrsize = ctx.buflen;
#endif
    csrdata = calloc(1, csrsize);
    if (!csrdata) {
        warn("csr_load: calloc failed");
        mbedtls_pem_free(&ctx);
        goto out;
    }
    memcpy(csrdata, csrbuf, csrsize);
    mbedtls_pem_free(&ctx);
#endif
    r = base64_ENCODED_LEN(csrsize, base64_VARIANT_URLSAFE_NO_PADDING);
    ret = calloc(1, r);
    if (!ret) {
        warn("csr_load: calloc failed");
        goto out;
    }
    if (!bin2base64(ret, r, csrdata, csrsize,
                base64_VARIANT_URLSAFE_NO_PADDING)) {
        warnx("csr_load: bin2base64 failed");
        free(ret);
        ret = NULL;
        goto out;
    }
    if (names) {
        char **tmp = csr_names(crq);
        if (tmp)
            *names = tmp;
        else {
            free(ret);
            ret = NULL;
        }
    }
out:
    free(csrdata);
#if defined(USE_GNUTLS)
    gnutls_x509_crq_deinit(crq);
#elif defined(USE_MBEDTLS)
    mbedtls_x509_csr_free(crq);
#elif defined(USE_OPENSSL)
    X509_REQ_free(crq);
#endif
    return ret;
}

#if defined(USE_GNUTLS)
static int cert_load(gnutls_x509_crt_t *crt, unsigned int crt_size,
        const char *format, ...)
#elif defined(USE_OPENSSL)
static int cert_load(X509 **crt, unsigned int crt_size,
        const char *format, ...)
#elif defined(USE_MBEDTLS)
static int cert_load(mbedtls_x509_crt **crt, const char *format, ...)
#endif
{
    char *certfile = NULL;
#if !defined(USE_OPENSSL)
    void *certdata = NULL;
    size_t certsize = 0;
#endif
    int ret = 0;
    int r;
    va_list ap;

#if !defined(USE_MBEDTLS)
    if (crt_size < 1)
        return 0;
#endif

    va_start(ap, format);
    if (vasprintf(&certfile, format, ap) < 0)
        certfile = NULL;
    va_end(ap);
    if (!certfile) {
        warnx("cert_load: vasprintf failed");
        goto out;
    }

#if defined(USE_OPENSSL)
    FILE *f = NULL;
    if (!(f = fopen(certfile, "r"))) {
        if (errno == ENOENT)
            msg(1, "%s does not exist", certfile);
        else
            warn("cert_load: failed to open %s", certfile);
        goto out;
    }
    for (r = 0; r < (int)crt_size; r++) {
        crt[r] = PEM_read_X509(f, NULL, NULL, NULL);
        if (!crt[r])
            break;
    }
    fclose(f);
    if (r == 0) {
        openssl_error("cert_load");
        warnx("cert_load: failed to load %s", certfile);
        goto out;
    }
    ret = r;
#else
    certdata = read_file(certfile, &certsize);
    if (!certdata) {
        if (errno == ENOENT)
            msg(1, "%s does not exist", certfile);
        else
            warn("cert_load: failed to read %s", certfile);
        goto out;
    }
#endif
#if defined(USE_GNUTLS)
    gnutls_datum_t data = {certdata, certsize};
    r = gnutls_x509_crt_list_import(crt, &crt_size, &data, GNUTLS_X509_FMT_PEM,
            GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED);
    if (r < 0) {
        warnx("cert_load: gnutls_x509_crt_list_import: %s", gnutls_strerror(r));
        goto out;
    }
    ret = r;
#elif defined(USE_MBEDTLS)
    *crt = calloc(1, sizeof(**crt));
    if (!*crt) {
        warn("cert_load: calloc failed");
        goto out;
    }
    mbedtls_x509_crt_init(*crt);
    r = mbedtls_x509_crt_parse(*crt, certdata, certsize+1);
    if (r < 0) {
        warnx("cert_load: mbedtls_x509_crt_parse failed: %s",
                _mbedtls_strerror(r));
        mbedtls_x509_crt_free(*crt);
        free(*crt);
        goto out;
    }
    if (r > 0) {
        warnx("cert_load: failed to parse %d certificates", r);
        mbedtls_x509_crt_free(*crt);
        free(*crt);
        goto out;
    }
    for (mbedtls_x509_crt *c = *crt; c; c = c->next)
        ret++;
#endif
out:
#if !defined(USE_OPENSSL)
    free(certdata);
#endif
    free(certfile);
    return ret;
}

#if defined(USE_MBEDTLS)
static int mbedtls_crt_get_authority_key_id(mbedtls_x509_crt *crt,
        unsigned char **akid, size_t *size)
{
    unsigned char *p = crt->v3_ext.p;
    unsigned char *end = p + crt->v3_ext.len;
    size_t len;
    int r;

    if (!p || p == end)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return r;
    if (p + len != end)
        return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

    while (p < end) {
        unsigned char *end_ext;

        r = mbedtls_asn1_get_tag(&p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (r)
            return r;

        end_ext = p + len;
        r = mbedtls_asn1_get_tag(&p, end_ext, &len, MBEDTLS_ASN1_OID);
        if (r)
            return r;

        if (len != MBEDTLS_OID_SIZE(MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER) ||
                memcmp(p, MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER, len)) {
            p = end_ext;
            continue;
        }
        p += len;

        r = mbedtls_asn1_get_tag(&p, end_ext, &len, MBEDTLS_ASN1_BOOLEAN);
        if (r == 0) {
            if (len != 1)
                return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
            p++;
        } else if (r != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
            return r;

        r = mbedtls_asn1_get_tag(&p, end_ext, &len,
                MBEDTLS_ASN1_OCTET_STRING);
        if (r)
            return r;
        if (end_ext != p + len)
            return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

        r = mbedtls_asn1_get_tag(&p, p + len, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (r)
            return r;

        r = mbedtls_asn1_get_tag(&p, p + len, &len,
                MBEDTLS_ASN1_CONTEXT_SPECIFIC);
        if (r)
            return r;

        *akid = p;
        *size = len;
        return 0;
    }

    return MBEDTLS_ERR_X509_UNKNOWN_OID;
}
#endif

bool cert_match(const char *cert, unsigned char *fingerprint,
        size_t fingerprint_len)
{
    size_t certsize = strlen(cert);
    bool ret = false;

#if defined(USE_GNUTLS)
    gnutls_x509_crt_t *crt = NULL;
    unsigned int crt_size = 0;
    gnutls_datum_t data = {(unsigned char *)cert, certsize};
    int r = gnutls_x509_crt_list_import2(&crt, &crt_size, &data,
            GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED);
    if (r < 0) {
        warnx("cert_match: gnutls_x509_crt_list_import2: %s",
                gnutls_strerror(r));
        return ret;
    }
    for (unsigned int i = 0; i < crt_size; i++) {
        unsigned char fp[128];
        if (!ret) {
            size_t s = sizeof(fp);
            r = gnutls_x509_crt_get_fingerprint(crt[i], GNUTLS_DIG_SHA256,
                    fp, &s);
            if (r == 0 && fingerprint_len <= s &&
                    memcmp(fp, fingerprint, fingerprint_len) == 0) {
                msg(1, "certificate matched by fingerprint");
                ret = true;
            }
        }
        if (!ret) {
            size_t s = sizeof(fp);
            r = gnutls_x509_crt_get_authority_key_id(crt[i], fp, &s, NULL);
            if (r == 0 && fingerprint_len <= s &&
                    memcmp(fp, fingerprint, fingerprint_len) == 0) {
                msg(1, "certificate matched by Authority Key Id");
                ret = true;
            }
        }
        gnutls_x509_crt_deinit(crt[i]);
    }
    gnutls_free(crt);
#elif defined(USE_OPENSSL)
    BIO *bio = BIO_new_mem_buf(cert, certsize);
    if (!bio) {
        openssl_error("cert_match");
        return ret;
    }
    while (!BIO_eof(bio) && !ret) {
        unsigned char fp[32];
        unsigned int s = sizeof(fp);
        X509 *crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (!crt)
            break;
        if (X509_digest(crt, EVP_sha256(), fp, &s) &&
                fingerprint_len <= s &&
                memcmp(fp, fingerprint, fingerprint_len) == 0) {
            msg(1, "certificate matched by fingerprint");
            ret = true;
        } else {
            AUTHORITY_KEYID *akid = X509_get_ext_d2i(crt,
                    NID_authority_key_identifier, NULL, NULL);
            if (akid != NULL) {
                if (akid->keyid != NULL && fingerprint_len <=
                        (size_t)ASN1_STRING_length(akid->keyid) &&
                        memcmp(ASN1_STRING_get0_data(akid->keyid),
                            fingerprint, fingerprint_len) == 0) {
                    msg(1, "certificate matched by Authority Key Id");
                    ret = true;
                }
                AUTHORITY_KEYID_free(akid);
            }
        }
        X509_free(crt);
    }
    BIO_free(bio);
#elif defined(USE_MBEDTLS)
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int r = mbedtls_x509_crt_parse(&crt, (unsigned char *)cert, certsize+1);
    if (r < 0) {
        warnx("cert_match: mbedtls_x509_crt_parse failed: %s",
                _mbedtls_strerror(r));
        mbedtls_x509_crt_free(&crt);
        return ret;
    }
    if (r > 0) {
        warnx("cert_load: failed to parse %d certificates", r);
        mbedtls_x509_crt_free(&crt);
        return ret;
    }
    for (mbedtls_x509_crt *c = &crt; c; c = c->next) {
        unsigned char fp[32];
        unsigned char *akid;
        size_t akid_len;
        r = mbedtls_hash_fast(MBEDTLS_MD_SHA256, c->raw.p, c->raw.len, fp);
        if (r == 0 && fingerprint_len <= sizeof(fp) &&
                memcmp(fp, fingerprint, fingerprint_len) == 0) {
            msg(1, "certificate matched by fingerprint");
            ret = true;
            break;
        }
        r = mbedtls_crt_get_authority_key_id(c, &akid, &akid_len);
        if (r == 0 && fingerprint_len <= akid_len &&
                memcmp(akid, fingerprint, fingerprint_len) == 0) {
            msg(1, "certificate matched by Authority Key Id");
            ret = true;
            break;
        }
    }
    mbedtls_x509_crt_free(&crt);
#endif
    return ret;
}

#if defined(USE_GNUTLS)
static char *crt_ari_url(gnutls_x509_crt_t crt, const char *prefix)
#elif defined(USE_OPENSSL)
static char *crt_ari_url(X509 *crt, const char *prefix)
#elif defined(USE_MBEDTLS)
static char *crt_ari_url(mbedtls_x509_crt *crt, const char *prefix)
#endif
{
    char *url = NULL;
    unsigned char akid[128];
    char akid_b64[base64_ENCODED_LEN(sizeof(akid),
            base64_VARIANT_URLSAFE_NO_PADDING)];
    unsigned char serial[128];
    char serial_b64[base64_ENCODED_LEN(sizeof(serial),
            base64_VARIANT_URLSAFE_NO_PADDING)];
    size_t alen = sizeof(akid);
    size_t slen = sizeof(serial);

#if defined(USE_GNUTLS)
    int r = gnutls_x509_crt_get_authority_key_id(crt, akid, &alen, NULL);
    if (r)
        return NULL;
    r = gnutls_x509_crt_get_serial(crt, serial, &slen);
    if (r)
        return NULL;
#elif defined(USE_OPENSSL)
    AUTHORITY_KEYID *ak = X509_get_ext_d2i(crt,
            NID_authority_key_identifier, NULL, NULL);
    if (ak != NULL) {
        if (ak->keyid == NULL ||
                alen < (size_t)ASN1_STRING_length(ak->keyid))
            alen = 0;
        else {
            alen = (size_t)ASN1_STRING_length(ak->keyid);
            memcpy(akid, ASN1_STRING_get0_data(ak->keyid), alen);
        }
        AUTHORITY_KEYID_free(ak);
        if (alen == 0)
            return NULL;
    } else
        return NULL;
    const ASN1_INTEGER *sn = X509_get0_serialNumber(crt);
    if (!sn)
        return NULL;
    BIGNUM *bn = ASN1_INTEGER_to_BN(sn, NULL);
    if (!bn) {
        openssl_error("cert_ari_url");
        return NULL;
    }
    if (slen < (size_t)BN_num_bytes(bn)) {
        BN_free(bn);
        return NULL;
    } else {
        slen = (size_t)BN_bn2bin(bn, serial);
        BN_free(bn);
    }
#elif defined(USE_MBEDTLS)
    unsigned char *ak;
    size_t len;
    int r = mbedtls_crt_get_authority_key_id(crt, &ak, &len);
    if (r)
        return NULL;
    if (alen < len)
        return NULL;
    alen = len;
    memcpy(akid, ak, alen);
    if (!crt->serial.p || slen < crt->serial.len)
        return NULL;
    slen = crt->serial.len;
    memcpy(serial, crt->serial.p, slen);
#endif
    if (!bin2base64(akid_b64, sizeof(akid_b64), akid, alen,
                base64_VARIANT_URLSAFE_NO_PADDING) ||
            !bin2base64(serial_b64, sizeof(serial_b64), serial, slen,
                base64_VARIANT_URLSAFE_NO_PADDING)) {
        warnx("crt_ari_url: bin2base64 failed");
        return NULL;
    }

    if (asprintf(&url, "%s/%s.%s", prefix, akid_b64, serial_b64) < 0) {
        warnx("crt_ari_url: asprintf failed");
        url = NULL;
    }

    return url;
}

#if defined(USE_GNUTLS)
static bool ocsp_check(gnutls_x509_crt_t *crt)
{
    bool result = true;
    char *ocsp_uri = NULL;
    gnutls_ocsp_req_t req = NULL;
    gnutls_ocsp_resp_t rsp = NULL;
    gnutls_datum_t nreq = {NULL, 0};
    gnutls_datum_t nrsp = {NULL, 0};
    gnutls_datum_t req_data = {NULL, 0};
    gnutls_datum_t d = {NULL, 0};
    curldata_t *cd = NULL;
    int rc;

    if (!crt[0] || !crt[1])
        goto out;

    for (unsigned int seq = 0; true; seq++) {
        d.data = NULL;
        d.size = 0;
        rc = gnutls_x509_crt_get_authority_info_access(crt[0], seq,
                GNUTLS_IA_OCSP_URI, &d, NULL);
        if (rc == GNUTLS_E_UNKNOWN_ALGORITHM)
            continue;
        else if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
            break;
        else if (rc != GNUTLS_E_SUCCESS) {
            warnx("ocsp_check: unable to retrieve OCSP URI: %s",
                    gnutls_strerror(rc));
            break;
        }
        ocsp_uri = calloc(1, d.size+1);
        if (!ocsp_uri) {
            warn("ocsp_check: calloc failed");
            gnutls_free(d.data);
            break;
        }
        memcpy(ocsp_uri, d.data, d.size);
        gnutls_free(d.data);
        break;
    }
    if (!ocsp_uri)
        goto out;

    rc = gnutls_ocsp_req_init(&req);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_req_init failed: %s",
                gnutls_strerror(rc));
        goto out;
    }

    rc = gnutls_ocsp_req_add_cert(req, GNUTLS_DIG_SHA1, crt[1], crt[0]);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_req_add_cert failed: %s",
                gnutls_strerror(rc));
        goto out;
    }

    rc = gnutls_ocsp_req_randomize_nonce(req);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_req_randomize failed: %s",
                gnutls_strerror(rc));
        goto out;
    }

    rc = gnutls_ocsp_req_export(req, &req_data);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_req_export failed: %s",
                gnutls_strerror(rc));
        goto out;
    }

    d.data = NULL;
    d.size = 0;
    rc = gnutls_ocsp_req_print(req, GNUTLS_OCSP_PRINT_FULL, &d);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_req_print failed: %s",
                gnutls_strerror(rc));
        gnutls_free(d.data);
        goto out;
    }
    msg(2, "ocsp_check: %.*s", d.size, d.data);
    gnutls_free(d.data);

    msg(1, "querying OCSP server at %s", ocsp_uri);
    msg_hd(3, "ocsp_check: HTTP post:\n", req_data.data, req_data.size);
    cd = curl_post(ocsp_uri, req_data.data, req_data.size,
            "Content-Type: application/ocsp-request", NULL);
    if (!cd) {
        warnx("ocsp_check: curl_post(\"%s\") failed", ocsp_uri);
        goto out;
    }

    if (cd->headers)
        msg(3, "ocsp_check: HTTP headers:\n%s", cd->headers);
    if (cd->body)
        msg_hd(3, "ocsp_check: HTTP body:\n", cd->body, cd->body_len);

    rc = gnutls_ocsp_resp_init(&rsp);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_resp_init failed: %s",
                gnutls_strerror(rc));
        goto out;
    }

    d.data = (unsigned char *)cd->body;
    d.size = cd->body_len;
    rc = gnutls_ocsp_resp_import(rsp, &d);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_resp_import failed: %s",
                gnutls_strerror(rc));
        goto out;
    }

    d.data = NULL;
    d.size = 0;
    rc = gnutls_ocsp_resp_print(rsp, GNUTLS_OCSP_PRINT_FULL, &d);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_resp_print failed: %s",
                gnutls_strerror(rc));
        gnutls_free(d.data);
        goto out;
    }
    msg(2, "ocsp_check: %.*s", d.size, d.data);
    gnutls_free(d.data);

    unsigned int verify;
    rc = gnutls_ocsp_resp_verify_direct(rsp, crt[1], &verify, 0);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_resp_verify_direct failed: %s",
                gnutls_strerror(rc));
        goto out;
    }

    if (verify != 0) {
        warnx("warning: failed to verify OCSP response (%d)", verify);
        goto out;
    }

    rc = gnutls_ocsp_resp_get_status(rsp);
    if (rc != GNUTLS_OCSP_RESP_SUCCESSFUL) {
        if (rc < 0)
            warnx("ocsp_check: gnutls_ocsp_resp_get_status failed: %s",
                    gnutls_strerror(rc));
        else
            warnx("OCSP response was unsuccessful (%d)", rc);
        goto out;
    }

    rc = gnutls_ocsp_resp_check_crt(rsp, 0, crt[0]);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_resp_check_crt failed: %s",
                gnutls_strerror(rc));
        goto out;
    }

    rc = gnutls_ocsp_req_get_nonce(req, NULL, &nreq);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_req_get_nonce failed: %s",
                gnutls_strerror(rc));
        goto out;
    }

    rc = gnutls_ocsp_resp_get_nonce(rsp, NULL, &nrsp);
    if (rc != GNUTLS_E_SUCCESS) {
        if (rc != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            warnx("ocsp_check: gnutls_ocsp_rsp_get_nonce failed: %s",
                    gnutls_strerror(rc));
            goto out;
        } else
            msg(1, "OCSP response has no nonce");
    } else if (nreq.size != nrsp.size ||
            memcmp(nreq.data, nrsp.data, nreq.size)) {
        warnx("warning: OCSP response nonce mismatch");
        goto out;
    }

    unsigned int cert_status;
    rc = gnutls_ocsp_resp_get_single(rsp, 0, NULL, NULL, NULL, NULL,
            &cert_status, NULL, NULL, NULL, NULL);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_rsp_get_single failed: %s",
                gnutls_strerror(rc));
        goto out;
    }

    switch (cert_status) {
        case GNUTLS_OCSP_CERT_GOOD:
            msg(1, "OCSP certificate status is GOOD");
            break;

        case GNUTLS_OCSP_CERT_REVOKED:
            warnx("OCSP certificate status is REVOKED");
            result = false;
            break;

        case GNUTLS_OCSP_CERT_UNKNOWN:
        default:
            msg(1, "OCSP certificate status is UNKNOWN");
            break;
    }

out:
    if (req)
        gnutls_ocsp_req_deinit(req);
    if (rsp)
        gnutls_ocsp_resp_deinit(rsp);
    gnutls_free(req_data.data);
    gnutls_free(nreq.data);
    gnutls_free(nrsp.data);
    curldata_free(cd);
    free(ocsp_uri);
    return result;
}
#elif defined(USE_OPENSSL)
static bool ocsp_check(X509 **crt)
{
    bool result = true;
    char *ocsp_uri = NULL;
    OCSP_REQUEST *req = NULL;
    unsigned char *reqdata = NULL;
    int reqsize = 0;
    OCSP_RESPONSE *rsp = NULL;
    OCSP_BASICRESP *brsp = NULL;
    OCSP_CERTID *id = NULL;
    STACK_OF(OCSP_CERTID) *ids = NULL;
    STACK_OF(OPENSSL_STRING) *ocsp_uris = NULL;
    STACK_OF(X509) *issuers = NULL;
    curldata_t *cd = NULL;
    int rc;

    if (!crt[0] || !crt[1])
        goto out;

    ocsp_uris = X509_get1_ocsp(crt[0]);
    if (!ocsp_uris) {
        openssl_error("ocsp_check");
        goto out;
    }
    for (int j = 0; !ocsp_uri && j < sk_OPENSSL_STRING_num(ocsp_uris); j++) {
        char *uri = sk_OPENSSL_STRING_value(ocsp_uris, j);
        if (uri && strlen(uri)) {
            ocsp_uri = strdup(uri);
            if (!ocsp_uri) {
                warn("ocsp_check: strdup failed");
                goto out;
            }
        }
    }
    if (!ocsp_uri)
        goto out;

    req = OCSP_REQUEST_new();
    if (!req) {
        openssl_error("ocsp_check");
        goto out;
    }

    ids = sk_OCSP_CERTID_new_null();
    if (!ids) {
        openssl_error("ocsp_check");
        goto out;
    }

    id = OCSP_cert_to_id(EVP_sha1(), crt[0], crt[1]);
    if (!id || !sk_OCSP_CERTID_push(ids, id)) {
        openssl_error("ocsp_check");
        goto out;
    }

    if (!OCSP_request_add0_id(req, id)) {
        openssl_error("ocsp_check");
        goto out;
    }

    if (!OCSP_request_add1_nonce(req, NULL, -1)) {
        openssl_error("ocsp_check");
        goto out;
    }

    rc = i2d_OCSP_REQUEST(req, NULL);
    if (rc < 0) {
        openssl_error("ocsp_check");
        goto out;
    }
    reqsize = rc;
    reqdata = calloc(1, reqsize);
    if (!reqdata) {
        warn("ocsp_check: calloc failed");
        goto out;
    }
    unsigned char *tmp = reqdata;
    if (i2d_OCSP_REQUEST(req, &tmp) != reqsize) {
        openssl_error("ocsp_check");
        goto out;
    }

    if (g_loglevel > 1) {
        BIO *out = BIO_new(BIO_s_mem());
        if (out) {
            if (OCSP_REQUEST_print(out, req, 0)) {
                char *data = NULL;
                int size = BIO_get_mem_data(out, &data);
                warnx("ocsp_check: %.*s", size, data);
            }
            BIO_free(out);
        }
    }

    msg(1, "querying OCSP server at %s", ocsp_uri);
    msg_hd(3, "ocsp_check: HTTP post:\n", reqdata, reqsize);
    cd = curl_post(ocsp_uri, reqdata, reqsize,
            "Content-Type: application/ocsp-request", NULL);
    if (!cd) {
        warnx("ocsp_check: curl_post(\"%s\") failed", ocsp_uri);
        goto out;
    }

    if (cd->headers)
        msg(3, "ocsp_check: HTTP headers:\n%s", cd->headers);
    if (cd->body)
        msg_hd(3, "ocsp_check: HTTP body:\n", cd->body, cd->body_len);

    const unsigned char *tmp2 = (const unsigned char *)cd->body;
    rsp = d2i_OCSP_RESPONSE(NULL, &tmp2, cd->body_len);
    if (!rsp) {
        openssl_error("ocsp_check");
        goto out;
    }

    if (g_loglevel > 1) {
        BIO *out = BIO_new(BIO_s_mem());
        if (out) {
            if (OCSP_RESPONSE_print(out, rsp, 0)) {
                char *data = NULL;
                int size = BIO_get_mem_data(out, &data);
                warnx("ocsp_check: %.*s", size, data);
            }
            BIO_free(out);
        }
    }

    rc = OCSP_response_status(rsp);
    if (rc != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        if (rc < 0)
            openssl_error("ocsp_check");
        else
            warnx("OCSP response was unsuccessful (%d)", rc);
        goto out;
    }

    brsp = OCSP_response_get1_basic(rsp);
    if (!brsp) {
        openssl_error("ocsp_check");
        goto out;
    }

    rc = OCSP_check_nonce(req, brsp);
    if (rc < 0)
        msg(1, "OCSP response has no nonce");
    else if (rc == 0) {
        warnx("ocsp_check: OCSP_check_nonce failed");
        goto out;
    }

    issuers = sk_X509_new_null();
    if (!issuers) {
        openssl_error("ocsp_check");
        goto out;
    }
    sk_X509_push(issuers, crt[1]);

    if (OCSP_basic_verify(brsp, issuers, NULL, OCSP_TRUSTOTHER) <= 0) {
        openssl_error("ocsp_check");
        goto out;
    }

    int status;
    if (!OCSP_resp_find_status(brsp, id, &status, NULL, NULL, NULL, NULL)) {
        openssl_error("ocsp_check");
        goto out;
    }

    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            msg(1, "OCSP certificate status is GOOD");
            break;

        case V_OCSP_CERTSTATUS_REVOKED:
            warnx("OCSP certificate status is REVOKED");
            result = false;
            break;

        case V_OCSP_CERTSTATUS_UNKNOWN:
        default:
            msg(1, "OCSP certificate status is UNKNOWN");
            break;
    }

out:
    free(ocsp_uri);
    free(reqdata);
    if (cd)
        curldata_free(cd);
    if (req)
        OCSP_REQUEST_free(req);
    if (rsp)
        OCSP_RESPONSE_free(rsp);
    if (brsp)
        OCSP_BASICRESP_free(brsp);
    if (ids)
        sk_OCSP_CERTID_free(ids);
    if (ocsp_uris)
        X509_email_free(ocsp_uris);
    if (issuers)
        sk_X509_free(issuers);
    return result;
}
#elif defined(USE_MBEDTLS)
#define OID_AUTHORITY_INFO_ACCESS MBEDTLS_OID_PKIX "\x01\x01"
#define OID_AD_OCSP MBEDTLS_OID_PKIX "\x30\x01"
#define OID_AD_OCSP_BASIC OID_AD_OCSP "\x01"
#define OID_AD_OCSP_NONCE OID_AD_OCSP "\x02"

static int ext_parse_ocsp_uri(unsigned char *p, size_t len, const char **out)
{
    unsigned char *end = p + len;
    unsigned char *end_ext;
    unsigned char *end_ad;
    int r;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

    if (end != p + len)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
            MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

    while (p < end) {
        r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

        end_ext = p + len;

        r = mbedtls_asn1_get_tag(&p, end_ext, &len, MBEDTLS_ASN1_OID);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

        if (len != MBEDTLS_OID_SIZE(OID_AUTHORITY_INFO_ACCESS) ||
                memcmp(OID_AUTHORITY_INFO_ACCESS, p, len) != 0) {
            p = end_ext;
            continue;
        }

        p += len;

        int crit;
        r = mbedtls_asn1_get_bool(&p, end_ext, &crit);
        if (r && r != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

        r = mbedtls_asn1_get_tag(&p, end_ext, &len, MBEDTLS_ASN1_OCTET_STRING);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

        if (p + len != end_ext)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

        r = mbedtls_asn1_get_tag(&p, end_ext, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (r)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

        if (p + len != end_ext)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

        while (p < end_ext) {
            r = mbedtls_asn1_get_tag(&p, end_ext, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            if (r)
                return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

            end_ad = p + len;

            r = mbedtls_asn1_get_tag(&p, end_ad, &len, MBEDTLS_ASN1_OID);
            if (r)
                return MBEDTLS_ERR_X509_INVALID_EXTENSIONS + r;

            if (len != MBEDTLS_OID_SIZE(OID_AD_OCSP) ||
                    memcmp(OID_AD_OCSP, p, len) != 0) {
                p = end_ad;
                continue;
            }

            p += len;

            r = mbedtls_asn1_get_tag(&p, end_ad, &len,
                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | 6);
            if (r) {
                p = end_ad;
                continue;
            }

            *out = (const char *)p;
            return len;
        }

        if (p != end_ext)
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }
    return 0;
}

static int ocsp_req(mbedtls_x509_crt *crt, unsigned char *req, size_t size,
        const unsigned char **certid, size_t *certid_size)
{
    int ret = 0;
    size_t ext_len = 0;
    size_t len = 0;
    const char *alg_oid;
    size_t alg_oid_len = 0;
    unsigned char hash[20];
    unsigned char *p = req + size;
    mbedtls_x509_crt *issuer = crt->next;

    if (!issuer)
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&p, req,
                crt->serial.p, crt->serial.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, req,
                crt->serial.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, req,
                crt->serial.tag));

    for (size_t buf_size = 0x400; ; ) {
        unsigned char *buf = mbedtls_calloc(1, buf_size);
        if (!buf)
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        unsigned char *c = buf + buf_size;
        ret = mbedtls_pk_write_pubkey(&c, buf, &issuer->pk);
        if (ret >= 0)
#if MBEDTLS_VERSION_NUMBER < 0x03000000
            ret = mbedtls_sha1_ret(buf + buf_size - ret, ret, hash);
#else
            ret = mbedtls_sha1(buf + buf_size - ret, ret, hash);
#endif
        mbedtls_free(buf);
        if (ret == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
            buf_size *= 2;
            continue;
        }
        if (ret < 0)
            return ret;
        break;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(&p, req,
                hash, sizeof(hash)));

#if MBEDTLS_VERSION_NUMBER < 0x03000000
    ret = mbedtls_sha1_ret(crt->issuer_raw.p, crt->issuer_raw.len, hash);
#else
    ret = mbedtls_sha1(crt->issuer_raw.p, crt->issuer_raw.len, hash);
#endif
    if (ret)
        return ret;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_octet_string(&p, req,
                hash, sizeof(hash)));

    ret = mbedtls_oid_get_oid_by_md(MBEDTLS_MD_SHA1, &alg_oid, &alg_oid_len);
    if (ret)
        return ret;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_algorithm_identifier(&p, req,
                alg_oid, alg_oid_len, 0));

    if (certid)
        *certid = p;
    if (certid_size)
        *certid_size = len;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, req, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, req,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, req, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, req,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, req, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, req,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    len += ext_len;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, req, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, req,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, req, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, req,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    memmove(req, p, len);
    if (certid)
        *certid -= p - req;
    return len;
}

static int ocsp_resp(unsigned char *p, size_t len,
        const unsigned char *certid, size_t certid_size, int *status)
{
    const unsigned char *end = p + len;
    int i, r;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return r;

    r = mbedtls_asn1_get_tag(&p, end, &len, 10); // ASN1_ENUMERATED
    if (r)
        return r;

    if (len == 0 || len > sizeof(int) || (*p & 0x80))
        return MBEDTLS_ERR_ASN1_INVALID_LENGTH;

    while (len--)
        r = (r << 8) | *p++;
    if (r)
        return r;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    if (r)
        return r;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return r;
    end = p + len;

    r = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID);
    if (r)
        return r;

    if (len != MBEDTLS_OID_SIZE(OID_AD_OCSP_BASIC) ||
            memcmp(OID_AD_OCSP_BASIC, p, len) != 0)
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    p += len;

    r = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING);
    if (r)
        return r;
    end = p + len;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return r;
    end = p + len;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return r;
    end = p + len;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    if (r && r != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
        return r;
    if (r == 0) {
        int ver = 0;
        r = mbedtls_asn1_get_int(&p, end, &ver);
        if (r)
            return r;
        if (ver)
            return MBEDTLS_ERR_ASN1_INVALID_DATA;
    }

    for (i = 1; i < 3; i++) {
        r = mbedtls_asn1_get_tag(&p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | i);
        if (r && r != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
            return r;
        if (r == 0)
            break;
    }
    if (i > 2)
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    p += len;

    r = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_GENERALIZED_TIME);
    if (r)
        return r;
    p += len;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return r;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return r;

    r = mbedtls_asn1_get_tag(&p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r)
        return r;
    if (certid_size != len || memcmp(certid, p, len) != 0)
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    p += len;

    for (i = 0; i < 3; i++) {
        r = mbedtls_asn1_get_tag(&p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | i);
        if (r && r != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
            return r;
        if (r == 0)
            break;

        r = mbedtls_asn1_get_tag(&p, end, &len,
                MBEDTLS_ASN1_CONTEXT_SPECIFIC | i);
        if (r && r != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)
            return r;
        if (r == 0)
            break;
    }
    if (i > 2)
        return MBEDTLS_ERR_ASN1_INVALID_DATA;
    else if (status)
        *status = i;

    return 0;
}

static bool ocsp_check(mbedtls_x509_crt *crt)
{
    bool result = true;
    char *ocsp_uri = NULL;
    curldata_t *cd = NULL;
    unsigned char *req = NULL;
    size_t req_size = 0x100;
    const unsigned char *certid = NULL;
    size_t certid_size = 0;

    if (!crt->v3_ext.p || crt->v3_ext.len == 0)
        goto out;

    const char *tmp = NULL;
    int r = ext_parse_ocsp_uri(crt->v3_ext.p, crt->v3_ext.len, &tmp);
    if (r < 0)
        warnx("ocsp_check: ext_parse_ocsp_uri failed: %s",
                _mbedtls_strerror(r));
    else if (r == 0)
        goto out;

    ocsp_uri = strndup(tmp, r);
    if (!ocsp_uri) {
        warn("ocsp_check: strndup failed");
        goto out;
    }

    while (!req) {
        req = calloc(1, req_size);
        if (!req) {
            warn("ocsp_check: calloc failed");
            goto out;
        }
        r = ocsp_req(crt, req, req_size, &certid, &certid_size);
        if (r == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
            free(req);
            req = NULL;
            req_size *= 2;
        }
        else if (r < 0) {
            warnx("ocsp_check: ocsp_req failed: %s", _mbedtls_strerror(r));
            goto out;
        } else
            req_size = r;
    }

    msg(1, "querying OCSP server at %s", ocsp_uri);
    msg_hd(3, "ocsp_check: HTTP post:\n", req, req_size);
    cd = curl_post(ocsp_uri, req, req_size,
            "Content-Type: application/ocsp-request", NULL);
    if (!cd) {
        warnx("ocsp_check: curl_post(\"%s\") failed", ocsp_uri);
        goto out;
    }

    if (cd->headers)
        msg(3, "ocsp_check: HTTP headers:\n%s", cd->headers);
    if (cd->body)
        msg_hd(3, "ocsp_check: HTTP body:\n", cd->body, cd->body_len);

    int status;
    r = ocsp_resp((unsigned char *)cd->body, cd->body_len, certid, certid_size,
            &status);
    if (r < 0) {
        warnx("ocsp_check: ocsp_resp failed: %s",
                _mbedtls_strerror(r));
        goto out;
    } else if (r > 0) {
        warnx("OCSP response was unsuccessful (%d)", r);
        goto out;
    } else switch (status) {
        case 0: // GOOD
            msg(1, "OCSP certificate status is GOOD");
            break;

        case 1: // REVOKED
            warnx("OCSP certificate status is REVOKED");
            result = false;
            break;

        case 2: // UNKNOWN
        default:
            msg(1, "OCSP certificate status is UNKNOWN");
            break;
    }

out:
    free(ocsp_uri);
    free(req);
    if (cd)
        curldata_free(cd);
    return result;
}
#endif

static time_t parse_rfc3339_timestamp(const char *str)
{
    int n;
    time_t t = (time_t)-1;
    struct tm tm;

    memset(&tm, 0, sizeof(tm));
    if (sscanf(str, "%4d-%2d-%2d%*[Tt]%2d:%2d:%2d%n",
                &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &n) != 6)
        return (time_t)-1;
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    t = mktime(&tm);
    if (t == (time_t)-1)
        return (time_t)-1;
    str += n;
    str += strspn(str, ".0123456789");
    if (toupper(*str) != 'Z') {
        int tz, tzh, tzm;
        if (strlen(str) < 6 ||
            sscanf(str + 1, "%2d:%2d", &tzh, &tzm) != 2)
                return (time_t)-1;
        tz = 60*(60*tzh + tzm);
        switch (*str) {
            case '+':
                t -= tz;
                break;
            case '-':
                t += tz;
                break;
            default:
                t = (time_t) -1;
        }
    }
    return t;
}

#if defined(USE_GNUTLS)
int ari_check(gnutls_x509_crt_t crt, const char *ari_url)
#elif defined(USE_OPENSSL)
int ari_check(X509 *crt, const char *ari_url)
#elif defined(USE_MBEDTLS)
int ari_check(mbedtls_x509_crt *crt, const char *ari_url)
#endif
{
    int ret = -1;
    json_value_t *json = NULL;

    if (!ari_url)
        goto out;

    char *url = crt_ari_url(crt, ari_url);
    if (!url)
        goto out;

    msg(1, "checking certificate renewal info at %s", url);
    curldata_t *c = curl_get(url);
    free(url);
    if (!c) {
        warnx("ari_check: curl_get failed");
        goto out;
    }

    if (c->headers)
        msg(3, "ari_check: HTTP headers\n%s", c->headers);
    if (c->body)
        msg(3, "ari_check: HTTP body\n%s", c->body);

    char *p = find_header(c->headers, "Content-Type");
    if (p && strcasestr(p, "json"))
        json = json_parse(c->body, c->body_len);
    free(p);
    curldata_free(c);

    if (!json) {
        warnx("ari_check: failed to parse");
        goto out;
    }

    const json_value_t *window = json_find(json, "suggestedWindow");
    if (!window) {
        warnx("ari_check: missing suggestedWindow");
        goto out;
    }

    const char *start = json_find_string(window, "start");
    const char *end = json_find_string(window, "end");
    if (!start || !end) {
        warnx("ari_check: missing start or end");
        goto out;
    }
    msg(1, "certificate renewal window: start=%s end=%s", start, end);
    time_t start_t = parse_rfc3339_timestamp(start);
    if (start_t == (time_t)-1) {
        warnx("ari_check: invalid start");
        goto out;
    }
    time_t end_t = parse_rfc3339_timestamp(end);
    if (end_t == (time_t)-1) {
        warnx("ari_check: invalid end");
        goto out;
    }
    if (start_t >= end_t) {
        warnx("ari_check: invalid start/end");
        goto out;
    }

    if (time(NULL) > start_t + (end_t - start_t) * ((float)rand()/RAND_MAX))
        ret = 1;
    else
        ret = 0;

out:
    json_free(json);
    return ret;
}

bool cert_valid(const char *certfile, char * const *names, const char *ari_url,
        int validity, bool status_check)
{
    bool valid = false;
#if defined(USE_GNUTLS)
    gnutls_x509_crt_t crt[2] = {NULL, NULL};
    int ncrt = cert_load(crt, 2, "%s", certfile);
    if (ncrt <= 0)
        goto out;

    time_t expiration = gnutls_x509_crt_get_expiration_time(crt[0]);
    if (expiration == (time_t)-1) {
        warnx("cert_valid: gnutls_x509_crt_get_expiration_time failed");
        goto out;
    }

    int days_left = (expiration - time(NULL))/(24*3600);
    msg(1, "%s expires in %d days", certfile, days_left);
    int ari = -1;
    if (days_left > 0)
        ari = ari_check(crt[0], ari_url);
    if (ari > 0 || (ari < 0 && days_left < validity)) {
        msg(1, "%s is due for renewal", certfile);
        goto out;
    }

    while (names && *names) {
        if (!gnutls_x509_crt_check_hostname2(crt[0], *names,
                    GNUTLS_VERIFY_DO_NOT_ALLOW_WILDCARDS)) {
            msg(1, "%s does not include %s", certfile, *names);
            goto out;
        }
        names++;
    }

    valid = true;
    if (status_check) {
        if (ncrt < 2)
            warn("no issuer certificate in %s, skipping OCSP check", certfile);
        else
            valid = ocsp_check(crt);
    }
out:
    for (int i = 0; i < ncrt; i++)
        if (crt[i])
            gnutls_x509_crt_deinit(crt[i]);
#elif defined(USE_OPENSSL)
    GENERAL_NAMES *san = NULL;
    X509_NAME *sname = NULL;
    X509 *crt[2] = {NULL, NULL};
    int ncrt = cert_load(crt, 2, "%s", certfile);
    if (ncrt <= 0)
        goto out;
    int days_left;
    const ASN1_TIME *tm = X509_get0_notAfter(crt[0]);
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3050000fL
    struct tm tcrt;
    if (tm && ASN1_time_parse((const char *)tm->data, tm->length, &tcrt,
                tm->type) != -1) {
        time_t now = time(NULL);
        struct tm *tnow = gmtime(&now);
        if (!tnow) {
            warnx("cert_valid: gmtime overflow");
            goto out;
        }
        days_left = difftime(mktime(&tcrt), mktime(tnow))/(3600*24);
    } else {
#else
    int sec;
    if (!tm || !ASN1_TIME_diff(&days_left, &sec, NULL, tm)) {
#endif
        warnx("cert_valid: invalid expiration time format in %s", certfile);
        goto out;
    }
    msg(1, "%s expires in %d days", certfile, days_left);
    int ari = -1;
    if (days_left > 0)
        ari = ari_check(crt[0], ari_url);
    if (ari > 0 || (ari < 0 && days_left < validity)) {
        msg(1, "%s is due for renewal", certfile);
        goto out;
    }

    int crit = 0;
    san = X509_get_ext_d2i(crt[0], NID_subject_alt_name, &crit, NULL);
    if (!san && crit < 0) {
        openssl_error("cert_valid");
        goto out;
    }

    sname = X509_get_subject_name(crt[0]);

    while (names && *names) {
        bool found = false;

        int count = sk_GENERAL_NAME_num(san);
        while (count-- && !found) {
            GENERAL_NAME *name = sk_GENERAL_NAME_value(san, count);
            if (!name)
                continue;
            int type;
            ASN1_STRING *value = GENERAL_NAME_get0_value(name, &type);
            if (!value)
                continue;
            if (type == GEN_DNS) {
                unsigned char *s = NULL;
                if (ASN1_STRING_to_UTF8(&s, (ASN1_STRING *)value) < 0) {
                    openssl_error("cert_valid");
                    continue;
                } else if (s) {
                    if (strcasecmp((char *)s, *names) == 0)
                        found = true;
                    OPENSSL_free(s);
                }
            } else if (type == GEN_IPADD) {
                char s[INET6_ADDRSTRLEN];
                int af;
                switch (ASN1_STRING_length(value)) {
                    case 4:
                        af = AF_INET;
                        break;
                    case 16:
                        af = AF_INET6;
                        break;
                    default:
                        continue;
                }
                memset(s, 0, sizeof(s));
                if (!inet_ntop(af, ASN1_STRING_get0_data(value), s, sizeof(s)))
                    continue;
                if (strcasecmp(s, *names) == 0)
                    found = true;
            }
        }

        if (sname) {
            for (int i = -1; !found; ) {
                 i = X509_NAME_get_index_by_NID(sname, NID_commonName, i);
                 if (i < 0)
                     break;
                 X509_NAME_ENTRY *entry = X509_NAME_get_entry(sname, i);
                 if (!entry)
                     continue;
                 ASN1_STRING *str = X509_NAME_ENTRY_get_data(entry);
                 if (!str)
                     continue;
                 unsigned char *s = NULL;
                 if (ASN1_STRING_to_UTF8(&s, str) < 0) {
                     openssl_error("cert_valid");
                     continue;
                 }
                 if (strcasecmp((char *)s, *names) == 0)
                     found = true;
                 OPENSSL_free(s);
            }
        }

        if (!found) {
            msg(1, "%s does not include %s", certfile, *names);
            goto out;
        }
        names++;
    }

    valid = true;
    if (status_check) {
        if (ncrt < 2)
            warn("no issuer certificate in %s, skipping OCSP check", certfile);
        else
            valid = ocsp_check(crt);
    }
out:
    for (int i = 0; i < ncrt; i++)
        if (crt[i])
            X509_free(crt[i]);
    if (san)
        GENERAL_NAMES_free(san);
#elif defined(USE_MBEDTLS)
    mbedtls_x509_crt *crt = NULL;
    mbedtls_x509_sequence san;
    memset(&san, 0, sizeof(san));

    int ncrt = cert_load(&crt, "%s", certfile);
    if (ncrt < 1)
        goto out;

    struct tm texp = {
        .tm_sec = crt->valid_to.sec,
        .tm_min = crt->valid_to.min,
        .tm_hour = crt->valid_to.hour,
        .tm_mday = crt->valid_to.day,
        .tm_mon = crt->valid_to.mon - 1,
        .tm_year = crt->valid_to.year - 1900,
        .tm_isdst = -1
    };

    time_t expiration = mktime(&texp);
    if (expiration == (time_t)-1) {
        warnx("cert_valid: failed to determine expiration time");
        goto out;
    }

    int days_left = (expiration - time(NULL))/(24*3600);
    msg(1, "%s expires in %d days", certfile, days_left);
    int ari = -1;
    if (days_left > 0)
        ari = ari_check(crt, ari_url);
    if (ari > 0 || (ari < 0 && days_left < validity)) {
        msg(1, "%s is due for renewal", certfile);
        goto out;
    }

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    if (mbedtls_x509_crt_has_ext_type(crt, MBEDTLS_X509_EXT_SUBJECT_ALT_NAME)) {
#else
    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
#endif
        int r = ext_san(crt->v3_ext.p, crt->v3_ext.len, &san);
        if (r) {
            warnx("cert_valid: ext_san failed: %s", _mbedtls_strerror(r));
            goto out;
        }
    }

    while (names && *names) {
        bool found = false;
        const mbedtls_x509_name *name = NULL;
        const mbedtls_x509_sequence *cur = NULL;

        for (cur = &san; cur && !found; cur = cur->next) {
            if (cur->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC|2)) {
                if (strncasecmp(*names, (const char *)cur->buf.p,
                            strlen(*names)) == 0)
                    found = true;
            } else if (cur->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC|7)) {
                char s[INET6_ADDRSTRLEN];
                int af;
                switch (cur->buf.len) {
                    case 4:
                        af = AF_INET;
                        break;
                    case 16:
                        af = AF_INET6;
                        break;
                    default:
                        continue;
                }
                memset(s, 0, sizeof(s));
                if (!inet_ntop(af, cur->buf.p, s, sizeof(s)))
                    continue;
                if (strcasecmp(s, *names) == 0)
                    found = true;
             }
        }
        for (name = &crt->subject; name != NULL && !found; name = name->next) {
            if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0 &&
                    strncasecmp(*names, (const char *)name->val.p,
                        strlen(*names)) == 0)
                found = true;
        }
        if (!found) {
            msg(1, "%s does not include %s", certfile, *names);
            goto out;
        }
        names++;
    }

    valid = true;
    if (status_check) {
        if (ncrt < 2)
            warn("no issuer certificate in %s, skipping OCSP check", certfile);
        else
            valid = ocsp_check(crt);
    }
out:
    if (crt) {
        mbedtls_x509_crt_free(crt);
        free(crt);
    }
    while (san.next) {
        mbedtls_x509_sequence *tmp = san.next;
        san.next = tmp->next;
        mbedtls_free(tmp);
    }
#endif
    return valid;
}

char *cert_der_base64url(const char *certfile)
{
    char *ret = NULL;
    void *certdata = NULL;
    size_t certsize = 0;
    int r;
#if defined(USE_GNUTLS)
    gnutls_x509_crt_t crt = NULL;
    if (cert_load(&crt, 1, certfile) <= 0) {
        warnx("cert_der_base64url: cert_load failed");
        goto out;
    }

    gnutls_datum_t data = {NULL, 0};
    r = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &data);
    gnutls_x509_crt_deinit(crt);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("cert_der_base64url: gnutls_x509_crt_export2: %s",
                gnutls_strerror(r));
        goto out;
    }
    certsize = data.size;
    certdata = gnutls_datum_data(&data, true);
    if (!certdata)
        goto out;
#elif defined(USE_OPENSSL)
    X509 *crt = NULL;
    if (cert_load(&crt, 1, certfile) <= 0) {
        warnx("cert_der_base64url: cert_load failed");
        goto out;
    }
    r = i2d_X509(crt, NULL);
    if (r < 0) {
        openssl_error("cert_der_base64url");
        X509_free(crt);
        goto out;
    }
    certsize = r;
    certdata = calloc(1, certsize);
    if (!certdata) {
        warn("cert_der_base64url: calloc failed");
        X509_free(crt);
        goto out;
    }
    unsigned char *tmp = certdata;
    r = i2d_X509(crt, &tmp);
    X509_free(crt);
    if (r != (int)certsize) {
        openssl_error("cert_der_base64url");
        goto out;
    }
#elif defined(USE_MBEDTLS)
    certdata = read_file(certfile, &certsize);
    if (!certdata) {
        warn("cert_der_base64url: error reading %s", certfile);
        goto out;
    }
    mbedtls_pem_context ctx;
    mbedtls_pem_init(&ctx);
    size_t len;
    r = mbedtls_pem_read_buffer(&ctx, "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----", certdata, NULL, 0, &len);
    if (r) {
        warnx("cert_der_base64url: mbedtls_pem_read_buffer failed: %s",
                _mbedtls_strerror(r));
        mbedtls_pem_free(&ctx);
        goto out;
    }
    free(certdata);
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    const unsigned char *certbuf = mbedtls_pem_get_buffer(&ctx, &certsize);
    if (!certbuf) {
        warn("csr_der_base64url: mbedtls_pem_get_buffer failed");
        goto out;
    }
#else
    const unsigned char *certbuf = ctx.buf;
    certsize = ctx.buflen;
#endif
    certdata = calloc(1, certsize);
    if (!certdata) {
        warn("cert_der_base64url: calloc failed");
        mbedtls_pem_free(&ctx);
        goto out;
    }
    memcpy(certdata, certbuf, certsize);
    mbedtls_pem_free(&ctx);
#endif
    r = base64_ENCODED_LEN(certsize, base64_VARIANT_URLSAFE_NO_PADDING);
    if (!(ret = calloc(1, r))) {
        warn("cert_der_base64url: calloc failed");
        goto out;
    }
    if (!bin2base64(ret, r, certdata, certsize,
                base64_VARIANT_URLSAFE_NO_PADDING)) {
        warnx("cert_der_base64url: bin2base64 failed");
        free(ret);
        ret = NULL;
        goto out;
    }
out:
    free(certdata);
    return ret;
}
