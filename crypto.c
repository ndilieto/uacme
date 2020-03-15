/*
 * Copyright (C) 2019,2020 Nicola Di Lieto <nicola.dilieto@gmail.com>
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

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "base64.h"
#include "crypto.h"
#include "curlwrap.h"
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
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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
#elif defined(USE_MBEDTLS)
#if MBEDTLS_VERSION_NUMBER < 0x02100000
#error mbedTLS version 2.16 or later is required
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
#ifdef MBEDTLS_VERSION_C
    if (mbedtls_version_get_number() < 0x02100000) {
        warnx("crypto_init: mbedTLS version 2.16 or later is required");
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
        warnx("mbedtls_hash_get_len: md_info not found");
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }
    return mbedtls_md(mdi, input, len, output);
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
        warnx("sha2_base64url: calloc failed");
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
    RSA *rsa = EVP_PKEY_get0_RSA(key);
    if (!rsa) {
        openssl_error("rsa_params");
        goto out;
    }
    r = BN_num_bytes(RSA_get0_n(rsa));
    data = calloc(1, r);
    if (!data) {
        warn("rsa_params: calloc failed");
        goto out;
    }
    if (BN_bn2bin(RSA_get0_n(rsa), data) != r) {
        openssl_error("rsa_params");
        goto out;
    }
    _m = bn2str(data, r, 0);
    if (!_m) {
        warnx("rsa_params: bn2str failed");
        goto out;
    }
    free(data);
    r = BN_num_bytes(RSA_get0_e(rsa));
    data = calloc(1, r);
    if (!data) {
        warn("rsa_params: calloc failed");
        goto out;
    }
    if (BN_bn2bin(RSA_get0_e(rsa), data) != r) {
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
    if (!mbedtls_pk_can_do(key, MBEDTLS_PK_RSA)) {
        warnx("rsa_params: not a RSA key");
        goto out;
    }
    const mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*key);
    len = mbedtls_mpi_size(&rsa->N);
    data = calloc(1, len);
    if (!data) {
        warnx("rsa_params: calloc failed");
        goto out;
    }
    r = mbedtls_mpi_write_binary(&rsa->N, data, len);
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
    len = mbedtls_mpi_size(&rsa->E);
    data = calloc(1, len);
    if (!data) {
        warnx("rsa_params: calloc failed");
        goto out;
    }
    r = mbedtls_mpi_write_binary(&rsa->E, data, len);
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
#elif defined(USE_MBEDTLS)
    free(data);
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
    size_t len;
    if (!mbedtls_pk_can_do(key, MBEDTLS_PK_ECKEY)) {
        warnx("ec_params: not a EC key");
        goto out;
    }
    const mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*key);
    switch (ec->grp.id) {
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
    len = mbedtls_mpi_size(&ec->Q.X);
    data = calloc(1, len);
    if (!data) {
        warnx("ec_params: calloc failed");
        goto out;
    }
    r = mbedtls_mpi_write_binary(&ec->Q.X, data, len);
    if (r) {
        warnx("ec_params: mbedtls_mpi_write_binary failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    _x = bn2str(data, len, (bits+7)/8);
    if (!_x) {
        warnx("ec_params: bn2str failed");
        goto out;
    }
    free(data);
    len = mbedtls_mpi_size(&ec->Q.Y);
    data = calloc(1, len);
    if (!data) {
        warnx("ec_params: calloc failed");
        goto out;
    }
    r = mbedtls_mpi_write_binary(&ec->Q.Y, data, len);
    if (r) {
        warnx("ec_params: mbedtls_mpi_write_binary failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    _y = bn2str(data, len, (bits+7)/8);
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
    ECDSA_SIG *s = d2i_ECDSA_SIG(NULL, &p, *sig_size);
    if (!s) {
        openssl_error("ec_decode");
        return false;
    }
    unsigned char *tmp = calloc(1, 2*hash_size);
    if (!tmp) {
        warn("ec_decode: calloc failed");
        ECDSA_SIG_free(s);
        return false;
    }
    r = BN_num_bytes(ECDSA_SIG_get0_r(s));
    unsigned char *data = calloc(1, r);
    if (!data) {
        warn("ec_decode: calloc failed");
        ECDSA_SIG_free(s);
        free(tmp);
        return false;
    }
    if (BN_bn2bin(ECDSA_SIG_get0_r(s), data) != r) {
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

    r = BN_num_bytes(ECDSA_SIG_get0_s(s));
    data = calloc(1, r);
    if (!data) {
        warn("ec_decode: calloc failed");
        ECDSA_SIG_free(s);
        free(tmp);
        return false;
    }
    if (BN_bn2bin(ECDSA_SIG_get0_s(s), data) != r) {
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
            signature = calloc(1, mbedtls_pk_get_len(key));
            break;

        case MBEDTLS_PK_ECKEY:
            signature = calloc(1, 9+2*mbedtls_pk_get_len(key));
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
    r = mbedtls_pk_parse_key(key, keydata, keysize+1, NULL, 0);
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

char *csr_gen(const char * const *names, bool status_req, privkey_t key)
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

    r = gnutls_x509_crq_set_dn_by_oid(crq, GNUTLS_OID_X520_COMMON_NAME, 0,
                *names, strlen(*names));
    if (r != GNUTLS_E_SUCCESS) {
        warnx("csr_gen: gnutls_x509_crq_set_dn_by_oid: %s", gnutls_strerror(r));
        goto out;
    }

    while (*names) {
        ip_len = sizeof(ip);
        if (is_ip(*names, ip, &ip_len))
            r = gnutls_x509_crq_set_subject_alt_name(crq, GNUTLS_SAN_IPADDRESS,
                    ip, ip_len, GNUTLS_FSAN_APPEND);
        else
            r = gnutls_x509_crq_set_subject_alt_name(crq, GNUTLS_SAN_DNSNAME,
                    *names, strlen(*names), GNUTLS_FSAN_APPEND);
        if (r != GNUTLS_E_SUCCESS) {
            warnx("csr_gen: gnutls_x509_set_subject_alt_name: %s",
                    gnutls_strerror(r));
            goto out;
        }
        names++;
    }

    r = gnutls_x509_crq_set_key_usage(crq, key_usage);
    if (r != GNUTLS_E_SUCCESS) {
        warnx("csr_gen: gnutls_x509_crq_set_key_usage: %s",
                gnutls_strerror(r));
        goto out;
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
    if (!(name = X509_NAME_new())) {
        openssl_error("csr_gen");
        goto out;
    }
    if (!X509_REQ_set_pubkey(crq, key)) {
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
    if (asprintf(&san, "%s:%s", is_ip(*names, NULL, NULL) ? "IP" : "DNS",
                *names) < 0) {
        warnx("csr_gen: asprintf failed");
        san = NULL;
        goto out;
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
    ext = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, key_usage);
    if (!ext) {
        openssl_error("csr_gen");
        goto out;
    }
    sk_X509_EXTENSION_push(exts, ext);
    if (status_req) {
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_tlsfeature,
                "status_request");
        if (!ext) {
            openssl_error("csr_gen");
            goto out;
        }
        sk_X509_EXTENSION_push(exts, ext);
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

    if (asprintf(&cn, "CN=%s", *names) < 0) {
        warnx("csr_gen: asprintf failed");
        cn = NULL;
        goto out;
    }

    r = mbedtls_x509write_csr_set_key_usage(&csr, key_usage);
    if (r) {
        warnx("csr_gen: mbedtls_x509write_csr_set_key_usage failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }

    r = mbedtls_x509write_csr_set_subject_name(&csr, cn);
    if (r) {
        warnx("csr_gen: mbedtls_x509write_csr_set_subject_name failed: %s",
                _mbedtls_strerror(r));
        goto out;
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
        while (names[count]) count++;
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
    if (!(req = calloc(1, r))) {
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
    if (req)
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
    msg(2, "%.*s", d.size, d.data);
    gnutls_free(d.data);

    msg(1, "querying OCSP server at %s", ocsp_uri);
    cd = curl_post(ocsp_uri, req_data.data, req_data.size,
            "Content-Type: application/ocsp-request", NULL);
    if (!cd) {
        warnx("ocsp_check: curl_post(\"%s\") failed", ocsp_uri);
        goto out;
    }
    if (cd->headers)
        msg(3, "ocsp_check: HTTP headers:\n%s", cd->headers);

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
    rc = gnutls_ocsp_resp_print(rsp, GNUTLS_OCSP_PRINT_COMPACT, &d);
    if (rc != GNUTLS_E_SUCCESS) {
        warnx("ocsp_check: gnutls_ocsp_resp_print failed: %s",
                gnutls_strerror(rc));
        gnutls_free(d.data);
        goto out;
    }
    msg(2, "%.*s", d.size, d.data);
    gnutls_free(d.data);

    rc = gnutls_ocsp_resp_get_status(rsp);
    if (rc != GNUTLS_OCSP_RESP_SUCCESSFUL) {
        if (rc < 0)
            warnx("ocsp_check: gnutls_ocsp_resp_get_status failed: %s",
                    gnutls_strerror(rc));
        else
            warnx("OCSP response was unsuccessful (%d)", rc);
        goto out;
    }

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
    (void) crt;
    warnx("OCSP check not implemented yet when built with OpenSSL");
    return true;
}
#elif defined(USE_MBEDTLS)
static bool ocsp_check(mbedtls_x509_crt *crt)
{
    (void) crt;
    warnx("OCSP check not implemented yet when built with mbedTLS");
    return true;
}
#endif

bool cert_valid(const char *certdir, const char * const *names, int validity,
        bool status_check)
{
    bool valid = false;
#if defined(USE_GNUTLS)
    gnutls_x509_crt_t crt[2] = {NULL, NULL};
    int ncrt = cert_load(crt, 2, "%s/cert.pem", certdir);
    if (ncrt <= 0)
        goto out;

    time_t expiration = gnutls_x509_crt_get_expiration_time(crt[0]);
    if (expiration == (time_t)-1) {
        warnx("cert_valid: gnutls_x509_crt_get_expiration_time failed");
        goto out;
    }

    int days_left = (expiration - time(NULL))/(24*3600);
    msg(1, "%s/cert.pem expires in %d days", certdir, days_left);
    if (days_left < validity) {
        msg(1, "%s/cert.pem is due for renewal", certdir);
        goto out;
    }

    while (names && *names) {
        if (!gnutls_x509_crt_check_hostname2(crt[0], *names,
                    GNUTLS_VERIFY_DO_NOT_ALLOW_WILDCARDS)) {
            msg(1, "%s/cert.pem does not include %s", certdir, *names);
            goto out;
        }
        names++;
    }

    valid = true;
    if (status_check) {
        if (ncrt < 2)
            warn("no issuer certificate in %s/cert.pem, skipping OCSP check",
                    certdir);
        else
            valid = ocsp_check(crt);
    }
out:
    for (int i = 0; i < ncrt; i++)
        if (crt[i])
            gnutls_x509_crt_deinit(crt[i]);
#elif defined(USE_OPENSSL)
    GENERAL_NAMES* san = NULL;
    X509 *crt[2] = {NULL, NULL};
    int ncrt = cert_load(crt, 2, "%s/cert.pem", certdir);
    if (ncrt <= 0)
        goto out;
    int days_left, sec;
    const ASN1_TIME *tm = X509_get0_notAfter(crt[0]);
    if (!tm || !ASN1_TIME_diff(&days_left, &sec, NULL, tm)) {
        warnx("cert_valid: invalid expiration time format in %s/cert.pem",
                certdir);
        goto out;
    }
    msg(1, "%s/cert.pem expires in %d days", certdir, days_left);
    if (days_left < validity) {
        msg(1, "%s/cert.pem is due for renewal", certdir);
        goto out;
    }

    san = X509_get_ext_d2i(crt[0], NID_subject_alt_name, NULL, NULL);
    if (!san) {
        openssl_error("cert_valid");
        goto out;
    }

    while (names && *names) {
        bool found = false;
        int count = sk_GENERAL_NAME_num(san);
        while (count-- && !found) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(san, count);
            if (name && name->type == GEN_DNS) {
                unsigned char *s = NULL;
                int len = ASN1_STRING_to_UTF8(&s, name->d.dNSName);
                if (s) {
                    char *ss = (char *)s;
                    if ((int)strlen(ss) == len && strcasecmp(ss, *names) == 0)
                        found = true;
                    OPENSSL_free(s);
                }
            }
        }
        if (!found) {
            msg(1, "%s/cert.pem does not include %s", certdir, *names);
            goto out;
        }
        names++;
    }

    valid = true;
    if (status_check) {
        if (ncrt < 2)
            warn("no issuer certificate in %s/cert.pem, skipping OCSP check",
                    certdir);
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
    int ncrt = cert_load(&crt, "%s/cert.pem", certdir);
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
    msg(1, "%s/cert.pem expires in %d days", certdir, days_left);
    if (days_left < validity) {
        msg(1, "%s/cert.pem is due for renewal", certdir);
        goto out;
    }

    while (names && *names) {
        const mbedtls_x509_name *name = NULL;
        const mbedtls_x509_sequence *cur = NULL;

        if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
            for (cur = &crt->subject_alt_names; cur; cur = cur->next)
                if (strncasecmp(*names, (const char *)cur->buf.p,
                            strlen(*names)) == 0)
                    break;
        } else for (name = &crt->subject; name != NULL; name = name->next) {
            if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0 &&
                    strncasecmp(*names, (const char *)name->val.p,
                        strlen(*names)) == 0)
                break;
        }
        if (cur == NULL && name == NULL) {
            msg(1, "%s/cert.pem does not include %s", certdir, *names);
            goto out;
        }
        names++;
    }

    valid = true;
    if (status_check) {
        if (ncrt < 2)
            warn("no issuer certificate in %s/cert.pem, skipping OCSP check",
                    certdir);
        else
            valid = ocsp_check(crt);
    }
out:
    if (crt) {
        mbedtls_x509_crt_free(crt);
        free(crt);
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
    certdata = calloc(1, certsize);
    if (!certdata) {
        warn("cert_der_base64url: calloc failed");
        mbedtls_pem_free(&ctx);
        goto out;
    }
    memcpy(certdata, ctx.buf, ctx.buflen);
    certsize = ctx.buflen;
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
