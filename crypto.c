/*
 * Copyright (C) 2019 Nicola Di Lieto <nicola.dilieto@gmail.com>
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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base64.h"
#include "crypto.h"
#include "msg.h"
#include "read-file.h"

#if defined(USE_GNUTLS)
#include <gnutls/crypto.h>
#elif defined(USE_MBEDTLS)
#include <mbedtls/asn1write.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#endif

#if defined(USE_GNUTLS)
bool crypto_init(void)
{
    gnutls_global_init();
    return true;
}

void crypto_deinit(void)
{
    gnutls_global_deinit();
}
#elif defined(USE_MBEDTLS)
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
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
            &entropy, NULL, 0);
    if (r)
    {
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

static int mbedtls_hash_fast(mbedtls_md_type_t md_alg,
        const unsigned char *input, size_t len, unsigned char *output)
{
    const mbedtls_md_info_t *mdi =
        mbedtls_md_info_from_type(md_alg);
    if (!mdi)
    {
        warnx("mbedtls_hash_get_len: md_info not found");
        return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    }
    return mbedtls_md(mdi, input, len, output);
}
#endif

char *sha256_base64url(const char *format, ...)
{
    char *input = NULL;
    size_t encoded_hash_len;
    char *encoded_hash = NULL;
    const unsigned int hash_len = 32;
    unsigned char *hash = NULL;
    va_list ap;
    va_start(ap, format);
    if (vasprintf(&input, format, ap) < 0)
    {
        warn("sha256_base64url: vasprintf failed");
        input = NULL;
        goto out;
    }

    hash = calloc(1, hash_len);
    if (!hash)
    {
        warnx("sha256_base64url: calloc failed");
        goto out;
    }

#if defined(USE_GNUTLS)
    int r = gnutls_hash_fast(GNUTLS_DIG_SHA256, input, strlen(input), hash);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("sha256_base64url: gnutls_hash_fast failed: %s",
                gnutls_strerror(r));
#elif defined(USE_MBEDTLS)
    int r = mbedtls_hash_fast(MBEDTLS_MD_SHA256, input, strlen(input), hash);
    if (r != 0)
    {
        warnx("sha256_base64url: mbedtls_hash_fast failed: %s",
                _mbedtls_strerror(r));
#endif
        goto out;
    }

    encoded_hash_len = base64_ENCODED_LEN(hash_len,
            base64_VARIANT_URLSAFE_NO_PADDING);
    encoded_hash = calloc(1, encoded_hash_len);
    if (!encoded_hash)
    {
        warn("sha256_base64url: calloc failed");
        goto out;
    }
    if (!bin2base64(encoded_hash, encoded_hash_len,
                hash, hash_len, base64_VARIANT_URLSAFE_NO_PADDING))
    {
        warnx("sha256_base64url: bin2base64 failed");
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

static char *bn2str(const unsigned char *data, size_t len)
{
    char *ret = NULL;
    while (len && !*data)
    {
        data++;
        len--;
    }
    size_t encoded_len = base64_ENCODED_LEN(len,
            base64_VARIANT_URLSAFE_NO_PADDING);
    ret = calloc(1, encoded_len);
    if (!ret)
    {
        warn("bn2str: calloc failed");
        goto out;
    }
    if (!bin2base64(ret, encoded_len, data, len,
                base64_VARIANT_URLSAFE_NO_PADDING))
    {
        free(ret);
        ret = NULL;
    }
out:
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
    if (gnutls_privkey_get_pk_algorithm(key, NULL) != GNUTLS_PK_RSA)
    {
        warnx("rsa_params: not a RSA key");
        goto out;
    }
    r = gnutls_privkey_export_rsa_raw(key, &mod, &exp,
            NULL, NULL, NULL, NULL, NULL, NULL);
    if (r < 0)
    {
        warnx("rsa_params: gnutls_privkey_export: %s",
                gnutls_strerror(r));
        goto out;
    }
    _m = bn2str(mod.data, mod.size);
    free(mod.data);
    if (!_m)
    {
        warnx("rsa_params: bn2str failed");
        free(exp.data);
        goto out;
    }
    _e = bn2str(exp.data, exp.size);
    free(exp.data);
    if (!_e)
    {
        warnx("rsa_params: bn2str failed");
        goto out;
    }
#elif defined(USE_MBEDTLS)
    unsigned char *data;
    size_t len;
    if (!mbedtls_pk_can_do(key, MBEDTLS_PK_RSA))
    {
        warnx("rsa_params: not a RSA key");
        goto out;
    }
    const mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*key);
    len = mbedtls_mpi_size(&rsa->N);
    data = calloc(1, len);
    if (!data)
    {
        warnx("rsa_params: calloc failed");
        goto out;
    }
    r = mbedtls_mpi_write_binary(&rsa->N, data, len);
    if (r)
    {
        warnx("rsa_params: mbedtls_mpi_write_binary failed: %s",
                _mbedtls_strerror(r));
        free(data);
        goto out;
    }
    _m = bn2str(data, len);
    free(data);
    if (!_m)
    {
        warnx("rsa_params: bn2str failed");
        goto out;
    }
    len = mbedtls_mpi_size(&rsa->E);
    data = calloc(1, len);
    if (!data)
    {
        warnx("rsa_params: calloc failed");
        goto out;
    }
    r = mbedtls_mpi_write_binary(&rsa->E, data, len);
    if (r)
    {
        warnx("rsa_params: mbedtls_mpi_write_binary failed: %s",
                _mbedtls_strerror(r));
        free(data);
        goto out;
    }
    _e = bn2str(data, len);
    free(data);
    if (!_e)
    {
        warnx("rsa_params: bn2str failed");
        goto out;
    }
#endif
out:
    if (_e && _m)
    {
        *e = _e;
        *m = _m;
        return true;
    }
    else
    {
        free(_e);
        free(_m);
        return false;
    }
}

static char *jws_jwk(privkey_t key)
{
    char *ret = NULL;
    char *m = NULL;
    char *e = NULL;
#if defined(USE_GNUTLS)
    switch (gnutls_privkey_get_pk_algorithm(key, NULL))
    {
        case GNUTLS_PK_RSA:
            if (!rsa_params(key, &m, &e))
            {
                goto out;
            }
            break;

        case GNUTLS_PK_DSA:
        case GNUTLS_PK_DH:
        case GNUTLS_PK_EC:
#elif defined(USE_MBEDTLS)
    switch (mbedtls_pk_get_type(key))
    {
        case MBEDTLS_PK_RSA:
            if (!rsa_params(key, &m, &e))
            {
                goto out;
            }
            break;

        case MBEDTLS_PK_ECDSA:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECKEY:
#endif
        default:
            warnx("jws_jwk: only RSA keys supported at this time");
            goto out;
            break;
    }
    if (asprintf(&ret, "\"jwk\":{\"kty\":\"RSA\","
                "\"e\":\"%s\",\"n\":\"%s\"}", e, m) < 0)
    {
        warnx("jws_jwk: asprintf failed");
        ret = NULL;
    }
out:
    free(e);
    free(m);
    return ret;
}

char *jws_protected_jwk(const char *nonce, const char *url,
        privkey_t key)
{
    char *ret = NULL;
    char *jwk = jws_jwk(key);
    if (!jwk)
    {
        return NULL;
    }
    if (asprintf(&ret, "{\"alg\":\"RS256\",\"nonce\":\"%s\","
                "\"url\":\"%s\",%s}", nonce, url, jwk) < 0)
    {
        warnx("jws_protected_jwk: asprintf failed");
        ret = NULL;
    }
    free(jwk);
    return ret;
}

char *jws_protected_kid(const char *nonce, const char *url,
        const char *kid)
{
    char *ret = NULL;
    if (asprintf(&ret, "{\"alg\":\"RS256\",\"nonce\":\"%s\","
                "\"url\":\"%s\",\"kid\":\"%s\"}", nonce, url, kid) < 0)
    {
        warnx("jws_protected_kid: asprintf failed");
        ret = NULL;
    }
    return ret;
}

char *jws_thumbprint(privkey_t key)
{
    char *ret = NULL;
    char *m = NULL;
    char *e = NULL;
#if defined(USE_GNUTLS)
    switch (gnutls_privkey_get_pk_algorithm(key, NULL))
    {
        case GNUTLS_PK_RSA:
            if (!rsa_params(key, &m, &e))
            {
                goto out;
            }
            break;

        case GNUTLS_PK_DSA:
        case GNUTLS_PK_DH:
        case GNUTLS_PK_EC:
#elif defined(USE_MBEDTLS)
    switch (mbedtls_pk_get_type(key))
    {
        case MBEDTLS_PK_RSA:
            if (!rsa_params(key, &m, &e))
            {
                goto out;
            }
            break;

        case MBEDTLS_PK_ECDSA:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECKEY:
#endif
        default:
            warnx("jws_thumbprint: only RSA keys supported at this time");
            goto out;
            break;
    }
    ret = sha256_base64url(
            "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}", e, m);
    if (!ret)
    {
        warnx("jws_thumbprint: sha256_base64url failed");
    }
out:
    free(e);
    free(m);
    return ret;
}

#if defined(USE_GNUTLS)
static unsigned char *gnutls_datum_data(gnutls_datum_t *d, bool free)
{
    unsigned char *ret = malloc(d->size);
    if (!ret)
    {
        warn("gnutls_datum2mem: malloc failed");
        goto out;
    }
    memcpy(ret, d->data, d->size);
    if (free)
    {
        gnutls_free(d->data);
        d->data = NULL;
    }
out:
    return ret;
}
#endif

char *jws_encode(const char *protected, const char *payload,
    privkey_t key)
{
    int r;
    char *jws = NULL;
    char *encoded_payload = encode_base64url(payload);
    char *encoded_protected = encode_base64url(protected);
    char *encoded_combined = NULL;
    unsigned char *signature = NULL;
    size_t signature_size = 0;
    char *encoded_signature = NULL;
    if (!encoded_payload || !encoded_protected)
    {
        warnx("jws_encode: encode_base64url failed");
        goto out;
    }
    if (asprintf(&encoded_combined, "%s.%s", encoded_protected,
                encoded_payload) < 0)
    {
        warnx("jws_encode: asprintf failed");
        encoded_combined = NULL;
        goto out;
    }
#if defined(USE_GNUTLS)
    gnutls_datum_t data = {
        (unsigned char *)encoded_combined, strlen(encoded_combined)};
    gnutls_datum_t sign = {NULL, 0};
    r = gnutls_privkey_sign_data(key, GNUTLS_DIG_SHA256, 0, &data, &sign);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("jws_encode: gnutls_privkey_sign_data: %s", gnutls_strerror(r));
        goto out;
    }
    signature_size = sign.size;
    signature = gnutls_datum_data(&sign, true);
    if (!signature)
    {
        goto out;
    }
#elif defined(USE_MBEDTLS)
    size_t hash_len = 32;
    unsigned char *hash = calloc(1, hash_len);
    if (!hash)
    {
        warn("sha256_base64url: calloc failed");
        goto out;
    }
    r = mbedtls_hash_fast(MBEDTLS_MD_SHA256, encoded_combined,
            strlen(encoded_combined), hash);
    if (r != 0)
    {
        warnx("sha256_base64url: mbedtls_hash_fast failed: %s",
                _mbedtls_strerror(r));
        free(hash);
        goto out;
    }
    signature = calloc(1, 4096);
    if (!signature)
    {
        warn("sha256_base64url: calloc failed");
        free(hash);
        goto out;
    }
    r = mbedtls_pk_sign(key, MBEDTLS_MD_SHA256, hash, hash_len, signature,
            &signature_size, mbedtls_ctr_drbg_random, &ctr_drbg);
    free(hash);
    if (r != 0)
    {
        warnx("sha256_base64url: mbedtls_pk_sign failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
#endif
    size_t encoded_signature_len = base64_ENCODED_LEN(signature_size,
            base64_VARIANT_URLSAFE_NO_PADDING);
    encoded_signature = calloc(1, encoded_signature_len);
    if (!encoded_signature)
    {
        warn("jsw_encode: calloc failed");
        goto out;
    }
    if (!bin2base64(encoded_signature, encoded_signature_len, signature,
                signature_size, base64_VARIANT_URLSAFE_NO_PADDING))
    {
        warnx("jsw_encode: bin2base64 failed");
        goto out;
    }
    if (asprintf(&jws,
                "{\"protected\":\"%s\","
                "\"payload\":\"%s\","
                "\"signature\":\"%s\"}",
                encoded_protected,
                encoded_payload,
                encoded_signature) < 0)
    {
        warnx("jws_encode: asprintf failed");
        jws = NULL;
    }
out:
    free(encoded_payload);
    free(encoded_protected);
    free(encoded_combined);
    free(encoded_signature);
    free(signature);
    return jws;
}

bool key_gen(const char *keyfile)
{
    bool success = false;
    int r;
    unsigned char *pem_data = NULL;
    size_t pem_size = 0;
    msg(1, "generating new key");
#if defined(USE_GNUTLS)
    gnutls_x509_privkey_t key = NULL;
    r = gnutls_x509_privkey_init(&key);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("key_gen: gnutls_x509_privkey_init: %s",
                gnutls_strerror(r));
        goto out;
    }
    r = gnutls_x509_privkey_generate(key, GNUTLS_PK_RSA, 4096, 0);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("key_gen: gnutls_x509_privkey_generate: %s",
                gnutls_strerror(r));
        goto out;
    }
    gnutls_datum_t data = {NULL, 0};
    r = gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_PEM, &data);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("key_gen: gnutls_x509_privkey_export2: %s",
                gnutls_strerror(r));
        goto out;
    }
    pem_size = data.size;
    pem_data = gnutls_datum_data(&data, true);
    if (!pem_data)
    {
        goto out;
    }
#elif defined(USE_MBEDTLS)
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    const mbedtls_pk_info_t *pki = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
    if (!pki)
    {
        warnx("key_gen: mbedtls_pk_info_from_type failed");
        goto out;
    }
    r = mbedtls_pk_setup(&key, pki);
    if (r)
    {
        warnx("key_gen: mbedtls_pk_setup failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    r = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random,
            &ctr_drbg, 4096, 65537);
    if (r)
    {
        warnx("key_gen: mbedtls_rsa_genkey failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    pem_size = 4096;
    pem_data = calloc(1, pem_size);
    if (!pem_data)
    {
        warn("key_gen: calloc failed");
        goto out;
    }
    r = mbedtls_pk_write_key_pem(&key, pem_data, pem_size);
    if (r)
    {
        warnx("key_gen: mbedtls_pk_write_key_pem failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    pem_size = strlen(pem_data);
#endif
    mode_t prev = umask((S_IWUSR | S_IXUSR) | S_IRWXG | S_IRWXO);
    FILE *f = fopen(keyfile, "w");
    umask(prev);
    if (!f)
    {
        warn("key_gen: failed to create %s", keyfile);
        goto out;
    }
    r = fwrite(pem_data, 1, pem_size, f);
    fclose(f);
    if (r != pem_size)
    {
        warn("key_load: failed to write to %s", keyfile);
        unlink(keyfile);
        goto out;
    }
    msg(1, "key saved to %s", keyfile);
    success = true;
out:
#if defined(USE_GNUTLS)
    gnutls_x509_privkey_deinit(key);
#elif defined(USE_MBEDTLS)
    mbedtls_pk_free(&key);
#endif
    free(pem_data);
    return success;
}

privkey_t key_load(bool gen_if_needed, const char *format, ...)
{
    int r;
    privkey_t key = NULL;
    char *keyfile = NULL;
    unsigned char *keydata = NULL;
    size_t keysize = 0;
    va_list ap;
    va_start(ap, format);
    if (vasprintf(&keyfile, format, ap) < 0)
    {
        keyfile = NULL;
    }
    va_end(ap);
    if (!keyfile)
    {
        warnx("key_load: vasprintf failed");
        goto out;
    }

    msg(1, "loading key from %s", keyfile);
    while (!(keydata = (unsigned char *)read_file(keyfile, &keysize)))
    {
        if (errno != ENOENT)
        {
            warn("key_load: failed to read %s", keyfile);
            goto out;
        }
        else
        {
            msg(1, "%s not found", keyfile);
            if (!gen_if_needed || !key_gen(keyfile))
            {
                goto out;
            }
        }
    }

#if defined(USE_GNUTLS)
    r = gnutls_privkey_init(&key);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("key_load: gnutls_privkey_import_x509_raw: %s",
                gnutls_strerror(r));
        goto out;
    }
    gnutls_datum_t data = {keydata, keysize};
    r = gnutls_privkey_import_x509_raw(key, &data,
            GNUTLS_X509_FMT_PEM, NULL, 0);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("key_load: gnutls_privkey_import_x509_raw: %s",
                gnutls_strerror(r));
        gnutls_privkey_deinit(key);
        key = NULL;
        goto out;
    }

    r = gnutls_privkey_verify_params(key);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("key_load: gnutls_privkey_verify_params: %s",
                gnutls_strerror(r));
        gnutls_privkey_deinit(key);
        key = NULL;
        goto out;
    }

    r = gnutls_privkey_get_pk_algorithm(key, NULL);
    if (r != GNUTLS_PK_RSA)
    {
        warnx("key_load: only RSA keys supported at this time");
        gnutls_privkey_deinit(key);
        key = NULL;
        goto out;
    }
#elif defined (USE_MBEDTLS)
    key = calloc(1, sizeof(*key));
    if (!key)
    {
        warn("key_load: calloc failed");
        goto out;
    }
    mbedtls_pk_init(key);
    r = mbedtls_pk_parse_key(key, keydata, keysize+1, NULL, 0);
    if (r)
    {
        warnx("key_load: mbedtls_pk_parse failed: %s",
                _mbedtls_strerror(r));
        free(key);
        key = NULL;
        goto out;
    }

    if (!mbedtls_pk_can_do(key, MBEDTLS_PK_RSA))
    {
        warnx("key_load: only RSA keys supported at this time");
        mbedtls_pk_free(key);
        free(key);
        key = NULL;
        goto out;
    }

    r = mbedtls_rsa_check_privkey(mbedtls_pk_rsa(*key));
    if (r)
    {
        warnx("key_load: mbedtls_rsa_check_privkey failed: %s",
                _mbedtls_strerror(r));
        mbedtls_pk_free(key);
        free(key);
        key = NULL;
        goto out;
    }
#endif
out:
    free(keyfile);
    free(keydata);
    return key;
}

char *csr_gen(const char * const *names, privkey_t key)
{
    char *req = NULL;
    unsigned char *csrdata = NULL;
    size_t csrsize = 0;
    int r;
#if defined(USE_GNUTLS)
    gnutls_pubkey_t pubkey = NULL;
    gnutls_x509_crq_t crq = NULL;

    r = gnutls_x509_crq_init(&crq);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("csr_gen: gnutls_x509_crq_init: %s", gnutls_strerror(r));
        goto out;
    }

    r = gnutls_x509_crq_set_dn_by_oid(crq, GNUTLS_OID_X520_COMMON_NAME, 0,
                *names, strlen(*names));
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("csr_gen: gnutls_x509_crq_set_dn_by_oid: %s", gnutls_strerror(r));
        goto out;
    }

    while (*names)
    {
        r = gnutls_x509_crq_set_subject_alt_name(crq, GNUTLS_SAN_DNSNAME,
                *names, strlen(*names), GNUTLS_FSAN_APPEND);
        if (r != GNUTLS_E_SUCCESS)
        {
            warnx("csr_gen: gnutls_x509_set_subject_alt_name: %s",
                    gnutls_strerror(r));
            goto out;
        }
        names++;
    }

    r = gnutls_pubkey_init(&pubkey);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("csr_gen: gnutls_pubkey_init: %s", gnutls_strerror(r));
        goto out;
    }

    r = gnutls_pubkey_import_privkey(pubkey, key, 0, 0);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("csr_gen: gnutls_pubkey_import_privkey: %s", gnutls_strerror(r));
        goto out;
    }

    r = gnutls_x509_crq_set_pubkey(crq, pubkey);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("csr_gen: gnutls_x509_crq_set_pubkey: %s", gnutls_strerror(r));
        goto out;
    }

    gnutls_digest_algorithm_t dig;
    unsigned int mand;
    r = gnutls_pubkey_get_preferred_hash_algorithm(pubkey, &dig, &mand);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("csr_gen: gnutls_pubkey_get_preferred_hash_algorithm: %s",
                gnutls_strerror(r));
        goto out;
    }
    if (mand == 0)
    {
        dig = GNUTLS_DIG_SHA256;
    }
    else if (dig != GNUTLS_DIG_SHA256)
    {
        warnx("csr_gen: only SHA256 digest supported at this time");
        goto out;
    }

    r = gnutls_x509_crq_privkey_sign(crq, key, dig, 0);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("csr_gen: gnutls_crq_privkey_sign: %s", gnutls_strerror(r));
        goto out;
    }

    gnutls_datum_t data = {NULL, 0};
    r = gnutls_x509_crq_export2(crq, GNUTLS_X509_FMT_DER, &data);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("csr_gen: gnutls_x509_crq_export2: %s", gnutls_strerror(r));
        goto out;
    }
    csrsize = data.size;
    csrdata = gnutls_datum_data(&data, true);
    if (!csrdata)
    {
        goto out;
    }
#elif defined(USE_MBEDTLS)
    mbedtls_x509write_csr csr;
    mbedtls_x509write_csr_init(&csr);
    mbedtls_x509write_csr_set_key(&csr, key);
    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    size_t buflen = 4096;
    unsigned char *buf = calloc(1, buflen);
    if (!buf)
    {
        warn("csr_gen: calloc failed");
        goto out;
    }

    r = mbedtls_x509write_csr_set_subject_name(&csr, *names);
    if (r)
    {
        warnx("csr_gen: mbedtls_x509write_csr_set_subject_name failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }

    unsigned char *p = buf + buflen;
    size_t len = 0;
    size_t count = 0;
    while (names[count]) count++;
    while (count)
    {
        count--;
        r = mbedtls_asn1_write_raw_buffer(&p, buf, names[count],
                strlen(names[count]));
        if (r >= 0)
        {
            len += r;
        }
        else
        {
            warnx("csr_gen: mbedtls_asn1_write_raw_buffer failed: %s",
                _mbedtls_strerror(r));
            goto out;
        }
        r = mbedtls_asn1_write_len(&p, buf, strlen(names[count]));
        if (r >= 0)
        {
            len += r;
        }
        else
        {
            warnx("csr_gen: mbedtls_asn1_write_len failed: %s",
                _mbedtls_strerror(r));
            goto out;
        }
        r = mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONTEXT_SPECIFIC|2);
        if (r >= 0)
        {
            len += r;
        }
        else
        {
            warnx("csr_gen: mbedtls_asn1_write_tag failed: %s",
                _mbedtls_strerror(r));
            goto out;
        }
    }
    r = mbedtls_asn1_write_len(&p, buf, len);
    if (r >= 0)
    {
        len += r;
    }
    else
    {
        warnx("csr_gen: mbedtls_asn1_write_len failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }
    r = mbedtls_asn1_write_tag(&p, buf,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (r >= 0)
    {
        len += r;
    }
    else
    {
        warnx("csr_gen: mbedtls_asn1_write_tag failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }

    r = mbedtls_x509write_csr_set_extension(&csr,
            MBEDTLS_OID_SUBJECT_ALT_NAME,
            MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
            buf + buflen - len, len);
    if (r)
    {
        warnx("csr_gen: mbedtls_x509write_csr_set_extension failed: %s",
                _mbedtls_strerror(r));
        goto out;
    }

    r = mbedtls_x509write_csr_der(&csr, buf, buflen,
            mbedtls_ctr_drbg_random, &ctr_drbg);
    if (r < 0)
    {
        warnx("csr_gen: mbedtls_x509write_csr_der failed: %s",
                _mbedtls_strerror(r));
        free(buf);
        goto out;
    }
    csrsize = r;
    csrdata = calloc(1, csrsize);
    if (!csrdata)
    {
        warn("csr_gen: calloc failed");
        free(buf);
        goto out;
    }
    memcpy(csrdata, buf + buflen - csrsize, csrsize);
#endif
    r = base64_ENCODED_LEN(csrsize, base64_VARIANT_URLSAFE_NO_PADDING);
    if (!(req = calloc(1, r)))
    {
        warn("csr_gen: calloc failed");
        goto out;
    }
    if (!bin2base64(req, r, csrdata, csrsize,
                base64_VARIANT_URLSAFE_NO_PADDING))
    {
        warnx("csr_gen: bin2base64 failed");
        free(req);
        req = NULL;
        goto out;
    }
out:
#if defined(USE_GNUTLS)
    gnutls_pubkey_deinit(pubkey);
    gnutls_x509_crq_deinit(crq);
#elif defined(USE_MBEDTLS)
    mbedtls_x509write_csr_free(&csr);
    free(buf);
#endif
    free(csrdata);
    return req;
}

bool cert_save(const char *cert, const char *certdir)
{
    bool success = false;
    time_t t = time(NULL);
    char *certfile = NULL;
    char *bakfile = NULL;
    char *tmpfile = NULL;
    int fd = -1;

    if (asprintf(&certfile, "%s/cert.pem", certdir) < 0)
    {
        certfile = NULL;
        warnx("cert_save: vasprintf failed");
        goto out;
    }
    if (asprintf(&tmpfile, "%s/cert.pem.tmp", certdir) < 0)
    {
        tmpfile = NULL;
        warnx("cert_save: vasprintf failed");
        goto out;
    }
    if (asprintf(&bakfile, "%s/cert-%llu.pem", certdir,
                (unsigned long long)t) < 0)
    {
        bakfile = NULL;
        warnx("cert_save: vasprintf failed");
        goto out;
    }
    msg(1, "saving certificate to %s", certfile);
    if (link(certfile, bakfile) < 0 && errno != ENOENT)
    {
        warn("failed to link %s to %s", bakfile, certfile);
        goto out;
    }
    fd = open(tmpfile, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IRGRP|S_IROTH);
    if (fd < 0)
    {
        warn("failed to create %s", tmpfile);
        goto out;
    }
    if (write(fd, cert, strlen(cert)) != strlen(cert))
    {
        warn("failed to write to %s", tmpfile);
        goto out;
    }
    if (close(fd) < 0)
    {
        warn("failed to close %s", tmpfile);
        goto out;
    }
    else
    {
        fd = -1;
    }
    if (rename(tmpfile, certfile) < 0)
    {
        warn("failed to rename %s to %s", tmpfile, certfile);
        goto out;
    }
    msg(1, "certificate saved to %s", certfile);
    success = true;
out:
    if (fd >= 0) close(fd);
    free(bakfile);
    free(tmpfile);
    free(certfile);
    return success;
}

#if defined(USE_GNUTLS)
static gnutls_x509_crt_t cert_load(const char *format, ...)
{
    gnutls_x509_crt_t crt = NULL;
#elif defined (USE_MBEDTLS)
static mbedtls_x509_crt *cert_load(const char *format, ...)
{
    mbedtls_x509_crt *crt = NULL;
#endif
    char *certfile = NULL;
    unsigned char *certdata = NULL;
    size_t certsize = 0;
    int r;
    va_list ap;

    va_start(ap, format);
    if (vasprintf(&certfile, format, ap) < 0)
    {
        certfile = NULL;
    }
    va_end(ap);
    if (!certfile)
    {
        warnx("cert_load: vasprintf failed");
        goto out;
    }

    certdata = (unsigned char *)read_file(certfile, &certsize);
    if (!certdata)
    {
        if (errno == ENOENT)
        {
            msg(2, "%s does not exist", certfile);
        }
        else
        {
            warn("cert_load: failed to read %s", certfile);
        }
        goto out;
    }

#if defined(USE_GNUTLS)
    gnutls_datum_t data = {certdata, certsize};
    r = gnutls_x509_crt_init(&crt);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("cert_load: gnutls_x509_crt_init: %s", gnutls_strerror(r));
        gnutls_x509_crt_deinit(crt);
        crt = NULL;
        goto out;
    }

    r = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("cert_load: gnutls_x509_crt_import: %s", gnutls_strerror(r));
        gnutls_x509_crt_deinit(crt);
        crt = NULL;
        goto out;
    }
#elif defined (USE_MBEDTLS)
    crt = calloc(1, sizeof(*crt));
    if (!crt)
    {
        warn("cert_load: calloc failed");
        goto out;
    }
    mbedtls_x509_crt_init(crt);
    r = mbedtls_x509_crt_parse(crt, certdata, certsize+1);
    if (r < 0)
    {
        warnx("cert_load: mbedtls_x509_crt_parse failed: %s",
                _mbedtls_strerror(r));
        mbedtls_x509_crt_free(crt);
        free(crt);
        crt = NULL;
        goto out;
    }
    if (r > 0)
    {
        warnx("cert_load: failed to parse %d certificates", r);
        mbedtls_x509_crt_free(crt);
        free(crt);
        crt = NULL;
        goto out;
    }
#endif
out:
    free(certdata);
    free(certfile);
    return crt;
}

bool cert_valid(const char *certdir, const char * const *names, int validity)
{
    bool valid = false;
#if defined(USE_GNUTLS)
    gnutls_x509_crt_t crt = cert_load("%s/cert.pem", certdir);
    if (!crt)
    {
        goto out;
    }

    time_t expiration = gnutls_x509_crt_get_expiration_time(crt);
    if (expiration == (time_t)-1)
    {
        warnx("cert_valid: gnutls_x509_crt_get_expiration_time failed");
        goto out;
    }

    int days_left = (expiration - time(NULL))/(24*3600);
    msg(1, "%s/cert.pem expires in %d days", certdir, days_left);
    if (days_left < validity)
    {
        msg(1, "%s/cert.pem is due for renewal", certdir);
        goto out;
    }

    while (names && *names)
    {
        if (!gnutls_x509_crt_check_hostname2(crt, *names,
                    GNUTLS_VERIFY_DO_NOT_ALLOW_WILDCARDS))
        {
            msg(1, "%s/cert.pem does not include %s", certdir, *names);
            goto out;
        }
        names++;
    }
    valid = true;
out:
    if (crt)
    {
        gnutls_x509_crt_deinit(crt);
    }
#elif defined (USE_MBEDTLS)
    mbedtls_x509_crt *crt = cert_load("%s/cert.pem", certdir);
    if (!crt)
    {
        goto out;
    }

    struct tm texp =
    {
        .tm_sec = crt->valid_to.sec,
        .tm_min = crt->valid_to.min,
        .tm_hour = crt->valid_to.hour,
        .tm_mday = crt->valid_to.day,
        .tm_mon = crt->valid_to.mon - 1,
        .tm_year = crt->valid_to.year - 1900,
        .tm_isdst = -1
    };

    time_t expiration = mktime(&texp);
    if (expiration == (time_t)-1)
    {
        warnx("cert_valid: failed to determine expiration time");
        goto out;
    }

    int days_left = (expiration - time(NULL))/(24*3600);
    msg(1, "%s/cert.pem expires in %d days", certdir, days_left);
    if (days_left < validity)
    {
        msg(1, "%s/cert.pem is due for renewal", certdir);
        goto out;
    }

    while (names && *names)
    {
        const mbedtls_x509_name *name = NULL;
        const mbedtls_x509_sequence *cur = NULL;

        if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME)
        {
            for (cur = &crt->subject_alt_names; cur; cur = cur->next)
            {
                if (strncasecmp(*names, cur->buf.p, strlen(*names)) == 0)
                {
                    break;
                }
            }
        }
        else for (name = &crt->subject; name != NULL; name = name->next)
        {
            if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0 &&
                    strncasecmp(*names, name->val.p, strlen(*names)) == 0)
            {
                break;
            }
        }
        if (cur == NULL && name == NULL)
        {
            msg(1, "%s/cert.pem does not include %s", certdir, *names);
            goto out;
        }
        names++;
    }
    valid = true;

out:
    if (crt)
    {
        mbedtls_x509_crt_free(crt);
        free(crt);
    }
#endif
    return valid;
}

char *cert_der_base64url(const char *certfile)
{
    char *ret = NULL;
    unsigned char *certdata = NULL;
    size_t certsize = 0;
    int r;
#if defined(USE_GNUTLS)
    gnutls_x509_crt_t crt = cert_load(certfile);
    if (!crt)
    {
        goto out;
    }

    gnutls_datum_t data = {NULL, 0};
    r = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &data);
    gnutls_x509_crt_deinit(crt);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("cert_der_base64url: gnutls_x509_crt_export2: %s",
                gnutls_strerror(r));
        goto out;
    }
    certsize = data.size;
    certdata = gnutls_datum_data(&data, true);
    if (!certdata)
    {
        goto out;
    }
#elif defined (USE_MBEDTLS)
    certdata = read_file(certfile, &certsize);
    if (!certdata)
    {
        warnx("cert_der_base64url: error reading %s", certfile);
        goto out;
    }
    mbedtls_pem_context ctx;
    mbedtls_pem_init(&ctx);
    size_t len;
    r = mbedtls_pem_read_buffer(&ctx, "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----", certdata, NULL, 0, &len);
    if (r)
    {
        warnx("cert_der_base64url: mbedtls_pem_read_buffer failed: %s",
                _mbedtls_strerror(r));
        mbedtls_pem_free(&ctx);
        goto out;
    }
    free(certdata);
    certdata = calloc(1, certsize);
    if (!certdata)
    {
        warn("cert_der_base64url: calloc failed");
        mbedtls_pem_free(&ctx);
        goto out;
    }
    memcpy(certdata, ctx.buf, ctx.buflen);
    certsize = ctx.buflen;
    mbedtls_pem_free(&ctx);
#endif
    r = base64_ENCODED_LEN(certsize, base64_VARIANT_URLSAFE_NO_PADDING);
    if (!(ret = calloc(1, r)))
    {
        warn("cert_der_base64url: calloc failed");
        goto out;
    }
    if (!bin2base64(ret, r, certdata, certsize,
                base64_VARIANT_URLSAFE_NO_PADDING))
    {
        warnx("cert_der_base64url: bin2base64 failed");
        free(ret);
        ret = NULL;
        goto out;
    }
out:
    free(certdata);
    return ret;
}
