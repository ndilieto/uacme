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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base64.h"
#include "crypto.h"
#include "msg.h"

char *sha256_base64url(const char *format, ...)
{
    char *input = NULL;
    size_t encoded_hash_len;
    char *encoded_hash = NULL;
    unsigned int hash_len;
    unsigned char *hash = NULL;
    va_list ap;
    va_start(ap, format);
    if (vasprintf(&input, format, ap) < 0)
    {
        warn("sha256_base64url: vasprintf failed");
        input = NULL;
        goto out;
    }
    hash_len = gnutls_hash_get_len(GNUTLS_DIG_SHA256);
    hash = calloc(1, hash_len);
    if (!hash)
    {
        warnx("sha256_base64url: calloc failed");
        goto out;
    }
    int r = gnutls_hash_fast(GNUTLS_DIG_SHA256, input, strlen(input), hash);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("sha256_base64url: gnutls_hash_fast failed: %s",
                gnutls_strerror(r));
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

char *bn2str(const gnutls_datum_t *bn)
{
    size_t len = bn->size;
    unsigned char *data = bn->data;
    while (len && !*data)
    {
        data++;
        len--;
    }
    size_t encoded_len = base64_ENCODED_LEN(len,
            base64_VARIANT_URLSAFE_NO_PADDING);
    char *encoded = calloc(1, encoded_len);
    if (!encoded)
    {
        warn("bn2str: calloc failed");
        return NULL;
    }
    if (!bin2base64(encoded, encoded_len, data, len,
                base64_VARIANT_URLSAFE_NO_PADDING))
    {
        free(encoded);
        encoded = NULL;
    }
    return encoded;
}

char *jws_protected_jwk(const char *nonce, const char *url,
        gnutls_privkey_t key)
{
    int r;
    char *protected = NULL;
    char *m = NULL;
    char *e = NULL;
    gnutls_datum_t mod = {NULL, 0};
    gnutls_datum_t exp = {NULL, 0};
    switch (gnutls_privkey_get_pk_algorithm(key, NULL))
    {
        case GNUTLS_PK_RSA:
            r = gnutls_privkey_export_rsa_raw(key, &mod, &exp,
                    NULL, NULL, NULL, NULL, NULL, NULL);
            if (r < 0)
            {
                warnx("jws_protected_jwk: privkey_export: %s",
                        gnutls_strerror(r));
                return NULL;
            }
            else
            {
                m = bn2str(&mod);
                gnutls_free(mod.data);
                if (!m)
                {
                    warnx("jws_protected_jwk: bn2str failed");
                    gnutls_free(exp.data);
                    return NULL;
                }
                e = bn2str(&exp);
                gnutls_free(exp.data);
                if (!e)
                {
                    warnx("jws_protected_jwk: bn2str failed");
                    free(m);
                    return NULL;
                }
            }
            if (asprintf(&protected,
                        "{\"alg\":\"RS256\","
                        "\"nonce\":\"%s\","
                        "\"url\":\"%s\","
                        "\"jwk\":{"
                        "\"kty\":\"RSA\",\"e\":\"%s\",\"n\":\"%s\"}}",
                        nonce, url, e, m) < 0)
            {
                warnx("jws_protected_jwk: asprintf failed");
                protected = NULL;
            }
            free(e);
            free(m);
            break;

        case GNUTLS_PK_DSA:
        case GNUTLS_PK_DH:
        case GNUTLS_PK_EC:
        default:
            warnx("jws_protected_jwk: unsupported key algorithm");
            break;
    }
    return protected;
}

char *jws_protected_kid(const char *nonce, const char *url,
        const char *kid)
{
    char *protected = NULL;
    if (asprintf(&protected,
                "{\"alg\":\"RS256\","
                "\"nonce\":\"%s\","
                "\"url\":\"%s\","
                "\"kid\":\"%s\"}",
                nonce, url, kid) < 0)
    {
        warnx("jws_protected_kid: asprintf failed");
        protected = NULL;
    }
    return protected;
}

char *jws_thumbprint(gnutls_privkey_t key)
{
    int r;
    char *thumbprint = NULL;
    char *m = NULL;
    char *e = NULL;
    gnutls_datum_t mod = {NULL, 0};
    gnutls_datum_t exp = {NULL, 0};
    switch (gnutls_privkey_get_pk_algorithm(key, NULL))
    {
        case GNUTLS_PK_RSA:
            r = gnutls_privkey_export_rsa_raw(key, &mod, &exp,
                    NULL, NULL, NULL, NULL, NULL, NULL);
            if (r < 0)
            {
                warnx("jws_thumbprint: privkey_export: %s",
                        gnutls_strerror(r));
                return NULL;
            }
            else
            {
                m = bn2str(&mod);
                gnutls_free(mod.data);
                if (!m)
                {
                    warnx("jws_thumbprint: bn2str failed");
                    gnutls_free(exp.data);
                    return NULL;
                }
                e = bn2str(&exp);
                gnutls_free(exp.data);
                if (!e)
                {
                    warnx("jws_thumbprint: bn2str failed");
                    free(m);
                    return NULL;
                }
            }
            thumbprint = sha256_base64url(
                    "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}", e, m);
            if (!thumbprint)
            {
                warnx("jws_thumbprint: sha256_base64url failed");
            }
            free(e);
            free(m);
            break;

        case GNUTLS_PK_DSA:
        case GNUTLS_PK_DH:
        case GNUTLS_PK_EC:
        default:
            warnx("jws_thumbprint: unsupported key algorithm");
            break;
    }
    return thumbprint;
}

char *jws_encode(const char *protected, const char *payload,
    gnutls_privkey_t key)
{
    char *jws = NULL;
    char *encoded_payload = encode_base64url(payload);
    char *encoded_protected = encode_base64url(protected);
    char *encoded_combined = NULL;
    char *encoded_signature = NULL;
    gnutls_datum_t data = {NULL, 0};
    gnutls_datum_t sign = {NULL, 0};
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
    data.data = encoded_combined;
    data.size = strlen(encoded_combined);
    int r = gnutls_privkey_sign_data(key, GNUTLS_DIG_SHA256, 0, &data, &sign);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("jws_encode: gnutls_privkey_sign_data: %s", gnutls_strerror(r));
        goto out;
    }
    size_t encoded_signature_len = base64_ENCODED_LEN(sign.size,
            base64_VARIANT_URLSAFE_NO_PADDING);
    encoded_signature = calloc(1, encoded_signature_len);
    if (!encoded_signature)
    {
        warn("jsw_encode: calloc failed");
        goto out;
    }
    if (!bin2base64(encoded_signature, encoded_signature_len,
                sign.data, sign.size, base64_VARIANT_URLSAFE_NO_PADDING))
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
    gnutls_free(sign.data);
    return jws;
}

bool key_gen(const char *keyfile)
{
    bool success = false;
    gnutls_x509_privkey_t key = NULL;
    gnutls_datum_t data = {NULL, 0};

    msg(1, "generating new key");
    int r = gnutls_x509_privkey_init(&key);
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
    r = gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_PEM, &data);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("key_gen: gnutls_x509_privkey_export2: %s",
                gnutls_strerror(r));
        goto out;
    }
    mode_t prev = umask((S_IWUSR | S_IXUSR) | S_IRWXG | S_IRWXO);
    FILE *f = fopen(keyfile, "w");
    umask(prev);
    if (!f)
    {
        warn("key_gen: failed to create %s", keyfile);
        goto out;
    }
    r = fwrite(data.data, 1, data.size, f);
    fclose(f);
    if (r != data.size)
    {
        warn("key_load: failed to write to %s", keyfile);
        unlink(keyfile);
        goto out;
    }
    msg(1, "key saved to %s", keyfile);
    success = true;
out:
    gnutls_free(data.data);
    gnutls_x509_privkey_deinit(key);
    return success;
}

gnutls_privkey_t key_load(bool gen_if_needed, const char *format, ...)
{
    int r;
    gnutls_privkey_t key = NULL;
    gnutls_datum_t data = {NULL, 0};
    char *keyfile = NULL;
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
    while ((r = gnutls_load_file(keyfile, &data)) != GNUTLS_E_SUCCESS)
    {
        if (errno != ENOENT)
        {
            warn("key_load: gnutls_load_file failed to read %s: %s",
                    keyfile, gnutls_strerror(r));
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

    r = gnutls_privkey_init(&key);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("key_load: gnutls_privkey_import_x509_raw: %s",
                gnutls_strerror(r));
        goto out;
    }
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

out:
    free(keyfile);
    free(data.data);
    return key;
}

char *csr_gen(const char * const *names, gnutls_privkey_t key)
{
    char *req = NULL;
    gnutls_x509_crq_t crq = NULL;
    gnutls_pubkey_t pubkey = NULL;
    gnutls_datum_t data = {NULL, 0};

    int r = gnutls_x509_crq_init(&crq);
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

    r = gnutls_x509_crq_export2(crq, GNUTLS_X509_FMT_DER, &data);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("csr_gen: gnutls_x509_crq_export2: %s", gnutls_strerror(r));
        goto out;
    }

    r = base64_ENCODED_LEN(data.size, base64_VARIANT_URLSAFE_NO_PADDING);
    if (!(req = calloc(1, r)))
    {
        warn("csr_gen: calloc failed");
        goto out;
    }
    if (!bin2base64(req, r, data.data, data.size,
                base64_VARIANT_URLSAFE_NO_PADDING))
    {
        warnx("csr_gen: bin2base64 failed");
        free(req);
        req = NULL;
        goto out;
    }
out:
    gnutls_x509_crq_deinit(crq);
    gnutls_pubkey_deinit(pubkey);
    gnutls_free(data.data);
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

gnutls_x509_crt_t cert_load(const char *format, ...)
{
    bool success = false;
    char *certfile = NULL;
    gnutls_x509_crt_t crt = NULL;
    gnutls_datum_t data = {NULL, 0};
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

    int r = gnutls_load_file(certfile, &data);
    if (r != GNUTLS_E_SUCCESS)
    {
        if (errno == ENOENT)
        {
            msg(2, "%s does not exist", certfile);
        }
        else
        {
            warn("cert_load: gnutls_load_file failed to read %s: %s",
                    certfile, gnutls_strerror(r));
        }
        goto out;
    }

    r = gnutls_x509_crt_init(&crt);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("cert_load: gnutls_x509_crt_init: %s", gnutls_strerror(r));
        goto out;
    }

    r = gnutls_x509_crt_import(crt, &data, GNUTLS_X509_FMT_PEM);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("cert_load: gnutls_x509_crt_import: %s", gnutls_strerror(r));
        goto out;
    }

    success = true;

out:
    gnutls_free(data.data);
    free(certfile);
    if (!success)
    {
        gnutls_x509_crt_deinit(crt);
        crt = NULL;
    }
    return crt;
}

bool cert_valid(const char *certdir, const char * const *names, int validity)
{
    bool valid = false;
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
    if (crt) gnutls_x509_crt_deinit(crt);
    return valid;
}

char *cert_der_base64url(const char *certfile)
{
    char *ret = NULL;
    gnutls_datum_t data = {NULL, 0};
    gnutls_x509_crt_t crt = cert_load(certfile);
    if (!crt)
    {
        goto out;
    }

    int r = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &data);
    if (r != GNUTLS_E_SUCCESS)
    {
        warnx("cert_der_base64url: gnutls_x509_crt_export2: %s",
                gnutls_strerror(r));
        goto out;
    }

    r = base64_ENCODED_LEN(data.size, base64_VARIANT_URLSAFE_NO_PADDING);
    if (!(ret = calloc(1, r)))
    {
        warn("cert_der_base64url: calloc failed");
        goto out;
    }
    if (!bin2base64(ret, r, data.data, data.size,
                base64_VARIANT_URLSAFE_NO_PADDING))
    {
        warnx("cert_der_base64url: bin2base64 failed");
        free(ret);
        ret = NULL;
        goto out;
    }
out:
    gnutls_x509_crt_deinit(crt);
    gnutls_free(data.data);
    return ret;
}
