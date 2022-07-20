/*
 * Copyright (C) 2019-2022 Nicola Di Lieto <nicola.dilieto@gmail.com>
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

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdbool.h>

#if defined(USE_GNUTLS)
#if defined(USE_OPENSSL) || defined(USE_MBEDTLS)
#error only one of USE_GNUTLS, USE_MBEDTLS or USE_OPENSSL must be defined
#endif
#include <gnutls/abstract.h>

typedef gnutls_privkey_t privkey_t;
#define privkey_deinit gnutls_privkey_deinit

#elif defined(USE_OPENSSL)
#if defined(USE_GNUTLS) || defined(USE_MBEDTLS)
#error only one of USE_GNUTLS, USE_MBEDTLS or USE_OPENSSL must be defined
#endif
#include <openssl/evp.h>

typedef EVP_PKEY *privkey_t;
#define privkey_deinit EVP_PKEY_free

#elif defined(USE_MBEDTLS)
#if defined(USE_OPENSSL) || defined(USE_GNUTLS)
#error only one of USE_GNUTLS, USE_MBEDTLS or USE_OPENSSL must be defined
#endif
#include <mbedtls/pk.h>

typedef mbedtls_pk_context *privkey_t;
static inline void privkey_deinit(privkey_t key)
{
    mbedtls_pk_free(key);
    free(key);
}

#else
#error either USE_GNUTLS or USE_MBEDTLS or USE_OPENSSL must be defined
#endif

typedef enum
{
    PK_NONE = 0,
    PK_RSA,
    PK_EC
} keytype_t;

bool crypto_init(void);
void crypto_deinit(void);
char *sha2_base64url(size_t, const char *, ...);
char *hmac_base64url(size_t, const char *, const char *, ...);
char *jws_jwk(privkey_t key, const char **, const char **);
char *jws_protected_jwk(const char *, const char *, privkey_t);
char *jws_protected_kid(const char *, const char *, const char *, privkey_t);
char *jws_protected_eab(size_t, const char *, const char *);
char *jws_thumbprint(privkey_t);
char *jws_encode(const char *, const char *, privkey_t);
char *jws_encode_hmac(const char *, const char *, size_t, const char *);
keytype_t key_type(privkey_t);
privkey_t key_load(keytype_t, int bits, const char *, ...);
bool is_ip(const char *, unsigned char *, size_t *);
char *csr_gen(char * const *, bool, privkey_t);
char *csr_load(const char *, char ***);
char *cert_der_base64url(const char *);
bool cert_valid(const char *, char * const *, int, bool);
bool cert_match(const char *, unsigned char *, size_t);

#endif

