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

#ifndef __CRYPTO_H__
#define __CRYPTO_H__
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>
#include <stdbool.h>

char *sha256_base64url(const char *, ...);
char *jws_protected_jwk(const char *, const char *, gnutls_privkey_t);
char *jws_protected_kid(const char *, const char *, const char *);
char *jws_thumbprint(gnutls_privkey_t);
char *jws_encode(const char *, const char *, gnutls_privkey_t);
bool key_gen(const char *);
gnutls_privkey_t key_load(bool, const char *, ...);
char *csr_gen(const char * const *, gnutls_privkey_t);
gnutls_x509_crt_t cert_load(const char *format, ...);
bool cert_save(const char *, const char *);
char *cert_der_base64url(const char *);
bool cert_valid(const char *, const char * const *, int);

#endif

