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

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <locale.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "base64.h"
#include "curlwrap.h"
#include "crypto.h"
#include "json.h"
#include "msg.h"

#define PRODUCTION_URL "https://acme-v02.api.letsencrypt.org/directory"
#define STAGING_URL "https://acme-staging-v02.api.letsencrypt.org/directory"
#define DEFAULT_CONFDIR SYSCONFDIR "/ssl/uacme"

typedef struct acme {
    privkey_t key;
    json_value_t *json;
    json_value_t *account;
    json_value_t *dir;
    json_value_t *order;
    char *nonce;
    char *kid;
    char *headers;
    char *body;
    char *type;
    unsigned char alt_fp[32];
    size_t alt_fp_len;
    size_t alt_n;
    int eab_bits;
    const char *eab_keyid;
    const char *eab_key;
    const char *directory;
    const char *hook;
    const char *email;
    const char *profile;
    char *keyprefix;
    char *certprefix;
} acme_t;

unsigned int retry_after(const char *str, unsigned int d)
{
    long dt;
    char *p;

    if (!str || !*str)
        return d;

    dt = strtol(str, &p, 10);
    if (*p) {
        time_t now = time(NULL);
        struct tm t, tnow;

        gmtime_r(&now, &tnow);
        p = strptime(str, "%a, %d %b %Y %T", &t);
        if (!p)
            p = strptime(str, "%a, %d-%b-%y %T", &t);
        if (!p)
            p = strptime(str, "%a %b %d %T %Y", &t);
        if (!p)
            return d;
        dt = difftime(mktime(&t), mktime(&tnow));
    }
    if (dt > UINT_MAX)
        return UINT_MAX;
    else if (dt > 0)
        return (unsigned int)dt;
    else
        return d;
}

int acme_get(acme_t *a, const char *url)
{
    int ret = 0;

    if (!url) {
        warnx("acme_get: invalid URL");
        goto out;
    }

    for (int retry = 0; retry < 3; retry++) {
        if (retry > 0)
            msg(1, "acme_get: retrying");

        json_free(a->json);
        a->json = NULL;
        free(a->headers);
        a->headers = NULL;
        free(a->body);
        a->body = NULL;
        free(a->type);
        a->type = NULL;

        if (g_loglevel > 1)
            warnx("acme_get: url=%s", url);
        curldata_t *c = curl_get(url);
        if (!c) {
            warnx("acme_get: curl_get failed");
            goto out;
        }
        free(a->nonce);
        a->nonce = find_header(c->headers, "Replay-Nonce");
        a->type = find_header(c->headers, "Content-Type");
        if (a->type && strcasestr(a->type, "json"))
            a->json = json_parse(c->body, c->body_len);
        a->headers = c->headers;
        c->headers = NULL;
        a->body = c->body;
        c->body = NULL;
        ret = c->code;
        curldata_free(c);
        if (g_loglevel > 2) {
            if (a->headers)
                warnx("acme_get: HTTP headers\n%s", a->headers);
            if (a->body)
                warnx("acme_get: HTTP body\n%s", a->body);
        }
        if (g_loglevel > 1) {
            if (a->json) {
                warnx("acme_get: return code %d, json=", ret);
                json_dump(stderr, a->json);
            } else
                warnx("acme_get: return code %d", ret);
        }
        if (!a->type || !a->json ||
                !strcasestr(a->type, "application/problem+json"))
            break;
        if (ret == 503 && json_compare_string(a->json, "type",
                    "urn:ietf:params:acme:error:rateLimited") == 0) {
            char *ra = find_header(a->headers, "Retry-After");
            unsigned int dt = retry_after(ra, 60);
            free(ra);
            msg(1, "acme_get: server busy, waiting %u seconds", dt);
            sleep(dt);
            continue;
        }
        break;
    }
out:
    if (!a->headers)
        a->headers = strdup("");
    if (!a->body)
        a->body = strdup("");
    if (!a->type)
        a->type = strdup("");
    return ret;
}

bool acme_error(acme_t *a)
{
    if (!a->json) return false;

    if (a->type && strcasestr(a->type, "application/problem+json")) {
        warnx("the server reported the following error:");
        json_dump(stderr, a->json);
        return true;
    }

    const json_value_t *e = json_find(a->json, "error");
    if (e && e->type == JSON_OBJECT) {
        warnx("the server reported the following error:");
        json_dump(stderr, e);
        return true;
    }

    return false;
}

bool acme_nonce(acme_t *a)
{
    const char *url = json_find_string(a->dir, "newNonce");
    if (!url)
    {
        warnx("failed to find newNonce URL in directory");
        return false;
    }

    msg(2, "fetching new nonce at %s", url);
    if (acme_get(a, url) != 204) {
        warnx("failed to fetch new nonce at %s", url);
        acme_error(a);
        return false;
    } else if (acme_error(a))
        return false;
    else if (!a->nonce) {
        warnx("failed to find nonce in newNonce resource");
        return false;
    }

    return true;
}

int acme_post(acme_t *a, const char *url, const char *format, ...)
{
    int ret = 0;
    char *payload = NULL;
    char *protected = NULL;
    char *jws = NULL;

    if (!url) {
        warnx("acme_post: invalid URL");
        return 0;
    }

    va_list ap;
    va_start(ap, format);
    if (vasprintf(&payload, format, ap) < 0)
        payload = NULL;
    va_end(ap);
    if (!payload) {
        warnx("acme_post: vasprintf failed");
        return 0;
    }

    for (int retry = 0; retry < 3; retry++) {
        if (retry > 0)
            msg(1, "acme_post: retrying");

        if (!a->nonce && !acme_nonce(a)) {
            warnx("acme_post: no nonce available");
            goto out;
        }

        json_free(a->json);
        a->json = NULL;
        free(a->headers);
        a->headers = NULL;
        free(a->body);
        a->body = NULL;
        free(a->type);
        a->type = NULL;

        protected = (a->kid && *a->kid) ?
            jws_protected_kid(a->nonce, url, a->kid, a->key) :
            jws_protected_jwk(a->nonce, url, a->key);
        if (!protected) {
            warnx("acme_post: jws_protected_xxx failed");
            goto out;
        }
        jws = jws_encode(protected, payload, a->key);
        if (!jws) {
            warnx("acme_post: jws_encode failed");
            goto out;
        }
        if (g_loglevel > 2)
            warnx("acme_post: url=%s payload=%s protected=%s jws=%s",
                    url, payload, protected, jws);
        else if (g_loglevel > 1)
            warnx("acme_post: url=%s payload=%s", url, payload);
        curldata_t *c = curl_post(url, jws, strlen(jws),
                "Content-Type: application/jose+json", NULL);
        if (!c) {
            warnx("acme_post: curl_post failed");
            goto out;
        }
        free(a->nonce);
        a->nonce = find_header(c->headers, "Replay-Nonce");
        a->type = find_header(c->headers, "Content-Type");
        if (a->type && strcasestr(a->type, "json"))
            a->json = json_parse(c->body, c->body_len);
        a->headers = c->headers;
        c->headers = NULL;
        a->body = c->body;
        c->body = NULL;
        ret = c->code;
        curldata_free(c);
        if (g_loglevel > 2) {
            if (a->headers)
                warnx("acme_post: HTTP headers:\n%s", a->headers);
            if (a->body)
                warnx("acme_post: HTTP body:\n%s", a->body);
        }
        if (g_loglevel > 1) {
            if (a->json) {
                warnx("acme_post: return code %d, json=", ret);
                json_dump(stderr, a->json);
            } else
                warnx("acme_post: return code %d", ret);
        }
        if (!a->type || !a->json ||
                !strcasestr(a->type, "application/problem+json"))
            break;
        if (ret == 400 && json_compare_string(a->json, "type",
                    "urn:ietf:params:acme:error:badNonce") == 0) {
            msg(1, "acme_post: server rejected nonce");
            continue;
        }
        if (ret == 503 && json_compare_string(a->json, "type",
                    "urn:ietf:params:acme:error:rateLimited") == 0) {
            char *ra = find_header(a->headers, "Retry-After");
            unsigned int dt = retry_after(ra, 60);
            free(ra);
            msg(1, "acme_post: server busy, waiting %u seconds", dt);
            sleep(dt);
            continue;
        }
        break;
    }
out:
    free(payload);
    free(protected);
    free(jws);
    if (!a->headers)
        a->headers = strdup("");
    if (!a->body)
        a->body = strdup("");
    if (!a->type)
        a->type = strdup("");
    return ret;
}

int hook_run(const char *prog, const char *method, const char *type,
        const char *ident, const char *token, const char *auth)
{
    int ret = -1;
    pid_t pid = fork();
    if (pid < 0)
        warn("hook_run: fork failed");
    else if (pid > 0) { // parent
        int status;
        if (waitpid(pid, &status, 0) < 0)
            warn("hook_run: waitpid failed");
        else if (WIFEXITED(status))
            ret = WEXITSTATUS(status);
        else
            warnx("hook_run: %s terminated abnormally", prog);
    } else { // child
        setenv("UACME_METHOD", method, 1);
        setenv("UACME_TYPE", type, 1);
        setenv("UACME_IDENT", ident, 1);
        setenv("UACME_TOKEN", token, 1);
        setenv("UACME_AUTH", auth, 1);
        if (execl(prog, prog, method, type, ident, token, auth,
                    (char *)NULL) < 0) {
            warn("hook_run: failed to execute %s", prog);
            abort();
        }
    }
    return ret;
}

bool check_or_mkdir(bool allow_create, const char *dir, mode_t mode)
{
    bool ret = false;
    char *tmp = strdup(dir);
    if (!tmp) {
        warnx("check_or_mkdir: strdup failed");
        goto out;
    }
    for (size_t i = strlen(tmp); i > 1; i--) {
        if (tmp[i - 1] != '/')
            break;
        tmp[i - 1] = 0;
    }
    if (access(dir, F_OK) < 0) {
        if (!allow_create) {
            warnx("failed to access %s", dir);
            goto out;
        }
        if (mkdir(dir, mode) < 0) {
            warn("failed to create %s", dir);
            goto out;
        }
        msg(1, "created directory %s", dir);
    }
    struct stat st;
    if (stat(dir, &st) != 0) {
        warn("failed to stat %s", dir);
        goto out;
    }
    if (!S_ISDIR(st.st_mode)) {
        warnx("%s is not a directory", dir);
        goto out;
    }
    ret = true;
out:
    free(tmp);
    return ret;
}

char *identifiers(char * const *names)
{
    char *ids = NULL;
    char *tmp = NULL;
    if (asprintf(&tmp, "\"identifiers\":[") < 0) {
        warnx("identifiers: asprintf failed");
        return NULL;
    }
    while (names && *names) {
        if (asprintf(&ids, "%s{\"type\":\"%s\",\"value\":\"%s\"},", tmp,
                    is_ip(*names, NULL, NULL) ? "ip" : "dns", *names) < 0) {
            warnx("identifiers: asprintf failed");
            free(tmp);
            return NULL;
        }
        free(tmp);
        tmp = ids;
        ids = NULL;
        names++;
    }
    tmp[strlen(tmp)-1] = 0;
    if (asprintf(&ids, "%s]", tmp) < 0) {
        warnx("identifiers: asprintf failed");
        ids = NULL;
    }
    free(tmp);
    return ids;
}

bool acme_bootstrap(acme_t *a)
{
    msg(1, "fetching directory at %s", a->directory);
    if (acme_get(a, a->directory) != 200) {
        warnx("failed to fetch directory at %s", a->directory);
        acme_error(a);
        return false;
    } else if (acme_error(a))
        return false;

    a->dir = a->json;
    a->json = NULL;

    if (a->profile) {
        const json_value_t *meta = json_find(a->dir, "meta");
        const json_value_t *profiles  = json_find(meta, "profiles");
        if (!profiles) {
            warnx("server does not support profiles");
            return false;
        }
        if (!json_find_string(profiles, a->profile)) {
            warnx("profile must be a supported one:");
            json_dump(stderr, profiles);
            return false;
        }
    }

    return true;
}

char *eab_encode(acme_t *a, const char *url)
{
    char *protected = NULL;
    char *payload = NULL;
    char *jws = NULL;

    protected = jws_protected_eab(a->eab_bits, a->eab_keyid, url);
    if (!protected) {
        warnx("eab_encode: jws_protected_eab failed");
        goto out;
    }

    payload = jws_jwk(a->key, NULL, NULL);
    if (!payload) {
        warnx("eab_encode: jws_jwk failed");
        goto out;
    }

    jws = jws_encode_hmac(protected, payload, a->eab_bits, a->eab_key);
    if (!jws) {
        warnx("eab_encode: jws_encode_hmac failed");
        goto out;
    }

    if (g_loglevel > 2)
        warnx("eab_encode: payload=%s protected=%s jws=%s",
                payload, protected, jws);

out:
    free(protected);
    free(payload);
    return jws;
}

bool account_new(acme_t *a, bool yes)
{
    const char *url = json_find_string(a->dir, "newAccount");
    if (!url) {
        warnx("failed to find newAccount URL in directory");
        return false;
    }

    msg(1, "creating new account at %s", url);
    switch (acme_post(a, url, "{\"onlyReturnExisting\":true}")) {
        case 200:
            if (!(a->kid = find_header(a->headers, "Location")))
            {
                warnx("account exists but location not found");
                return false;
            }
            warnx("Account already exists at %s", a->kid);
            return false;

        case 400:
            if (a->json && a->type &&
                    strcasestr(a->type, "application/problem+json") &&
                    json_compare_string(a->json, "type",
                      "urn:ietf:params:acme:error:accountDoesNotExist") == 0) {
                const json_value_t *meta = json_find(a->dir, "meta");
                const char *ext = json_find_value(meta,
                        "externalAccountRequired");
                if (ext && strcasecmp(ext, "true") == 0 && !a->eab_key) {
                    msg(0, "this ACME server requires external credentials, "
                           "please supply them with -e KEYID:KEY[:BITS]");
                    return false;
                }
                const char *terms = json_find_string(meta, "termsOfService");
                if (terms) {
                    if (yes)
                        msg(0, "terms at %s autoaccepted (-y)", terms);
                    else {
                        char c = 0;
                        msg(0, "type 'y' to accept the terms at %s", terms);
                        if (scanf(" %c", &c) != 1 || tolower(c) != 'y') {
                            warnx("terms not agreed to, aborted");
                            return false;
                        }
                    }
                }
                char *payload = strdup("\"termsOfServiceAgreed\":true");
                if (!payload) {
                    warn("account_new: strdup failed");
                    return false;
                }
                if (a->email && strlen(a->email)) {
                    char *tmp = NULL;
                    if (asprintf(&tmp, "%s,\"contact\": [\"mailto:%s\"]",
                                payload, a->email) < 0) {
                        warnx("account_new: asprintf failed");
                        free(tmp);
                        free(payload);
                        return false;
                    }
                    free(payload);
                    payload = tmp;
                }
                if (a->eab_key) {
                    char *tmp = NULL;
                    char *eab = eab_encode(a, url);
                    if (!eab) {
                        warnx("account_new: eab_encode failed");
                        free(payload);
                        return false;
                    }
                    if (asprintf(&tmp, "%s,\"externalAccountBinding\": %s",
                                payload, eab) < 0) {
                        warnx("account_new: asprintf failed");
                        free(tmp);
                        free(eab);
                        free(payload);
                        return false;
                    }
                    free(eab);
                    free(payload);
                    payload = tmp;
                }
                int r = acme_post(a, url, "{%s}", payload);
                free(payload);
                if (r == 201) {
                    if (acme_error(a))
                        return false;
                    if (json_compare_string(a->json, "status", "valid")) {
                        const char *st = json_find_string(a->json, "status");
                        warnx("account created but status is not valid (%s)",
                                st ? st : "unknown");
                        return false;
                    }
                    if (!(a->kid = find_header(a->headers, "Location"))) {
                        warnx("account created but location not found");
                        return false;
                    }
                    msg(1, "account created at %s", a->kid);
                    return true;
                }
            }
            // intentional fallthrough
        default:
            warnx("failed to create account at %s", url);
            acme_error(a);
            return false;
    }
}

bool account_retrieve(acme_t *a)
{
    const char *url = json_find_string(a->dir, "newAccount");
    if (!url) {
        warnx("failed to find newAccount URL in directory");
        return false;
    }
    msg(1, "retrieving account at %s", url);
    switch (acme_post(a, url, "{\"onlyReturnExisting\":true}")) {
        case 200:
            if (acme_error(a))
                return false;
            break;

        case 400:
            if (a->json && a->type &&
                    strcasestr(a->type, "application/problem+json") &&
                    json_compare_string(a->json, "type",
                      "urn:ietf:params:acme:error:accountDoesNotExist") == 0) {
                warnx("no account associated with %s/key.pem found at %s. "
                        "Consider trying 'new'", a->keyprefix, url);
                return false;
            }
            // intentional fallthrough
        default:
            warnx("failed to retrieve account at %s", url);
            acme_error(a);
            return false;
    }
    const char *status = json_find_string(a->json, "status");
    if (status && strcmp(status, "valid")) {
        warnx("invalid account status (%s)", status);
        return false;
    }
    if (!(a->kid = find_header(a->headers, "Location"))) {
        warnx("account location not found");
        return false;
    }
    msg(1, "account location: %s", a->kid);
    a->account = a->json;
    a->json = NULL;
    return true;
}

bool account_update(acme_t *a)
{
    bool email_update = false;
    const json_value_t *contacts = json_find(a->account, "contact");
    if (contacts && contacts->type != JSON_ARRAY) {
        warnx("failed to parse account contacts");
        return false;
    }
    if (a->email && strlen(a->email) > 0) {
        if (!contacts || contacts->v.array.size == 0)
            email_update = true;
        else for (size_t i=0; i<contacts->v.array.size; i++) {
            if (contacts->v.array.values[i].type != JSON_STRING ||
                    strcasestr(contacts->v.array.values[i].v.value,
                        "mailto:") != contacts->v.array.values[i].v.value) {
                warnx("failed to parse account contacts");
                return false;
            }
            if (strcasecmp(contacts->v.array.values[i].v.value
                        + strlen("mailto:"), a->email))
                email_update = true;
        }
    }
    else if (contacts && contacts->v.array.size > 0)
        email_update = true;
    if (email_update) {
        int ret = 0;
        if (a->email && strlen(a->email) > 0) {
            msg(1, "updating account email to %s at %s", a->email, a->kid);
            ret = acme_post(a, a->kid, "{\"contact\": [\"mailto:%s\"]}",
                    a->email);
        } else {
            msg(1, "removing account email at %s", a->kid);
            ret = acme_post(a, a->kid, "{\"contact\": []}");
        }
        if (ret != 200) {
            warnx("failed to update account email at %s", a->kid);
            acme_error(a);
            return false;
        } else if (acme_error(a))
            return false;
        msg(1, "account at %s updated", a->kid);
    }
    else
        msg(1, "email is already up to date for account at %s", a->kid);
    return true;
}

bool account_keychange(acme_t *a, bool never, keytype_t type, int bits)
{
    bool success = false;
    privkey_t newkey = NULL;
    char *newkeyfile = NULL;
    char *keyfile = NULL;
    char *bakfile = NULL;
    char *protected = NULL;
    char *payload = NULL;
    char *jwk = NULL;
    char *jws = NULL;
    const char *url = json_find_string(a->dir, "keyChange");
    if (!url) {
        warnx("account_keychange: failed to find keyChange URL in directory");
        goto out;
    }

    if (asprintf(&keyfile, "%s/key.pem", a->keyprefix) < 0) {
        warnx("account_keychange: asprintf failed");
        keyfile = NULL;
        goto out;
    }

    if (asprintf(&bakfile, "%s/key-%llu.pem", a->keyprefix,
                (unsigned long long)time(NULL)) < 0) {
        warnx("account_keychange: asprintf failed");
        bakfile = NULL;
        goto out;
    }

    if (asprintf(&newkeyfile, "%s/newkey.pem", a->keyprefix) < 0) {
        warnx("account_keychange: asprintf failed");
        newkeyfile = NULL;
        goto out;
    }

    newkey = key_load(never ? PK_NONE : type, bits, newkeyfile);
    if (!newkey)
        goto out;

    protected = jws_protected_jwk(NULL, url, newkey);
    if (!protected) {
        warnx("account_keychange: jws_protected_jwk failed");
        goto out;
    }

    jwk = jws_jwk(a->key, NULL, NULL);
    if (!jwk) {
        warnx("account_keychange: jws_jwk failed");
        goto out;
    }

    if (asprintf(&payload, "{\"account\":\"%s\",\"oldKey\":%s}",
                a->kid, jwk) < 0) {
        warnx("account_keychange: asprintf failed");
        payload = NULL;
        goto out;
    }

    jws = jws_encode(protected, payload, newkey);
    if (!jws) {
        warnx("account_keychange: jws_encode failed");
        goto out;
    }

    if (g_loglevel > 2)
        warnx("account_keychange: url=%s payload=%s protected=%s jws=%s",
                url, payload, protected, jws);
    else if (g_loglevel > 1)
        warnx("account_keychange: url=%s payload=%s", url, payload);

    msg(1, "changing account key at %s", url);
    if (acme_post(a, url, jws) != 200) {
        warnx("failed to change account key at %s", url);
        acme_error(a);
        goto out;
    } else if (acme_error(a))
        goto out;

    msg(1, "backing up %s as %s", keyfile, bakfile);
    if (link(keyfile, bakfile) < 0)
        warn("failed to link %s to %s", bakfile, keyfile);
    else {
        msg(1, "renaming %s to %s", newkeyfile, keyfile);
        if (rename(newkeyfile, keyfile) < 0) {
            warn("failed to rename %s to %s", newkeyfile, keyfile);
            unlink(bakfile);
        } else {
            msg(1, "account key changed");
            success = true;
        }
    }
    if (!success) {
        warnx("WARNING: account key changed but %s NOT replaced by %s",
                keyfile, newkeyfile);
        goto out;
    }
out:
    if (newkey)
        privkey_deinit(newkey);
    free(newkeyfile);
    free(keyfile);
    free(bakfile);
    free(protected);
    free(payload);
    free(jwk);
    free(jws);
    return success;
}

bool account_deactivate(acme_t *a)
{
    msg(1, "deactivating account at %s", a->kid);
    if (acme_post(a, a->kid, "{\"status\": \"deactivated\"}") != 200) {
        warnx("failed to deactivate account at %s", a->kid);
        acme_error(a);
        return false;
    } else if (acme_error(a))
        return false;
    msg(1, "account at %s deactivated", a->kid);
    return true;
}

bool authorize(acme_t *a)
{
    bool success = false;
    char *thumbprint = NULL;
    json_value_t *auth = NULL;
    const json_value_t *auths = json_find(a->order, "authorizations");
    if (!auths || auths->type != JSON_ARRAY) {
        warnx("failed to parse authorizations URL");
        goto out;
    }

    thumbprint = jws_thumbprint(a->key);
    if (!thumbprint)
        goto out;

    for (size_t i=0; i<auths->v.array.size; i++) {
        if (auths->v.array.values[i].type != JSON_STRING) {
            warnx("failed to parse authorizations URL");
            goto out;
        }
        msg(1, "retrieving authorization at %s",
                auths->v.array.values[i].v.value);
        if (acme_post(a, auths->v.array.values[i].v.value, "") != 200) {
            warnx("failed to retrieve auth %s",
                    auths->v.array.values[i].v.value);
            acme_error(a);
            goto out;
        }
        const char *status = json_find_string(a->json, "status");
        if (status && strcmp(status, "valid") == 0)
            continue;
        if (!status || strcmp(status, "pending") != 0) {
            warnx("unexpected auth status (%s) at %s",
                status ? status : "unknown",
                auths->v.array.values[i].v.value);
            acme_error(a);
            goto out;
        }
        const json_value_t *ident = json_find(a->json, "identifier");
        const char *ident_type = json_find_string(ident, "type");
        if (!ident_type || (strcmp(ident_type, "dns") != 0 &&
                strcmp(ident_type, "ip") != 0)) {
            warnx("no valid identifier in auth %s",
                    auths->v.array.values[i].v.value);
            goto out;
        }
        const char *ident_value = json_find_string(ident, "value");
        if (!ident_value || strlen(ident_value) <= 0) {
            warnx("no valid identifier in auth %s",
                    auths->v.array.values[i].v.value);
            goto out;
        }
        const json_value_t *chlgs = json_find(a->json, "challenges");
        if (!chlgs || chlgs->type != JSON_ARRAY) {
            warnx("no challenges in auth %s",
                    auths->v.array.values[i].v.value);
            goto out;
        }
        json_free(auth);
        auth = a->json;
        a->json = NULL;

        bool chlg_done = false;
        for (size_t j=0; j<chlgs->v.array.size && !chlg_done; j++) {
            const char *status = json_find_string(
                    chlgs->v.array.values+j, "status");
            if (status && (strcmp(status, "pending") == 0
                        || strcmp(status, "processing") == 0)) {
                const char *url = json_find_string(
                        chlgs->v.array.values+j, "url");
                const char *type = json_find_string(
                        chlgs->v.array.values+j, "type");
                const char *token = json_find_string(
                        chlgs->v.array.values+j, "token");
                char *key_auth = NULL;
                if (!type || !url) {
                    warnx("failed to parse challenge");
                    goto out;
                }
                if (strcmp(type, "dns-persist-01") == 0) {
                    const json_value_t *idns = json_find(
                            chlgs->v.array.values+j, "issuer-domain-names");
                    if (!idns || idns->type != JSON_ARRAY ||
                            idns->v.array.size < 1 ||
                            idns->v.array.size > 10 ||
                            idns->v.array.values[0].type != JSON_STRING ||
                            idns->v.array.values[0].v.value == NULL ||
                            strlen(idns->v.array.values[0].v.value) > 253 ||
                            strlen(idns->v.array.values[0].v.value) == 0) {
                        warnx("failed to parse challenge");
                        goto out;
                    }
                    token = idns->v.array.values[0].v.value;
                    for (const char *t = token; *t; t++)
                        if ((!isascii(*t) || !isalnum(*t) || !islower(*t)) &&
                                    *t != '-' && *t != '.') {
                            warnx("failed to validate issuer domain name");
                            goto out;
                        }
                } else {
                    if (!token) {
                        warnx("failed to parse challenge");
                        goto out;
                    }
                    for (const char *t = token; *t; t++)
                        if (!isalnum(*t) && *t != '-' && *t != '_') {
                            warnx("failed to validate token");
                            goto out;
                        }
                }
                if (strcmp(type, "dns-01") == 0 ||
                        strcmp(type, "tls-alpn-01") == 0)
                    key_auth = sha2_base64url(256, "%s.%s", token, thumbprint);
                else if (strcmp(type, "dns-persist-01") == 0) {
                    if (asprintf(&key_auth, "\"%s; accounturi=%s\"", token,
                                a->kid) < 0)
                        key_auth = NULL;
                } else if (asprintf(&key_auth, "%s.%s", token, thumbprint) < 0)
                    key_auth = NULL;
                if (!key_auth) {
                    warnx("failed to generate authorization key");
                    goto out;
                }
                if (a->hook && strlen(a->hook) > 0) {
                    msg(2, "type=%s", type);
                    msg(2, "ident=%s", ident_value);
                    msg(2, "token=%s", token);
                    msg(2, "key_auth=%s", key_auth);
                    msg(1, "running %s %s %s %s %s %s", a->hook, "begin",
                            type, ident_value, token, key_auth);
                    int r = hook_run(a->hook, "begin", type, ident_value, token,
                            key_auth);
                    msg(2, "hook returned %d", r);
                    if (r < 0) {
                        free(key_auth);
                        goto out;
                    } else if (r > 0) {
                        msg(1, "challenge %s declined", type);
                        free(key_auth);
                        continue;
                    }
                } else {
                    char c = 0;
                    msg(0, "challenge=%s ident=%s token=%s key_auth=%s",
                        type, ident_value, token, key_auth);
                    msg(0, "type 'y' followed by a newline to accept challenge"
                            ", anything else to skip");
                    if (scanf(" %c", &c) != 1 || tolower(c) != 'y') {
                        free(key_auth);
                        continue;
                    }
                }

                msg(1, "starting challenge at %s", url);
                if (acme_post(a, url, "{}") != 200) {
                    warnx("failed to start challenge at %s", url);
                    acme_error(a);
                } else for (unsigned u = 5; !chlg_done; u *= 2) {
                    msg(1, "polling challenge status at %s", url);
                    if (acme_post(a, url, "") != 200) {
                        warnx("failed to poll challenge status at %s", url);
                        acme_error(a);
                        break;
                    }
                    const char *status = json_find_string(a->json, "status");
                    if (status && strcmp(status, "valid") == 0)
                        chlg_done = true;
                    else if (!status || (strcmp(status, "processing") != 0 &&
                            strcmp(status, "pending") != 0)) {
                        warnx("challenge %s failed with status %s",
                                url, status ? status : "unknown");
                        acme_error(a);
                        break;
                    } else if (u < 5*512) {
                        char *ra = find_header(a->headers, "Retry-After");
                        unsigned int dt = retry_after(ra, u);
                        free(ra);
                        msg(dt > 40 ? 1 : 2, "%s, waiting %u seconds",
                                status, dt);
                        sleep(dt);
                    } else {
                        warnx("timeout while polling challenge status at %s, "
                                "giving up", url);
                        break;
                    }
                }
                if (a->hook && strlen(a->hook) > 0) {
                    const char *method = chlg_done ? "done" : "failed";
                    msg(1, "running %s %s %s %s %s %s", a->hook, method,
                            type, ident_value, token, key_auth);
                    hook_run(a->hook, method, type, ident_value, token,
                            key_auth);
                }
                free(key_auth);
                if (!chlg_done)
                    goto out;
            }
        }
        if (!chlg_done) {
            warnx("no challenge completed");
            goto out;
        }
    }

    success = true;

out:
    json_free(auth);
    free(thumbprint);
    return success;
}

bool cert_issue(acme_t *a, char * const *names, const char *csr)
{
    bool success = false;
    char *orderurl = NULL;
    char *certfile = NULL;
    char *bakfile = NULL;
    char *tmpfile = NULL;
    char *cert = NULL;
    time_t t = time(NULL);
    int fd = -1;
    char *ids = identifiers(names);
    if (!ids) {
        warnx("failed to process alternate names");
        goto out;
    }

    const char *url = json_find_string(a->dir, "newOrder");
    if (!url) {
        warnx("failed to find newOrder URL in directory");
        goto out;
    }

    msg(1, "creating new order at %s", url);
    if (acme_post(a, url, "{%s%s%s%s}", a->profile ? "\"profile\": \"" : "",
                a->profile ? a->profile : "",
                a->profile ? "\", " : "", ids) != 201)
    {
        warnx("failed to create new order at %s", url);
        acme_error(a);
        goto out;
    }
    const char *status = json_find_string(a->json, "status");
    if (!status || (strcmp(status, "pending") && strcmp(status, "ready"))) {
        warnx("invalid order status (%s)", status ? status : "unknown");
        acme_error(a);
        goto out;
    }
    orderurl = find_header(a->headers, "Location");
    if (!orderurl) {
        warnx("order location not found");
        goto out;
    }
    msg(1, "order location: %s", orderurl);
    a->order = a->json;
    a->json = NULL;

    if (strcmp(status, "ready") != 0) {
        if (!authorize(a)) {
            warnx("failed to authorize order at %s", orderurl);
            goto out;
        }
        for (unsigned u = 5; true; u *= 2) {
            msg(1, "polling order status at %s", orderurl);
            if (acme_post(a, orderurl, "") != 200) {
                warnx("failed to poll order status at %s", orderurl);
                acme_error(a);
                goto out;
            }
            status = json_find_string(a->json, "status");
            if (status && strcmp(status, "ready") == 0) {
                json_free(a->order);
                a->order = a->json;
                a->json = NULL;
                break;
            }
            else if (!status || strcmp(status, "pending") != 0) {
                warnx("unexpected order status (%s) at %s",
                        status ? status : "unknown", orderurl);
                acme_error(a);
                goto out;
            } else if (u < 5*512) {
                char *ra = find_header(a->headers, "Retry-After");
                unsigned int dt = retry_after(ra, u);
                free(ra);
                msg(dt > 40 ? 1 : 2, "%s, waiting %u seconds", status, dt);
                sleep(dt);
            } else {
                warnx("timeout while polling order status at %s, giving up",
                        orderurl);
                break;
            }
        }
    }

    const char *finalize = json_find_string(a->order, "finalize");
    if (!finalize) {
        warnx("failed to find finalize URL");
        goto out;
    }

    msg(1, "finalizing order at %s", finalize);
    if (acme_post(a, finalize, "{\"csr\": \"%s\"}", csr) != 200) {
        warnx("failed to finalize order at %s", finalize);
        acme_error(a);
        goto out;
    } else if (acme_error(a))
        goto out;

    for (unsigned u = 5; true; u *= 2) {
        msg(1, "polling order status at %s", orderurl);
        if (acme_post(a, orderurl, "") != 200) {
            warnx("failed to poll order status at %s", orderurl);
            acme_error(a);
            goto out;
        }
        status = json_find_string(a->json, "status");
        if (status && strcmp(status, "valid") == 0) {
            json_free(a->order);
            a->order = a->json;
            a->json = NULL;
            break;
        } else if (!status || strcmp(status, "processing") != 0) {
            warnx("unexpected order status (%s) at %s",
                    status ? status : "unknown", orderurl);
            acme_error(a);
            goto out;
        } else if (u < 5*512) {
            char *ra = find_header(a->headers, "Retry-After");
            unsigned int dt = retry_after(ra, u);
            free(ra);
            msg(dt > 40 ? 1 : 2, "%s, waiting %u seconds", status, dt);
            sleep(dt);
        } else {
            warnx("timeout while polling order status at %s, giving up",
                    orderurl);
            break;
        }
    }

    const char *certurl = json_find_string(a->order, "certificate");
    if (!certurl) {
        warnx("failed to parse certificate url");
        goto out;
    }

    msg(1, "retrieving certificate at %s", certurl);
    if (acme_post(a, certurl, "") != 200) {
        warnx("failed to retrieve certificate at %s", certurl);
        acme_error(a);
        goto out;
    } else if (acme_error(a)) {
        goto out;
    }
    cert = a->body;
    a->body = NULL;

    if (a->alt_n) {
        const char *regex = "^Link:[ \t]*<(.*)>[ \t]*.*;[ \t]*"
            "rel[ \t]*=[ \t]*\"?alternate(\"|[ \t]*;).*\r\n";
        regex_t reg;
        if (regcomp(&reg, regex, REG_EXTENDED | REG_ICASE | REG_NEWLINE)) {
            warnx("cert_issue: regcomp failed");
            goto out;
        } else {
            size_t i;
            regmatch_t m[2];
            char *alt_cert = NULL;
            char *h = NULL;
            char *headers = strdup(a->headers);
            if (!headers) {
                warn("cert_issue: strdup failed");
                goto out;
            }
            a->headers = NULL;
            h = headers;
            for (i = 0; i < a->alt_n && regexec(&reg, h, 2, m, 0) == 0; i++) {
                if (a->alt_fp_len > 0 || i == a->alt_n - 1) {
                    char *alturl = strndup(h + m[1].rm_so,
                            m[1].rm_eo - m[1].rm_so);
                    if (!alturl) {
                        warn("cert_issue: strndup failed");
                        break;
                    }
                    msg(1, "retrieving alternate certificate at %s", alturl);
                    if (acme_post(a, alturl, "") != 200) {
                        warnx("failed to retrieve alternate certificate at %s",
                                alturl);
                        acme_error(a);
                        free(alturl);
                        break;
                    }
                    free(alturl);
                    if (cert_match(a->body, a->alt_fp, a->alt_fp_len)) {
                        alt_cert = a->body;
                        a->body = NULL;
                        break;
                    }
                }
                h += m[1].rm_eo;
            }
            free(headers);
            regfree(&reg);
            if (alt_cert) {
                free(cert);
                cert = alt_cert;
            } else
                warnx("no matching alternate certificate found, "
                        "falling back to default");
        }
    }

    if (asprintf(&certfile, "%scert.pem", a->certprefix) < 0) {
        certfile = NULL;
        warnx("cert_issue: asprintf failed");
        goto out;
    }

    if (asprintf(&tmpfile, "%scert.pem.tmp", a->certprefix) < 0) {
        tmpfile = NULL;
        warnx("cert_issue: asprintf failed");
        goto out;
    }

    if (asprintf(&bakfile, "%scert-%llu.pem", a->certprefix,
                (unsigned long long)t) < 0) {
        bakfile = NULL;
        warnx("cert_issue: asprintf failed");
        goto out;
    }

    msg(1, "saving certificate to %s", tmpfile);
    fd = open(tmpfile, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IRGRP|S_IROTH);
    if (fd < 0) {
        warn("failed to create %s", tmpfile);
        goto out;
    }

    if (write(fd, cert, strlen(cert)) != (ssize_t)strlen(cert)) {
        warn("failed to write to %s", tmpfile);
        goto out;
    }

    if (close(fd) < 0) {
        warn("failed to close %s", tmpfile);
        goto out;
    } else
        fd = -1;

    if (link(certfile, bakfile) < 0) {
        if (errno != ENOENT) {
            warn("failed to link %s to %s", bakfile, certfile);
            goto out;
        }
    } else
        msg(1, "backed up %s as %s", certfile, bakfile);

    msg(1, "renaming %s to %s", tmpfile, certfile);
    if (rename(tmpfile, certfile) < 0) {
        warn("failed to rename %s to %s", tmpfile, certfile);
        unlink(bakfile);
        goto out;
    }

    success = true;
out:
    if (fd >= 0)
        close(fd);
    free(bakfile);
    free(tmpfile);
    free(certfile);
    free(ids);
    free(orderurl);
    free(cert);
    return success;
}

bool cert_revoke(acme_t *a, const char *certfile, int reason_code)
{
    bool success = false;
    char *certfiledup = NULL;
    char *revokedfile = NULL;
    const char *url = NULL;
    char *crt = cert_der_base64url(certfile);
    if (!crt) {
        warnx("failed to load %s", certfile);
        goto out;
    }

    url = json_find_string(a->dir, "revokeCert");
    if (!url) {
        warnx("failed to find revokeCert URL in directory");
        goto out;
    }

    msg(1, "revoking %s at %s", certfile, url);
    if (acme_post(a, url, "{\"certificate\":\"%s\",\"reason\":%d}", crt,
            reason_code) != 200) {
        warnx("failed to revoke %s at %s", certfile, url);
        acme_error(a);
        goto out;
    } else if (acme_error(a))
        goto out;

    msg(1, "revoked %s", certfile);
    certfiledup = strdup(certfile);
    if (!certfiledup) {
        warnx("cert_revoke: strdup failed");
        certfiledup = NULL;
        goto out;
    }
    if (asprintf(&revokedfile, "%s/revoked-%llu.pem", dirname(certfiledup),
                (unsigned long long)time(NULL)) < 0) {
        warnx("cert_revoke: asprintf failed");
        revokedfile = NULL;
        goto out;
    }
    msg(1, "renaming %s to %s", certfile, revokedfile);
    if (rename(certfile, revokedfile) < 0)
        warn("failed to rename %s to %s", certfile, revokedfile);

    success = true;
out:
    free(crt);
    free(revokedfile);
    free(certfiledup);
    return success;
}

bool validate_identifier_str(const char *s)
{
    int dots = 0;
    size_t len = 0;
    if (is_ip(s, 0, 0))
        return true;
    for (size_t j = 0; j < strlen(s); j++) {
        switch (s[j]) {
            case '.':
                if (j == 0) {
                    warnx("'.' not allowed at beginning in %s", s);
                    return false;
                }
                dots++;
                // intentional fallthrough
            case '_':
            case '-':
                len++;
                continue;
            case '*':
                if (j != 0 || s[1] != '.') {
                    warnx("'*.' only allowed at beginning in %s", s);
                    return false;
                }
                break;
            default:
                if (!isupper(s[j]) && !islower(s[j]) && !isdigit(s[j])) {
                    warnx("invalid character '%c' in %s", s[j], s);
                    return false;
                }
                len++;
        }
    }
    if (len == 0) {
        warnx("empty identifier is not allowed");
        return false;
    }
    if (dots == 0) {
        warnx("identifier '%s' has no dots", s);
        return false;
    }
    return true;
}

bool eab_parse(acme_t *a, char *eab)
{
    regmatch_t m[5];
    regex_t reg;
    if (regcomp(&reg, "^([^:]+):([-_A-Za-z0-9]+)(:([0-9]+))?$",
                REG_EXTENDED | REG_NEWLINE)) {
        warnx("eab_parse: regcomp failed");
        return false;
    }

    int r = regexec(&reg, eab, sizeof(m)/sizeof(m[0]), m, 0);
    regfree(&reg);

    if (r) {
        warnx("EAB credentials must be specified as 'KEYID:KEY[:BITS]'. "
                "KEY must be base64url encoded, "
                "BITS must be 256 (default), 384 or 512");
        return false;
    }

    eab[m[4].rm_eo] = 0;
    if (strcmp(eab + m[4].rm_so, "512"))
        a->eab_bits = 512;
    else if (strcmp(eab + m[4].rm_so, "384"))
        a->eab_bits = 384;
    else if (strcmp(eab + m[4].rm_so, "256") || strlen(eab + m[4].rm_so) == 0)
        a->eab_bits = 256;
    else {
        warnx("EAB credentials BITS must be 256 (default), 384 or 512");
        return false;
    }

    eab[m[1].rm_eo] = 0;
    a->eab_keyid = eab + m[1].rm_so;

    eab[m[2].rm_eo] = 0;
    a->eab_key = eab + m[2].rm_so;

    return true;
}

bool alt_parse(acme_t *a, char *alt)
{
    char *endptr;
    long l = strtol(alt, &endptr, 0);
    if (*endptr == 0 && l > 0 && (unsigned long)l < SIZE_MAX) {
        a->alt_n = l;
        return true;
    }

    size_t len = 0;
    char *tok = strtok(alt, ":");
    while (tok && len < sizeof(a->alt_fp)) {
        if (strlen(tok) != 2 || !isxdigit(tok[0]) || !isxdigit(tok[1]))
            break;
        a->alt_fp[len++] = strtol(tok, NULL, 16);
        tok = strtok(NULL, ":");
    }
    if (!tok && len > 1) {
        a->alt_fp_len = len;
        a->alt_n = UINT_MAX;
        return true;
    }

    warnx("-l requires a positive argument or a SHA256 fingerprint");
    return false;
}

void usage(const char *progname)
{
    fprintf(stderr,
        "usage: %s [-a|--acme-url URL] [-b|--bits BITS] [-c|--confdir DIR]\n"
        "\t[-d|--days DAYS] [-e|--eab KEYID:KEY[:BITS]] [-f|--force]\n"
        "\t[-h|--hook PROG] [-i|--no-ari] [-k|--rotate-key]\n"
        "\t[-l|--alternate [N | SHA256]] [-m|--must-staple]\n"
        "\t[-n|--never-create] [-o|--no-ocsp] [-p|--profile profile]\n"
        "\t[-r|--reason CODE] [-s|--staging] [-t|--type RSA | EC]\n"
        "\t[-v|--verbose ...] [-V|--version] [-y|--yes] [-?|--help]\n"
        "\tnew [EMAIL] | update [EMAIL] | deactivate | newkey |\n"
        "\tissue IDENTIFIER [ALTNAME ...] | issue CSRFILE |\n"
        "\tcheck IDENTIFIER [ALTNAME ...] | check CSRFILE |\n"
        "\trevoke CERTFILE [CERTKEYFILE]\n", progname);
}

void version(const char *progname)
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
            progname, progname, progname);
}

int main(int argc, char **argv)
{
    static struct option options[] = {
        {"acme-url",     required_argument, NULL, 'a'},
        {"bits",         required_argument, NULL, 'b'},
        {"confdir",      required_argument, NULL, 'c'},
        {"days",         required_argument, NULL, 'd'},
        {"eab",          required_argument, NULL, 'e'},
        {"force",        no_argument,       NULL, 'f'},
        {"help",         no_argument,       NULL, '?'},
        {"hook",         required_argument, NULL, 'h'},
        {"no-ari",       no_argument,       NULL, 'i'},
        {"rotate-key",   no_argument,       NULL, 'k'},
        {"alternate",    required_argument, NULL, 'l'},
        {"must-staple",  no_argument,       NULL, 'm'},
        {"never-create", no_argument,       NULL, 'n'},
        {"no-ocsp",      no_argument,       NULL, 'o'},
        {"profile",      required_argument, NULL, 'p'},
        {"reason",       required_argument, NULL, 'r'},
        {"staging",      no_argument,       NULL, 's'},
        {"type",         required_argument, NULL, 't'},
        {"verbose",      no_argument,       NULL, 'v'},
        {"version",      no_argument,       NULL, 'V'},
        {"yes",          no_argument,       NULL, 'y'},
        {NULL,           0,                 NULL, 0}
    };

    int ret = 2;
    bool never = false;
    bool force = false;
    bool yes = false;
    bool staging = false;
    bool custom_directory = false;
    bool status_req = false;
    bool status_check = true;
    bool ari_check = true;
    bool rotate = false;
    int days = 30;
    int bits = 0;
    int reason = 0;
    keytype_t type = PK_RSA;
    const char *ident = NULL;
    char *filename = NULL;
    char *csr = NULL;
    char **names = NULL;
    const char *confdir = DEFAULT_CONFDIR;
    char *keyprefix = NULL;
    char *keyfile = NULL;
    char *newkeyfile = NULL;
    char *bakkeyfile = NULL;
    privkey_t key = NULL;
    acme_t a;
    memset(&a, 0, sizeof(a));
    a.directory = PRODUCTION_URL;

    if (argc < 2) {
        usage(basename(argv[0]));
        return ret;
    }

    srand(getpid() ^ time(NULL));

#if LIBCURL_VERSION_NUM < 0x072600
#error libcurl version 7.38.0 or later is required
#endif
    const curl_version_info_data *cvid = curl_version_info(CURLVERSION_NOW);
    if (!cvid || cvid->version_num < 0x072600) {
        warnx("libcurl version 7.38.0 or later is required");
        return ret;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        warnx("failed to initialize libcurl");
        return ret;
    }

    if (!crypto_init()) {
        warnx("failed to initialize crypto library");
        curl_global_cleanup();
        return ret;
    }

    while (1) {
        char *endptr;
        int option_index;
        int c = getopt_long(argc, argv, "a:b:c:d:e:f?h:ikl:mnop:r:st:vVy",
                options, &option_index);
        if (c == -1) break;
        switch (c) {
            case 'a':
                if (staging) {
                    warnx("-a,--acme-url is incompatible with -s,--staging");
                    goto out;
                }
                custom_directory = true;
                a.directory = optarg;
                break;

            case 'b':
                bits = strtol(optarg, &endptr, 10);
                if (*endptr != 0 || bits <= 0) {
                    warnx("BITS must be a positive integer");
                    goto out;
                }
                break;

            case 'c':
                confdir = optarg;
                break;

            case 'd':
                days = strtol(optarg, &endptr, 10);
                if (*endptr != 0 || days <= 0) {
                    warnx("DAYS must be a positive integer");
                    goto out;
                }
                break;

            case 'e':
                if (!eab_parse(&a, optarg))
                    goto out;
                break;

            case 'f':
                force = true;
                break;

            case 'h':
                a.hook = optarg;
                break;

            case 'i':
                ari_check = false;
                break;

            case 'k':
                rotate = true;
                break;

            case 'l':
                if (!alt_parse(&a, optarg))
                    goto out;
                break;

            case 'm':
                status_req = true;
                break;

            case 'n':
                never = true;
                break;

            case 'o':
                status_check = false;
                break;

            case 'p':
                a.profile = optarg;
                break;

            case 'v':
                g_loglevel++;
                break;

            case 'r':
                reason = strtol(optarg, &endptr, 0);
                if (*endptr != 0 || reason < 0) {
                    warnx("CODE must be a non-negative integer");
                    goto out;
                }
                break;

            case 's':
                if (custom_directory) {
                    warnx("-s,--staging is incompatible with -a,--acme-url");
                    goto out;
                }
                staging = true;
                a.directory = STAGING_URL;
                break;

            case 't':
                if (strcasecmp(optarg, "RSA") == 0)
                    type = PK_RSA;
                else if (strcasecmp(optarg, "EC") == 0)
                    type = PK_EC;
                else {
                    warnx("type must be either RSA or EC");
                    goto out;
                }
                break;

             case 'V':
                version(basename(argv[0]));
                goto out;
                break;

            case 'y':
                yes = true;
                break;

            default:
                usage(basename(argv[0]));
                goto out;
        }
    }

    switch (type) {
        case PK_RSA:
            if (bits == 0)
                bits = 2048;
            else if (bits < 2048 || bits > 8192) {
                warnx("BITS must be between 2048 and 8192 for RSA keys");
                goto out;
            }
            else if (bits & 7) {
                warnx("BITS must be a multiple of 8 for RSA keys");
                goto out;
            }
            break;

        case PK_EC:
            switch (bits) {
                case 0:
                    bits = 256;
                    break;

                case 256:
                case 384:
                    break;

                default:
                    warnx("BITS must be either 256 or 384 for EC keys");
                    goto out;
            }
            break;

        default:
            warnx("key type must be either RSA or EC");
            goto out;
    }

    if (optind == argc) {
        usage(basename(argv[0]));
        goto out;
    }

    const char *action = argv[optind++];
    if (strcmp(action, "new") == 0 || strcmp(action, "update") == 0) {
        if (optind < argc)
            a.email = argv[optind++];
        if (optind < argc) {
            usage(basename(argv[0]));
            goto out;
        }
    } else if (strcmp(action, "newkey") == 0
            || strcmp(action, "deactivate") == 0) {
        if (optind < argc) {
            usage(basename(argv[0]));
            goto out;
        }
    } else if (strcmp(action, "issue") == 0 || strcmp(action, "check") == 0) {
        if (optind == argc) {
            usage(basename(argv[0]));
            goto out;
        }
        struct stat st;
        if (stat(argv[optind], &st)) {
            if (errno != ENOENT && errno != EACCES) {
                warn("failed to stat %s", argv[optind]);
                goto out;
            }
        } else if (S_ISREG(st.st_mode)) {
            filename = strdup(argv[optind++]);
            if (!filename) {
                warn("strdup failed");
                goto out;
            }
            if (optind < argc) {
                usage(basename(argv[0]));
                goto out;
            }
        }
        if (!filename) {
            int i = 0;
            for (i = 0; argv[optind + i]; i++)
                if (!validate_identifier_str(argv[optind + i]))
                    goto out;
            if (i == 0) {
                usage(basename(argv[0]));
                goto out;
            }
            names = calloc(i + 1, sizeof(*names));
            if (!names) {
                warn("calloc failed");
                goto out;
            }
            while (i--) {
                names[i] = strdup(argv[optind + i]);
                if (!names[i]) {
                    warn("strdup failed");
                    goto out;
                }
            }
            ident = names[0];
            if (ident[0] == '*' && ident[1] == '.')
                ident += 2;
        }
    } else if (strcmp(action, "revoke") == 0) {
        if (optind == argc) {
            usage(basename(argv[0]));
            goto out;
        }
        filename = strdup(argv[optind++]);
        if (!filename) {
            warn("strdup failed");
            goto out;
        }
        if (access(filename, R_OK)) {
            warn("failed to read %s", filename);
            goto out;
        }
        if (optind < argc) {
            const char *keyfile = argv[optind++];
            a.key = key_load(PK_NONE, bits, keyfile);
            if (!a.key)
                goto out;
        }
        if (optind < argc) {
            usage(basename(argv[0]));
            goto out;
        }
    } else {
        usage(basename(argv[0]));
        goto out;
    }

    time_t now = time(NULL);
    char buf[0x100];
    setlocale(LC_TIME, "C");
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %z", localtime(&now));
    if (strstr(PACKAGE_VERSION, "-dev-")) {
        warnx("development version " PACKAGE_VERSION " starting on %s", buf);
        warnx("please use for testing only; releases are available at "
                "https://github.com/ndilieto/uacme/tree/upstream/latest");
    } else
        msg(1, "version " PACKAGE_VERSION " starting on %s", buf);

    snprintf(buf, sizeof(buf), "%d", g_loglevel);
    setenv("UACME_VERBOSE", buf, 1);
    setenv("UACME_CONFDIR", confdir, 1);

    if (a.hook && access(a.hook, R_OK | X_OK) < 0) {
        warn("%s", a.hook);
        goto out;
    }

    if (!a.key) {
        if (asprintf(&a.keyprefix, "%s/private", confdir) < 0) {
            a.keyprefix = NULL;
            warnx("asprintf failed");
            goto out;
        }

        if (ident) {
            if (asprintf(&keyprefix, "%s/private/%s", confdir, ident) < 0) {
                keyprefix = NULL;
                warnx("asprintf failed");
                goto out;
            }

            if (asprintf(&a.certprefix, "%s/%s/", confdir, ident) < 0) {
                a.certprefix = NULL;
                warnx("asprintf failed");
                goto out;
            }
        }

        bool is_new = strcmp(action, "new") == 0;
        if (!check_or_mkdir(is_new && !never, confdir,
                    S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH))
            goto out;

        if (!check_or_mkdir(is_new && !never, a.keyprefix, S_IRWXU))
            goto out;

        a.key = key_load((!is_new || never) ? PK_NONE : type, bits,
                "%s/key.pem", a.keyprefix);
        if (!a.key)
            goto out;
    }

    if (strcmp(action, "new") == 0) {
        if (acme_bootstrap(&a) && account_new(&a, yes))
            ret = 0;
    } else if (strcmp(action, "update") == 0) {
        if (acme_bootstrap(&a) && account_retrieve(&a) && account_update(&a))
            ret = 0;
    } else if (strcmp(action, "newkey") == 0) {
        if (acme_bootstrap(&a) && account_retrieve(&a)
                && account_keychange(&a, never, type, bits))
            ret = 0;
    } else if (strcmp(action, "deactivate") == 0) {
        if (acme_bootstrap(&a) && account_retrieve(&a)
                && account_deactivate(&a))
            ret = 0;
    } else if (strcmp(action, "revoke") == 0) {
        if (acme_bootstrap(&a) && (!a.keyprefix || account_retrieve(&a)) &&
                cert_revoke(&a, filename, reason))
            ret = 0;
    } else if (strcmp(action, "issue") == 0 || strcmp(action, "check") == 0) {
        bool check = *action == 'c';
        if (filename) {
            int len = strlen(filename);
            char *dot = strrchr(filename, '.');

            if (dot)
                len = dot - filename;

            if (asprintf(&a.certprefix, "%.*s-", len, filename) < 0) {
                a.certprefix = NULL;
                warnx("asprintf failed");
                goto out;
            }

            csr = csr_load(filename, &names);
            if (!csr)
                goto out;

            if (status_req)
                warnx("-m, --must-staple is ignored with a CSR");

            if (rotate)
                warnx("-k, --rotate-key is ignored with a CSR");
        } else {
            if (rotate && never) {
                warnx("-k, --rotate-key and -n, --never-create "
                        "are incompatible");
                goto out;
            }

            if (rotate && check) {
                warnx("-k, --rotate-key is ignored with check");
                rotate = false;
            }

            if (!check_or_mkdir(!(never || check), keyprefix, S_IRWXU))
                goto out;

            if (!check_or_mkdir(!(never || check), a.certprefix,
                        S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH))
                goto out;

            if (asprintf(&keyfile, "%s/key.pem", keyprefix) < 0) {
                keyfile = NULL;
                warnx("asprintf failed");
                goto out;
            }

            if (rotate) {
                if (asprintf(&newkeyfile, "%s/newkey.pem", keyprefix) < 0) {
                    newkeyfile = NULL;
                    warnx("asprintf failed");
                    goto out;
                }
                if (asprintf(&bakkeyfile, "%s/key-%llu.pem", keyprefix,
                            (unsigned long long)time(NULL)) < 0) {
                    bakkeyfile = NULL;
                    warnx("asprintf failed");
                    goto out;
                }
            }

            key = key_load((never || check) ? PK_NONE : type, bits,
                    newkeyfile ? newkeyfile : keyfile);
            if (!key)
                goto out;
        }

        free(filename);
        if (asprintf(&filename, "%scert.pem", a.certprefix) < 0) {
            filename = NULL;
            warnx("asprintf failed");
            goto out;
        }

        if (!acme_bootstrap(&a))
            goto out;
        const char *ari_url = ari_check ?
            json_find_string(a.dir, "renewalInfo") : NULL;

        msg(1, "checking existence and expiration of %s", filename);
        if (cert_valid(filename, names, ari_url, days, status_check)) {
            if (check) {
                msg(1, "%s is valid", filename);
                ret = 1;
                goto out;
            } else if (force)
                msg(1, "forcing reissue of %s", filename);
            else {
                msg(1, "skipping %s", filename);
                ret = 1;
                goto out;
            }
        } else if (check) {
            ret = 0;
            goto out;
        }

        if (!csr) {
            msg(1, "generating certificate request");
            csr = csr_gen(names, status_req, a.profile != NULL, key);
            if (!csr) {
                warnx("failed to generate certificate request");
                goto out;
            }
        }

        if (account_retrieve(&a) && cert_issue(&a, names, csr)) {
            if (newkeyfile) {
                if (link(keyfile, bakkeyfile) < 0) {
                    if (errno != ENOENT)
                        warn("failed to link %s to %s", bakkeyfile, keyfile);
                } else
                    msg(1, "backed up %s as %s", keyfile, bakkeyfile);
                msg(1, "renaming %s to %s", newkeyfile, keyfile);
                if (rename(newkeyfile, keyfile) < 0) {
                    warn("failed to rename %s to %s", newkeyfile, keyfile);
                    unlink(bakkeyfile);
                    free(newkeyfile);
                    newkeyfile = NULL;
                    goto out;
                }
            }
            ret = 0;
        }
    }

out:
    json_free(a.json);
    json_free(a.account);
    json_free(a.dir);
    json_free(a.order);
    free(a.nonce);
    free(a.kid);
    free(a.headers);
    free(a.body);
    free(a.type);
    free(a.keyprefix);
    free(a.certprefix);
    if (a.key)
        privkey_deinit(a.key);
    if (key)
        privkey_deinit(key);
    free(keyprefix);
    free(keyfile);
    if (newkeyfile)
        unlink(newkeyfile);
    free(newkeyfile);
    free(bakkeyfile);
    free(csr);
    free(filename);
    for (int i = 0; names && names[i]; i++)
        free(names[i]);
    free(names);
    crypto_deinit();
    curl_global_cleanup();
    exit(ret);
}

