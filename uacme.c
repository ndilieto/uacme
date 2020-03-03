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

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <locale.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base64.h"
#include "curlwrap.h"
#include "crypto.h"
#include "json.h"
#include "msg.h"

#define PRODUCTION_URL "https://acme-v02.api.letsencrypt.org/directory"
#define STAGING_URL "https://acme-staging-v02.api.letsencrypt.org/directory"
#define DEFAULT_CONFDIR "/etc/ssl/uacme"

typedef struct acme
{
    privkey_t key;
    privkey_t ckey;
    json_value_t *json;
    json_value_t *account;
    json_value_t *dir;
    json_value_t *order;
    char *nonce;
    char *kid;
    char *headers;
    char *body;
    char *type;
    const char *directory;
    const char *hook;
    const char *email;
    const char *ident;
    const char * const *names;
    const char *confdir;
    char *keydir;
    char *ckeydir;
    char *certdir;
} acme_t;

char *find_header(const char *headers, const char *name)
{
    char *regex = NULL;
    if (asprintf(&regex, "^%s:[ \t]*(.*)\r\n", name) < 0)
    {
        warnx("find_header: asprintf failed");
        return NULL;
    }
    char *ret = NULL;
    regex_t reg;
    if (regcomp(&reg, regex, REG_EXTENDED | REG_ICASE | REG_NEWLINE))
    {
        warnx("find_header: regcomp failed");
    }
    else
    {
        regmatch_t m[2];
        if (regexec(&reg, headers, 2, m, 0) == 0)
        {
            ret = strndup(headers + m[1].rm_so, m[1].rm_eo - m[1].rm_so);
            if (!ret)
            {
                warn("find_header: strndup failed");
            }
        }
    }
    free(regex);
    regfree(&reg);
    return ret;
}

int acme_get(acme_t *a, const char *url)
{
    int ret = 0;

    json_free(a->json);
    a->json = NULL;
    free(a->headers);
    a->headers = NULL;
    free(a->body);
    a->body = NULL;
    free(a->type);
    a->type = NULL;

    if (!url)
    {
        warnx("acme_get: invalid URL");
        goto out;
    }
    if (g_loglevel > 1)
    {
        warnx("acme_get: url=%s", url);
    }
    curldata_t *c = curl_get(url);
    if (!c)
    {
        warnx("acme_get: curl_get failed");
        goto out;
    }
    free(a->nonce);
    a->nonce = find_header(c->headers, "Replay-Nonce");
    a->type = find_header(c->headers, "Content-Type");
    if (a->type && strstr(a->type, "json"))
    {
        a->json = json_parse(c->body, c->body_len);
    }
    a->headers = c->headers;
    c->headers = NULL;
    a->body = c->body;
    c->body = NULL;
    ret = c->code;
    curldata_free(c);
out:
    if (g_loglevel > 2)
    {
        if (a->headers)
        {
            warnx("acme_get: HTTP headers\n%s", a->headers);
        }
        if (a->body)
        {
            warnx("acme_get: HTTP body\n%s", a->body);
        }
    }
    if (g_loglevel > 1)
    {
        if (a->json)
        {
            warnx("acme_get: return code %d, json=", ret);
            json_dump(stderr, a->json);
        }
        else
        {
            warnx("acme_get: return code %d", ret);
        }
    }
    if (!a->headers) a->headers = strdup("");
    if (!a->body) a->body = strdup("");
    if (!a->type) a->type = strdup("");
    return ret;
}

int acme_post(acme_t *a, const char *url, const char *format, ...)
{
    int ret = 0;
    char *payload = NULL;
    char *protected = NULL;
    char *jws = NULL;

    if (!url)
    {
        warnx("acme_post: invalid URL");
        return 0;
    }

    if (!a->nonce)
    {
        warnx("acme_post: need a nonce first");
        return 0;
    }

    va_list ap;
    va_start(ap, format);
    if (vasprintf(&payload, format, ap) < 0)
    {
        payload = NULL;
    }
    va_end(ap);
    if (!payload)
    {
        warnx("acme_post: vasprintf failed");
        return 0;
    }

    for (int retry = 0; a->nonce && retry < 3; retry++)
    {
        if (retry > 0)
        {
            msg(1, "acme_post: server rejected nonce, retrying");
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
        if (!protected)
        {
            warnx("acme_post: jws_protected_xxx failed");
            goto out;
        }
        jws = jws_encode(protected, payload, a->key);
        if (!jws)
        {
            warnx("acme_post: jws_encode failed");
            goto out;
        }
        if (g_loglevel > 2)
        {
            warnx("acme_post: url=%s payload=%s "
                    "protected=%s jws=%s",
                    url, payload, protected, jws);
        }
        else if (g_loglevel > 1)
        {
            warnx("acme_post: url=%s payload=%s", url, payload);
        }
        curldata_t *c = curl_post(url, jws);
        if (!c)
        {
            warnx("acme_post: curl_post failed");
            goto out;
        }
        free(a->nonce);
        a->nonce = find_header(c->headers, "Replay-Nonce");
        a->type = find_header(c->headers, "Content-Type");
        if (a->type && strstr(a->type, "json"))
        {
            a->json = json_parse(c->body, c->body_len);
        }
        a->headers = c->headers;
        c->headers = NULL;
        a->body = c->body;
        c->body = NULL;
        ret = c->code;
        curldata_free(c);
        if (g_loglevel > 2)
        {
            if (a->headers)
            {
                warnx("acme_post: HTTP headers:\n%s", a->headers);
            }
            if (a->body)
            {
                warnx("acme_post: HTTP body:\n%s", a->body);
            }
        }
        if (g_loglevel > 1)
        {
            if (a->json)
            {
                warnx("acme_post: return code %d, json=", ret);
                json_dump(stderr, a->json);
            }
            else
            {
                warnx("acme_post: return code %d", ret);
            }
        }
        if (ret != 400 || !a->type || !a->nonce || !a->json ||
                0 != strcasecmp(a->type, "application/problem+json") ||
                0 != json_compare_string(a->json, "type",
                    "urn:ietf:params:acme:error:badNonce"))
        {
            break;
        }
    }
out:
    free(payload);
    free(protected);
    free(jws);
    if (!a->headers) a->headers = strdup("");
    if (!a->body) a->body = strdup("");
    if (!a->type) a->type = strdup("");
    return ret;
}

int hook_run(const char *prog, const char *method, const char *type,
        const char *ident, const char *token, const char *auth)
{
    int ret = -1;
    pid_t pid = fork();
    if (pid < 0)
    {
        warn("hook_run: fork failed");
    }
    else if (pid > 0) // parent
    {
        int status;
        if (waitpid(pid, &status, 0) < 0)
        {
            warn("hook_run: waitpid failed");
        }
        else if (WIFEXITED(status))
        {
            ret = WEXITSTATUS(status);
        }
        else
        {
            warnx("hook_run: %s terminated abnormally", prog);
        }
    }
    else // child
    {
        if (execl(prog, prog, method, type, ident, token, auth,
                    (char *)NULL) < 0)
        {
            warn("hook_run: failed to execute %s", prog);
            abort();
        }
    }
    return ret;
}

bool check_or_mkdir(bool allow_create, const char *dir, mode_t mode)
{
    if (access(dir, F_OK) < 0)
    {
        if (!allow_create)
        {
            warnx("failed to access %s", dir);
            return false;
        }
        if (mkdir(dir, mode) < 0)
        {
            warn("failed to create %s", dir);
            return false;
        }
        msg(1, "created directory %s", dir);
    }
    struct stat st;
    if (stat(dir, &st) != 0)
    {
        warn("failed to stat %s", dir);
        return false;
    }
    if (!S_ISDIR(st.st_mode))
    {
        warnx("%s is not a directory", dir);
        return false;
    }
    return true;
}

char *identifiers(const char * const *names)
{
    char *ids = NULL;
    char *tmp = NULL;
    if (asprintf(&tmp, "{\"identifiers\":[") < 0)
    {
        warnx("identifiers: asprintf failed");
        return NULL;
    }
    while (names && *names)
    {
        if (asprintf(&ids, "%s{\"type\":\"%s\",\"value\":\"%s\"},",
                    tmp, is_ip(*names, 0, 0) ? "ip" : "dns", *names) < 0)
        {
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
    if (asprintf(&ids, "%s]}", tmp) < 0)
    {
        warnx("identifiers: asprintf failed");
        ids = NULL;
    }
    free(tmp);
    return ids;
}

bool acme_error(acme_t *a)
{
    if (!a->json) return false;

    if (a->type && strcasecmp(a->type,
                "application/problem+json") == 0)
    {
        warnx("the server reported the following error:");
        json_dump(stderr, a->json);
        return true;
    }

    const json_value_t *e = json_find(a->json, "error");
    if (e && e->type == JSON_OBJECT)
    {
        warnx("the server reported the following error:");
        json_dump(stderr, e);
        return true;
    }

    return false;
}

bool acme_bootstrap(acme_t *a)
{
    msg(1, "fetching directory at %s", a->directory);
    if (200 != acme_get(a, a->directory))
    {
        warnx("failed to fetch directory at %s", a->directory);
        acme_error(a);
        return false;
    }
    else if (acme_error(a))
    {
        return false;
    }
    a->dir = a->json;
    a->json = NULL;

    const char *url = json_find_string(a->dir, "newNonce");
    if (!url)
    {
        warnx("failed to find newNonce URL in directory");
        return false;
    }

    msg(2, "fetching new nonce at %s", url);
    if (204 != acme_get(a, url))
    {
        warnx("failed to fetch new nonce at %s", url);
        acme_error(a);
        return false;
    }
    else if (acme_error(a))
    {
        return false;
    }
    return true;
}

bool account_new(acme_t *a, bool yes)
{
    const char *url = json_find_string(a->dir, "newAccount");
    if (!url)
    {
        warnx("failed to find newAccount URL in directory");
        return false;
    }

    msg(1, "creating new account at %s", url);
    switch (acme_post(a, url, "{\"onlyReturnExisting\":true}"))
    {
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
                    0 == strcasecmp(a->type, "application/problem+json") &&
                    0 == json_compare_string(a->json, "type",
                        "urn:ietf:params:acme:error:accountDoesNotExist"))
            {
                const json_value_t *meta = json_find(a->dir, "meta");
                const char *terms = json_find_string(meta, "termsOfService");
                if (terms)
                {
                    if (yes)
                    {
                        msg(0, "terms at %s autoaccepted (-y)", terms);
                    }
                    else
                    {
                        char c = 0;
                        msg(0, "type 'y' to accept the terms at %s", terms);
                        if (scanf(" %c", &c) != 1 || tolower(c) != 'y')
                        {
                            warnx("terms not agreed to, aborted");
                            return false;
                        }
                    }
                }
                int r = 0;
                if (a->email && strlen(a->email))
                {
                    r = acme_post(a, url, "{\"termsOfServiceAgreed\":true"
                                ",\"contact\": [\"mailto:%s\"]}", a->email);
                }
                else
                {
                    r = acme_post(a, url, "{\"termsOfServiceAgreed\":true}");
                }
                if (r == 201)
                {
                    if (acme_error(a))
                    {
                        return false;
                    }
                    if (json_compare_string(a->json, "status", "valid"))
                    {
                        const char *status = json_find_string(a->json,
                                "status");
                        warnx("account created but status is not valid (%s)",
                                status ? status : "unknown");
                        return false;
                    }
                    if (!(a->kid = find_header(a->headers, "Location")))
                    {
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
    if (!url)
    {
        warnx("failed to find newAccount URL in directory");
        return false;
    }
    msg(1, "retrieving account at %s", url);
    switch (acme_post(a, url, "{\"onlyReturnExisting\":true}"))
    {
        case 200:
            if (acme_error(a))
            {
                return false;
            }
            break;

        case 400:
            if (a->json && a->type &&
                    0 == strcasecmp(a->type, "application/problem+json") &&
                    0 == json_compare_string(a->json, "type",
                        "urn:ietf:params:acme:error:accountDoesNotExist"))
            {
                warnx("no account associated with %s/key.pem found at %s. "
                        "Consider trying 'new'", a->keydir, url);
                return false;
            }
            // intentional fallthrough
        default:
            warnx("failed to retrieve account at %s", url);
            acme_error(a);
            return false;
    }
    const char *status = json_find_string(a->json, "status");
    if (status && strcmp(status, "valid"))
    {
        warnx("invalid account status (%s)", status);
        return false;
    }
    if (!(a->kid = find_header(a->headers, "Location")))
    {
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
    if (contacts && contacts->type != JSON_ARRAY)
    {
        warnx("failed to parse account contacts");
        return false;
    }
    if (a->email && strlen(a->email) > 0)
    {
        if (!contacts || contacts->v.array.size == 0)
        {
            email_update = true;
        }
        else for (size_t i=0; i<contacts->v.array.size; i++)
        {
            if (contacts->v.array.values[i].type != JSON_STRING ||
                    contacts->v.array.values[i].v.value !=
                    strcasestr(contacts->v.array.values[i].v.value,
                        "mailto:"))
            {
                warnx("failed to parse account contacts");
                return false;
            }
            if (strcasecmp(contacts->v.array.values[i].v.value
                        + strlen("mailto:"), a->email))
            {
                email_update = true;
            }
        }
    }
    else if (contacts && contacts->v.array.size > 0)
    {
        email_update = true;
    }
    if (email_update)
    {
        int ret = 0;
        if (a->email && strlen(a->email) > 0)
        {
            msg(1, "updating account email to %s at %s", a->email, a->kid);
            ret = acme_post(a, a->kid, "{\"contact\": [\"mailto:%s\"]}",
                    a->email);
        }
        else
        {
            msg(1, "removing account email at %s", a->kid);
            ret = acme_post(a, a->kid, "{\"contact\": []}");
        }
        if (ret != 200)
        {
            warnx("failed to update account email at %s", a->kid);
            acme_error(a);
            return false;
        }
        else if (acme_error(a))
        {
            return false;
        }
        msg(1, "account at %s updated", a->kid);
    }
    else
    {
        msg(1, "email is already up to date for account at %s", a->kid);
    }
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
    if (!url)
    {
        warnx("account_keychange: failed to find keyChange URL in directory");
        goto out;
    }

    if (asprintf(&keyfile, "%s/key.pem", a->keydir) < 0)
    {
        warnx("account_keychange: asprintf failed");
        keyfile = NULL;
        goto out;
    }

    if (asprintf(&bakfile, "%s/key-%llu.pem", a->keydir,
                (unsigned long long)time(NULL)) < 0)
    {
        warnx("account_keychange: asprintf failed");
        bakfile = NULL;
        goto out;
    }

    if (asprintf(&newkeyfile, "%s/newkey.pem", a->keydir) < 0)
    {
        warnx("account_keychange: asprintf failed");
        newkeyfile = NULL;
        goto out;
    }

    newkey = key_load(never ? PK_NONE : type, bits, newkeyfile);
    if (!newkey)
    {
        goto out;
    }

    protected = jws_protected_jwk(NULL, url, newkey);
    if (!protected)
    {
        warnx("account_keychange: jws_protected_jwk failed");
        goto out;
    }

    jwk = jws_jwk(a->key, NULL, NULL);
    if (!jwk)
    {
        warnx("account_keychange: jws_jwk failed");
        goto out;
    }

    if (asprintf(&payload, "{\"account\":\"%s\",\"oldKey\":%s}",
                a->kid, jwk) < 0)
    {
        warnx("account_keychange: jws_jwk failed");
        goto out;
    }

    jws = jws_encode(protected, payload, newkey);
    if (!jws)
    {
        warnx("account_keychange: jws_encode failed");
        goto out;
    }

    if (g_loglevel > 2)
    {
        warnx("account_keychange: url=%s payload=%s protected=%s jws=%s",
                url, payload, protected, jws);
    }
    else if (g_loglevel > 1)
    {
        warnx("account_keychange: url=%s payload=%s", url, payload);
    }

    msg(1, "changing account key at %s", url);
    if (200 != acme_post(a, url, jws))
    {
        warnx("failed to change account key at %s", url);
        acme_error(a);
        goto out;
    }
    else if (acme_error(a))
    {
        goto out;
    }

    msg(1, "backing up %s as %s", keyfile, bakfile);
    if (link(keyfile, bakfile) < 0)
    {
        warn("failed to link %s to %s", bakfile, keyfile);
    }
    else
    {
        msg(1, "renaming %s to %s", newkeyfile, keyfile);
        if (rename(newkeyfile, keyfile) < 0)
        {
            warn("failed to rename %s to %s", newkeyfile, keyfile);
            unlink(bakfile);
        }
        else
        {
            msg(1, "account key changed");
            success = true;
        }
    }
    if (!success)
    {
        warnx("WARNING: account key changed but %s NOT replaced by %s",
                keyfile, newkeyfile);
        goto out;
    }
out:
    if (newkey) privkey_deinit(newkey);
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
    if (200 != acme_post(a, a->kid, "{\"status\": \"deactivated\"}"))
    {
        warnx("failed to deactivate account at %s", a->kid);
        acme_error(a);
        return false;
    }
    else if (acme_error(a))
    {
        return false;
    }
    msg(1, "account at %s deactivated", a->kid);
    return true;
}

bool authorize(acme_t *a)
{
    bool success = false;
    char *thumbprint = NULL;
    json_value_t *auth = NULL;
    const json_value_t *auths = json_find(a->order, "authorizations");
    if (!auths || auths->type != JSON_ARRAY)
    {
        warnx("failed to parse authorizations URL");
        goto out;
    }

    thumbprint = jws_thumbprint(a->key);
    if (!thumbprint)
    {
        goto out;
    }

    for (size_t i=0; i<auths->v.array.size; i++)
    {
        if (auths->v.array.values[i].type != JSON_STRING)
        {
            warnx("failed to parse authorizations URL");
            goto out;
        }
        msg(1, "retrieving authorization at %s",
                auths->v.array.values[i].v.value);
        if (200 != acme_post(a, auths->v.array.values[i].v.value, ""))
        {
            warnx("failed to retrieve auth %s",
                    auths->v.array.values[i].v.value);
            acme_error(a);
            goto out;
        }
        const char *status = json_find_string(a->json, "status");
        if (status && strcmp(status, "valid") == 0)
        {
            continue;
        }
        if (!status || strcmp(status, "pending") != 0)
        {
            warnx("unexpected auth status (%s) at %s",
                status ? status : "unknown",
                auths->v.array.values[i].v.value);
            acme_error(a);
            goto out;
        }
        const json_value_t *ident = json_find(a->json, "identifier");
        const char *ident_type = json_find_string(ident, "type");
        if (!ident_type || (strcmp(ident_type, "dns") != 0 &&
                strcmp(ident_type, "ip") != 0))
        {
            warnx("no valid identifier in auth %s",
                    auths->v.array.values[i].v.value);
            goto out;
        }
        const char *ident_value = json_find_string(ident, "value");
        if (!ident_value || strlen(ident_value) <= 0)
        {
            warnx("no valid identifier in auth %s",
                    auths->v.array.values[i].v.value);
            goto out;
        }
        const json_value_t *chlgs = json_find(a->json, "challenges");
        if (!chlgs || chlgs->type != JSON_ARRAY)
        {
            warnx("no challenges in auth %s",
                    auths->v.array.values[i].v.value);
            goto out;
        }
        json_free(auth);
        auth = a->json;
        a->json = NULL;

        bool chlg_done = false;
        for (size_t j=0; j<chlgs->v.array.size && !chlg_done; j++)
        {
            const char *status = json_find_string(
                    chlgs->v.array.values+j, "status");
            if (status && (strcmp(status, "pending") == 0
                        || strcmp(status, "processing") == 0))
            {
                const char *url = json_find_string(
                        chlgs->v.array.values+j, "url");
                const char *type = json_find_string(
                        chlgs->v.array.values+j, "type");
                const char *token = json_find_string(
                        chlgs->v.array.values+j, "token");
                char *key_auth = NULL;
                if (!type || !url || !token)
                {
                    warnx("failed to parse challenge");
                    goto out;
                }
                if (strcmp(type, "dns-01") == 0 ||
                        strcmp(type, "tls-alpn-01") == 0)
                {
                    key_auth = sha2_base64url(256, "%s.%s", token, thumbprint);
                }
                else if (asprintf(&key_auth, "%s.%s", token, thumbprint) < 0)
                {
                    key_auth = NULL;
                }
                if (!key_auth)
                {
                    warnx("failed to generate authorization key");
                    goto out;
                }
                if (a->hook && strlen(a->hook) > 0)
                {
                    msg(2, "type=%s", type);
                    msg(2, "ident=%s", ident_value);
                    msg(2, "token=%s", token);
                    msg(2, "key_auth=%s", key_auth);
                    msg(1, "running %s %s %s %s %s %s", a->hook, "begin",
                            type, ident_value, token, key_auth);
                    int r = hook_run(a->hook, "begin", type, ident_value, token,
                            key_auth);
                    msg(2, "hook returned %d", r);
                    if (r < 0)
                    {
                        free(key_auth);
                        goto out;
                    }
                    else if (r > 0)
                    {
                        msg(1, "challenge %s declined", type);
                        free(key_auth);
                        continue;
                    }
                }
                else
                {
                    char c = 0;
                    msg(0, "challenge=%s ident=%s token=%s key_auth=%s",
                        type, ident_value, token, key_auth);
                    msg(0, "type 'y' to accept challenge, anything else to skip");
                    if (scanf(" %c", &c) != 1 || tolower(c) != 'y')
                    {
                        free(key_auth);
                        continue;
                    }
                }

                msg(1, "starting challenge at %s", url);
                if (200 != acme_post(a, url, "{}"))
                {
                    warnx("failed to start challenge at %s", url);
                    acme_error(a);
                }
                else while (!chlg_done)
                {
                    msg(1, "polling challenge status at %s", url);
                    if (200 != acme_post(a, url, ""))
                    {
                        warnx("failed to poll challenge status at %s", url);
                        acme_error(a);
                        break;
                    }
                    const char *status = json_find_string(a->json, "status");
                    if (status && strcmp(status, "valid") == 0)
                    {
                        chlg_done = true;
                    }
                    else if (!status || (strcmp(status, "processing") != 0 &&
                            strcmp(status, "pending") != 0))
                    {
                        warnx("challenge %s failed with status %s",
                                url, status ? status : "unknown");
                        acme_error(a);
                        break;
                    }
                    else
                    {
                        msg(2, "challenge %s, waiting 5 seconds", status);
                        sleep(5);
                    }
                }
                if (a->hook && strlen(a->hook) > 0)
                {
                    const char *method = chlg_done ? "done" : "failed";
                    msg(1, "running %s %s %s %s %s %s", a->hook, method,
                            type, ident_value, token, key_auth);
                    hook_run(a->hook, method, type, ident_value, token, key_auth);
                }
                free(key_auth);
                if (!chlg_done)
                {
                    goto out;
                }
            }
        }
        if (!chlg_done)
        {
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

bool cert_issue(acme_t *a, bool status_req)
{
    bool success = false;
    char *csr = NULL;
    char *orderurl = NULL;
    char *certfile = NULL;
    char *bakfile = NULL;
    char *tmpfile = NULL;
    time_t t = time(NULL);
    int fd = -1;
    char *ids = identifiers(a->names);
    if (!ids)
    {
        warnx("failed to process alternate names");
        goto out;
    }

    const char *url = json_find_string(a->dir, "newOrder");
    if (!url)
    {
        warnx("failed to find newOrder URL in directory");
        goto out;
    }

    msg(1, "creating new order for %s at %s", a->ident, url);
    if (201 != acme_post(a, url, ids))
    {
        warnx("failed to create new order at %s", url);
        acme_error(a);
        goto out;
    }
    const char *status = json_find_string(a->json, "status");
    if (!status || (strcmp(status, "pending") && strcmp(status, "ready")))
    {
        warnx("invalid order status (%s)", status ? status : "unknown");
        acme_error(a);
        goto out;
    }
    orderurl = find_header(a->headers, "Location");
    if (!orderurl)
    {
        warnx("order location not found");
        goto out;
    }
    msg(1, "order URL: %s", orderurl);
    a->order = a->json;
    a->json = NULL;

    if (strcmp(status, "ready") != 0)
    {
        if (!authorize(a))
        {
            warnx("failed to authorize order at %s", orderurl);
            goto out;
        }
        while (1)
        {
            msg(1, "polling order status at %s", orderurl);
            if (200 != acme_post(a, orderurl, ""))
            {
                warnx("failed to poll order status at %s", orderurl);
                acme_error(a);
                goto out;
            }
            status = json_find_string(a->json, "status");
            if (status && strcmp(status, "ready") == 0)
            {
                json_free(a->order);
                a->order = a->json;
                a->json = NULL;
                break;
            }
            else if (!status || strcmp(status, "pending") != 0)
            {
                warnx("unexpected order status (%s) at %s",
                        status ? status : "unknown", orderurl);
                acme_error(a);
                goto out;
            }
            else
            {
                msg(2, "order pending, waiting 5 seconds");
                sleep(5);
            }
        }
    }

    msg(1, "generating certificate request");
    csr = csr_gen(a->names, status_req, a->ckey);
    if (!csr)
    {
        warnx("failed to generate certificate signing request");
        goto out;
    }

    const char *finalize = json_find_string(a->order, "finalize");
    if (!finalize)
    {
        warnx("failed to find finalize URL");
        goto out;
    }

    msg(1, "finalizing order at %s", finalize);
    if (200 != acme_post(a, finalize, "{\"csr\": \"%s\"}", csr))
    {
        warnx("failed to finalize order at %s", finalize);
        acme_error(a);
        goto out;
    }
    else if (acme_error(a))
    {
        goto out;
    }

    while (1)
    {
        msg(1, "polling order status at %s", orderurl);
        if (200 != acme_post(a, orderurl, ""))
        {
            warnx("failed to poll order status at %s", orderurl);
            acme_error(a);
            goto out;
        }
        status = json_find_string(a->json, "status");
        if (status && strcmp(status, "valid") == 0)
        {
            json_free(a->order);
            a->order = a->json;
            a->json = NULL;
            break;
        }
        else if (!status || strcmp(status, "processing") != 0)
        {
            warnx("unexpected order status (%s) at %s",
                    status ? status : "unknown", orderurl);
            acme_error(a);
            goto out;
        }
        else
        {
            msg(2, "order processing, waiting 5 seconds");
            sleep(5);
        }
    }

    const char *certurl = json_find_string(a->order, "certificate");
    if (!certurl)
    {
        warnx("failed to parse certificate url");
        goto out;
    }

    msg(1, "retrieving certificate at %s", certurl);
    if (200 != acme_post(a, certurl, ""))
    {
        warnx("failed to retrieve certificate at %s", certurl);
        acme_error(a);
        goto out;
    }
    else if (acme_error(a))
    {
        goto out;
    }

    if (asprintf(&certfile, "%s/cert.pem", a->certdir) < 0)
    {
        certfile = NULL;
        warnx("cert_issue: vasprintf failed");
        goto out;
    }

    if (asprintf(&tmpfile, "%s/cert.pem.tmp", a->certdir) < 0)
    {
        tmpfile = NULL;
        warnx("cert_issue: vasprintf failed");
        goto out;
    }

    if (asprintf(&bakfile, "%s/cert-%llu.pem", a->certdir,
                (unsigned long long)t) < 0)
    {
        bakfile = NULL;
        warnx("cert_issue: vasprintf failed");
        goto out;
    }

    msg(1, "saving certificate to %s", tmpfile);
    fd = open(tmpfile, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IRGRP|S_IROTH);
    if (fd < 0)
    {
        warn("failed to create %s", tmpfile);
        goto out;
    }

    if (write(fd, a->body, strlen(a->body)) != (ssize_t)strlen(a->body))
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

    if (link(certfile, bakfile) < 0)
    {
        if (errno != ENOENT)
        {
            warn("failed to link %s to %s", bakfile, certfile);
            goto out;
        }
    }
    else
    {
        msg(1, "backed up %s as %s", certfile, bakfile);
    }

    msg(1, "renaming %s to %s", tmpfile, certfile);
    if (rename(tmpfile, certfile) < 0)
    {
        warn("failed to rename %s to %s", tmpfile, certfile);
        unlink(bakfile);
        goto out;
    }

    success = true;
out:
    if (fd >= 0) close(fd);
    free(bakfile);
    free(tmpfile);
    free(certfile);
    free(csr);
    free(ids);
    free(orderurl);
    return success;
}

bool cert_revoke(acme_t *a, const char *certfile, int reason_code)
{
    bool success = false;
    char *certfiledup = NULL;
    char *revokedfile = NULL;
    const char *url = NULL;
    char *crt = cert_der_base64url(certfile);
    if (!crt)
    {
        warnx("failed to load %s", certfile);
        goto out;
    }

    url = json_find_string(a->dir, "revokeCert");
    if (!url)
    {
        warnx("failed to find revokeCert URL in directory");
        goto out;
    }

    msg(1, "revoking %s at %s", certfile, url);
    if (200 != acme_post(a, url, "{\"certificate\":\"%s\",\"reason\":%d}",
            crt, reason_code))
    {
        warnx("failed to revoke %s at %s", certfile, url);
        acme_error(a);
        goto out;
    }
    else if (acme_error(a))
    {
        goto out;
    }
    msg(1, "revoked %s", certfile);
    certfiledup = strdup(certfile);
    if (!certfiledup)
    {
        warnx("strdup failed");
        certfiledup = NULL;
        goto out;
    }
    if (asprintf(&revokedfile, "%s/revoked-%llu.pem", dirname(certfiledup),
                (unsigned long long)time(NULL)) < 0)
    {
        warnx("asprintf failed");
        revokedfile = NULL;
        goto out;
    }
    msg(1, "renaming %s to %s", certfile, revokedfile);
    if (rename(certfile, revokedfile) < 0)
    {
        warn("failed to rename %s to %s", certfile, revokedfile);
    }
    success = true;
out:
    free(crt);
    free(revokedfile);
    free(certfiledup);
    return success;
}

bool validate_identifier_str(const char *s)
{
    size_t len = 0;
    if (is_ip(s, 0, 0))
        return true;
    for (size_t j = 0; j < strlen(s); j++)
    {
        switch (s[j])
        {
            case '.':
                if (j == 0)
                {
                    warnx("'.' not allowed at beginning in %s", s);
                    return false;
                }
                // intentional fallthrough
            case '_':
            case '-':
                len++;
                continue;
            case '*':
                if (j != 0 || s[1] != '.')
                {
                    warnx("'*.' only allowed at beginning in %s", s);
                    return false;
                }
                break;
            default:
                if (!isupper(s[j]) && !islower(s[j])
                        && !isdigit(s[j]))
                {
                    warnx("invalid character '%c' in %s", s[j], s);
                    return false;
                }
                len++;
        }
    }
    if (len == 0)
    {
        warnx("empty name is not allowed");
        return false;
    }
    return true;
}

void usage(const char *progname)
{
    fprintf(stderr,
        "usage: %s [-a|--acme-url URL] [-b|--bits BITS] [-c|--confdir DIR]\n"
        "\t[-d|--days DAYS] [-f|--force] [-h|--hook PROGRAM] [-m|--must-staple]\n"
        "\t[-n|--never-create] [-s|--staging] [-t|--type RSA | EC]\n"
        "\t[-v|--verbose ...] [-V|--version] [-y|--yes] [-?|--help]\n"
        "\tnew [EMAIL] | update [EMAIL] | deactivate | newkey |\n"
        "\tissue IDENTIFIER [ALTNAME ...]] | revoke CERTFILE\n", progname);
}

int main(int argc, char **argv)
{
    static struct option options[] =
    {
        {"acme-url",     required_argument, NULL, 'a'},
        {"bits",         required_argument, NULL, 'b'},
        {"confdir",      required_argument, NULL, 'c'},
        {"days",         required_argument, NULL, 'd'},
        {"force",        no_argument,       NULL, 'f'},
        {"help",         no_argument,       NULL, '?'},
        {"hook",         required_argument, NULL, 'h'},
        {"must-staple",  no_argument,       NULL, 'm'},
        {"never-create", no_argument,       NULL, 'n'},
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
    bool version = false;
    bool yes = false;
    bool staging = false;
    bool custom_directory = false;
    bool status_req = false;
    int days = 30;
    int bits = 0;
    keytype_t type = PK_RSA;
    const char *filename = NULL;
    acme_t a;
    memset(&a, 0, sizeof(a));
    a.directory = PRODUCTION_URL;
    a.confdir = DEFAULT_CONFDIR;

    if (argc < 2)
    {
        usage(basename(argv[0]));
        return ret;
    }

#if LIBCURL_VERSION_NUM < 0x072600
#error libcurl version 7.38.0 or later is required
#endif
    const curl_version_info_data *cvid = curl_version_info(CURLVERSION_NOW);
    if (!cvid || cvid->version_num < 0x072600)
    {
        warnx("libcurl version 7.38.0 or later is required");
        return ret;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
    {
        warnx("failed to initialize libcurl");
        return ret;
    }

    if (!crypto_init())
    {
        warnx("failed to initialize crypto library");
        curl_global_cleanup();
        return ret;
    }

    while (1)
    {
        char *endptr;
        int option_index;
        int c = getopt_long(argc, argv, "a:b:c:d:f?h:mnst:vVy",
                options, &option_index);
        if (c == -1) break;
        switch (c)
        {
            case 'a':
                if (staging)
                {
                    warnx("-a,--acme-url is incompatible with -s,--staging");
                    goto out;
                }
                custom_directory = true;
                a.directory = optarg;
                break;

            case 'b':
                bits = strtol(optarg, &endptr, 10);
                if (*endptr != 0 || bits <= 0)
                {
                    warnx("BITS must be a positive integer");
                    goto out;
                }
                break;

            case 'c':
                a.confdir = optarg;
                break;

            case 'd':
                days = strtol(optarg, &endptr, 10);
                if (*endptr != 0 || days <= 0)
                {
                    warnx("DAYS must be a positive integer");
                    goto out;
                }
                break;

            case 'f':
                force = true;
                break;

            case 'h':
                a.hook = optarg;
                break;

            case 'm':
                status_req = true;
                break;

            case 'n':
                never = true;
                break;

            case 'v':
                g_loglevel++;
                break;

            case 's':
                if (custom_directory)
                {
                    warnx("-s,--staging is incompatible with -a,--acme-url");
                    goto out;
                }
                staging = true;
                a.directory = STAGING_URL;
                break;

            case 't':
                if (strcasecmp(optarg, "RSA") == 0)
                {
                    type = PK_RSA;
                }
                else if (strcasecmp(optarg, "EC") == 0)
                {
                    type = PK_EC;
                }
                else
                {
                    warnx("type must be either RSA or EC");
                    goto out;
                }
                break;

             case 'V':
                version = true;
                break;

            case 'y':
                yes = true;
                break;

            default:
                usage(basename(argv[0]));
                goto out;
        }
    }

    if (version)
    {
        msg(0, "version " VERSION);
        goto out;
    }

    switch (type)
    {
        case PK_RSA:
            if (bits == 0)
            {
                bits = 2048;
            }
            else if (bits < 2048 || bits > 8192)
            {
                warnx("BITS must be between 2048 and 8192 for RSA keys");
                goto out;
            }
            else if (bits & 7)
            {
                warnx("BITS must be a multiple of 8 for RSA keys");
                goto out;
            }
            break;

        case PK_EC:
            switch (bits)
            {
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

    if (optind == argc)
    {
        usage(basename(argv[0]));
        goto out;
    }

    const char *action = argv[optind++];
    if (strcmp(action, "new") == 0 || strcmp(action, "update") == 0)
    {
        if (optind < argc)
        {
            a.email = argv[optind++];
        }
        if (optind < argc)
        {
            usage(basename(argv[0]));
            goto out;
        }
    }
    else if (strcmp(action, "newkey") == 0
            || strcmp(action, "deactivate") == 0)
    {
        if (optind < argc)
        {
            usage(basename(argv[0]));
            goto out;
        }
    }
    else if (strcmp(action, "issue") == 0)
    {
        if (optind == argc)
        {
            usage(basename(argv[0]));
            goto out;
        }
        a.names = (const char * const *)argv + optind;
        for (const char * const *name = a.names; *name; name++)
        {
            if (!validate_identifier_str(*name))
            {
                goto out;
            }
        }

        a.ident = a.names[0];
        if (a.ident[0] == '*' && a.ident[1] == '.')
        {
            a.ident += 2;
        }
    }
    else if (strcmp(action, "revoke") == 0)
    {
        if (optind == argc)
        {
            usage(basename(argv[0]));
            goto out;
        }
        filename = argv[optind++];
        if (optind < argc)
        {
            usage(basename(argv[0]));
            goto out;
        }
        if (access(filename, R_OK))
        {
            warn("failed to read %s", filename);
            goto out;
        }
    }
    else
    {
        usage(basename(argv[0]));
        goto out;
    }

    time_t now = time(NULL);
    char buf[0x100];
    setlocale(LC_TIME, "C");
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %z", localtime(&now));
    msg(1, "version " PACKAGE_VERSION " starting on %s", buf);

    if (a.hook && access(a.hook, R_OK | X_OK) < 0)
    {
        warn("%s", a.hook);
        goto out;
    }

    if (asprintf(&a.keydir, "%s/private", a.confdir) < 0)
    {
        a.keydir = NULL;
        warnx("asprintf failed");
        goto out;
    }

    if (a.ident)
    {
        if (asprintf(&a.ckeydir, "%s/private/%s", a.confdir, a.ident) < 0)
        {
            a.ckeydir = NULL;
            warnx("asprintf failed");
            goto out;
        }

        if (asprintf(&a.certdir, "%s/%s", a.confdir, a.ident) < 0)
        {
            a.certdir = NULL;
            warnx("asprintf failed");
            goto out;
        }
    }

    bool is_new = strcmp(action, "new") == 0;
    if (!check_or_mkdir(is_new && !never, a.confdir,
                S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH))
    {
        goto out;
    }

    if (!check_or_mkdir(is_new && !never, a.keydir, S_IRWXU))
    {
        goto out;
    }

    if (!(a.key = key_load((!is_new || never) ? PK_NONE : type,
                    bits, "%s/key.pem", a.keydir)))
    {
        goto out;
    }

    if (strcmp(action, "new") == 0)
    {
        if (acme_bootstrap(&a) && account_new(&a, yes))
        {
            ret = 0;
        }
    }
    else if (strcmp(action, "update") == 0)
    {
        if (acme_bootstrap(&a) && account_retrieve(&a) && account_update(&a))
        {
            ret = 0;
        }
    }
    else if (strcmp(action, "newkey") == 0)
    {
        if (acme_bootstrap(&a) && account_retrieve(&a)
                && account_keychange(&a, never, type, bits))
        {
            ret = 0;
        }
    }
    else if (strcmp(action, "deactivate") == 0)
    {
        if (acme_bootstrap(&a) && account_retrieve(&a)
                && account_deactivate(&a))
        {
            ret = 0;
        }
    }
    else if (strcmp(action, "issue") == 0)
    {
        if (!check_or_mkdir(!never, a.ckeydir, S_IRWXU))
        {
            goto out;
        }

        if (!check_or_mkdir(!never, a.certdir,
                    S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH))
        {
            goto out;
        }

        if (!(a.ckey = key_load(never ? PK_NONE : type,
                        bits, "%s/key.pem", a.ckeydir)))
        {
            goto out;
        }

        msg(1, "checking existence and expiration of %s/cert.pem", a.certdir);
        if (cert_valid(a.certdir, a.names, days))
        {
            if (force)
            {
                msg(1, "forcing reissue of %s/cert.pem", a.certdir);
            }
            else
            {
                msg(1, "skipping %s/cert.pem", a.certdir);
                ret = 1;
                goto out;
            }
        }

        if (acme_bootstrap(&a) && account_retrieve(&a)
                && cert_issue(&a, status_req))
        {
            ret = 0;
        }
    }
    else if (strcmp(action, "revoke") == 0)
    {
        if (acme_bootstrap(&a) && account_retrieve(&a) &&
                cert_revoke(&a, filename, 0))
        {
            ret = 0;
        }
    }

out:
    if (a.key) privkey_deinit(a.key);
    if (a.ckey) privkey_deinit(a.ckey);
    json_free(a.json);
    json_free(a.account);
    json_free(a.dir);
    json_free(a.order);
    free(a.nonce);
    free(a.kid);
    free(a.headers);
    free(a.body);
    free(a.type);
    free(a.keydir);
    free(a.ckeydir);
    free(a.certdir);
    crypto_deinit();
    curl_global_cleanup();
    exit(ret);
}

