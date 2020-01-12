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

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "curlwrap.h"

curldata_t *curldata_calloc(void)
{
    curldata_t *c = calloc(1, sizeof(curldata_t));
    if (!c)
    {
        warn("curldata_calloc: calloc failed");
        return NULL;
    }
    c->body = strdup("");
    if (!c->body)
    {
        warn("curldata_calloc: strdup failed");
        free(c);
        return NULL;
    }
    c->headers = strdup("");
    if (!c->headers)
    {
        warn("curldata_calloc: strdup failed");
        free(c->body);
        free(c);
        return NULL;
    }
    return c;
}

void curldata_free(curldata_t *c)
{
    if (!c) return;
    free(c->body);
    free(c->headers);
    free(c);
}

static size_t curl_hcb(char *buf, size_t size, size_t n, void *userdata)
{
    curldata_t *c = (curldata_t *)userdata;
    void *p = realloc(c->headers, c->headers_len + size * n + 1);
    if (!p)
    {
        warn("curl_hcb: realloc failed");
        return 0;
    }
    c->headers = p;
    memcpy(c->headers + c->headers_len, buf, size * n);
    c->headers_len += size * n;
    c->headers[c->headers_len] = 0;
    return size * n;
}

static size_t curl_wcb(void *ptr, size_t size, size_t n, void *userdata)
{
    curldata_t *c = (curldata_t *)userdata;
    void *p = realloc(c->body, c->body_len + size * n + 1);
    if (!p)
    {
        warn("curl_wcb: realloc failed");
        return 0;
    }
    c->body = p;
    memcpy(c->body + c->body_len, ptr, size * n);
    c->body_len += size * n;
    c->body[c->body_len] = 0;
    return size * n;
}

curldata_t *curl_get(const char *url)
{
    curldata_t *c = NULL;
    for (int retry = 0; retry < 3; retry++)
    {
        CURL *curl;
        CURLcode res;
        curl = curl_easy_init();
        if (!curl)
        {
            warnx("curl_get: curl_easy_init failed");
            return NULL;
        }
        c = curldata_calloc();
        if (!c)
        {
            warnx("curl_get: curldata_calloc failed");
            curl_easy_cleanup(curl);
            return NULL;
        }
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_wcb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, c);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_hcb);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, c);
        curl_easy_setopt(curl, CURLOPT_USERAGENT,
                "uacme/" VERSION " (https://github.com/ndilieto/uacme)");
        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            warnx("curl_get: GET %s failed: %s", url,
                    curl_easy_strerror(res));
            curldata_free(c);
            c = NULL;
        }
        else
        {
            long code = -1;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            c->code = code;
        }
        curl_easy_cleanup(curl);
        if (c)
        {
            break;
        }
        else if (retry < 3)
        {
            warnx("curl_get: waiting 5 seconds before retrying");
            sleep(5);
        }
    }
    return c;
}

curldata_t *curl_post(const char *url, const char *post)
{
    curldata_t *c = NULL;
    for (int retry = 0; retry < 3; retry++)
    {
        CURL *curl;
        CURLcode res;
        struct curl_slist *list = NULL;
        curl = curl_easy_init();
        if (!curl)
        {
            warnx("curl_post: curl_easy_init failed");
            return NULL;
        }
        c = curldata_calloc();
        if (!c)
        {
            warnx("curl_post: curldata_calloc failed");
            curl_easy_cleanup(curl);
            return NULL;
        }
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_wcb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, c);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_hcb);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, c);
        curl_easy_setopt(curl, CURLOPT_USERAGENT,
                "uacme/" VERSION " (https://github.com/ndilieto/uacme)");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
        list = curl_slist_append(list, "Content-Type: application/jose+json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
        res = curl_easy_perform(curl);
        curl_slist_free_all(list);
        if (res != CURLE_OK)
        {
            warnx("curl_post: POST %s failed: %s", url,
                    curl_easy_strerror(res));
            curldata_free(c);
            c = NULL;
        }
        else
        {
            long code = -1;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            c->code = code;
        }
        curl_easy_cleanup(curl);
        if (c)
        {
            break;
        }
        else if (retry < 3)
        {
            warnx("curl_post: waiting 5 seconds before retrying");
            sleep(5);
        }
    }
    return c;
}
