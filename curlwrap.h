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

#ifndef __CURLWRAP_H__
#define __CURLWRAP_H__
#include <curl/curl.h>

typedef struct {
    char *body;
    size_t body_len;
    char *headers;
    size_t headers_len;
    int code;
} curldata_t;

curldata_t *curldata_calloc(void);
void curldata_free(curldata_t *c);
curldata_t *curl_get(const char *url);
curldata_t *curl_post(const char *url, void *post_data, size_t post_size,
        const char *header, ...);

#endif
