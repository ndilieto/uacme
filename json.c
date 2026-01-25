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

#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "jsmn.h"

static int json_build(const char *js, jsmntok_t *t, size_t count,
        json_value_t *value) {
    int i, j, k;
    if (count <= 0)
        return 0;
    switch (t->type) {
        case JSMN_PRIMITIVE:
            value->type = JSON_PRIMITIVE;
            value->v.value = strndup(js+t->start, t->end - t->start);
            if (!value->v.value) {
                warn("json_build: strndup failed");
                return -1;
            }
            return 1;

        case JSMN_STRING:
            value->type = JSON_STRING;
            value->v.value = strndup(js+t->start, t->end - t->start);
            if (!value->v.value) {
                warn("json_build: strndup failed");
                return -1;
            }
            return 1;

        case JSMN_OBJECT:
            value->type = JSON_OBJECT;
            value->v.object.size = t->size;
            value->v.object.names = calloc(t->size, sizeof(json_value_t));
            value->v.object.values = calloc(t->size, sizeof(json_value_t));
            if (!value->v.object.names || !value->v.object.values) {
                warn("json_build: calloc failed");
                return -1;
            }
            for (j = i = 0; i < t->size; i++) {
                value->v.object.names[i].parent = value;
                value->v.object.values[i].parent = value;
                k = json_build(js, t+1+j, count-j, value->v.object.names+i);
                if (k < 0) return k; else j += k;
                k = json_build(js, t+1+j, count-j, value->v.object.values+i);
                if (k < 0) return k; else j += k;
            }
            return j+1;

        case JSMN_ARRAY:
            value->type = JSON_ARRAY;
            value->v.array.size = t->size;
            value->v.array.values = calloc(t->size, sizeof(json_value_t));
            if (!value->v.array.values) {
                warn("json_build: calloc failed");
                return -1;
            }
            for (j = i = 0; i < t->size; i++) {
                value->v.array.values[i].parent = value;
                k = json_build(js, t+1+j, count-j, value->v.array.values+i);
                if (k < 0) return k; else j += k;
            }
            return j+1;

        default:
            value->type = JSON_UNDEFINED;
            return 0;
    }
}

static void _json_dump(FILE *f, const json_value_t *value, size_t indent)
{
    size_t i,j;
    if (!value) return;
    switch (value->type) {
        case JSON_PRIMITIVE:
            fprintf(f, "%s", value->v.value);
            return;

        case JSON_STRING:
            fprintf(f, "\"%s\"", value->v.value);
            return;

        case JSON_OBJECT:
            fprintf(f, "{\n");
            for (i = 0; i < value->v.object.size; i++) {
                for (j=0; j<4*(indent+1); j++) fputc(' ', f);
                _json_dump(f, value->v.object.names+i, indent + 1);
                fprintf(f, ": ");
                _json_dump(f, value->v.object.values+i, indent + 1);
                if (i < value->v.object.size - 1) fputc(',', f);
                fputc('\n', f);
            }
            for (j=0; j<4*indent; j++) fputc(' ', f);
            fputc('}', f);
            if (indent == 0)
                fputc('\n', f);
            return;

        case JSON_ARRAY:
            fprintf(f, "[\n");
            for (i = 0; i < value->v.array.size; i++) {
                for (j=0; j<4*(indent+1); j++) fputc(' ', f);
                _json_dump(f, value->v.array.values+i, indent + 1);
                if (i < value->v.array.size - 1) fputc(',', f);
                fputc('\n', f);
            }
            for (j=0; j<4*indent; j++) fputc(' ', f);
            fputc(']', f);
            if (indent == 0)
                fputc('\n', f);
            return;

        default:
            return;
    }
}

void json_dump(FILE *f, const json_value_t *value)
{
    _json_dump(f, value, 0);
}

void json_free(json_value_t *value)
{
    size_t i;
    if (!value) return;
    switch (value->type) {
        case JSON_PRIMITIVE:
        case JSON_STRING:
            free(value->v.value);
            break;

        case JSON_OBJECT:
            for (i = 0; i < value->v.object.size; i++) {
                json_free(value->v.object.names+i);
                json_free(value->v.object.values+i);
            }
            free(value->v.object.names);
            free(value->v.object.values);
            break;

        case JSON_ARRAY:
            for (i = 0; i < value->v.array.size; i++)
                json_free(value->v.array.values+i);
            free(value->v.array.values);
            break;

        default:
            break;
    }
    if (!value->parent)
        free(value);
}

const json_value_t *json_find(const json_value_t *haystack,
        const char *needle)
{
    if (!haystack || haystack->type != JSON_OBJECT)
        return NULL;
    for (size_t i=0; i<haystack->v.object.size; i++)
        if (strcmp(haystack->v.object.names[i].v.value, needle) == 0)
            return haystack->v.object.values + i;
    return NULL;
}

const char *json_find_value(const json_value_t *haystack,
        const char *needle)
{
    if (!haystack || haystack->type != JSON_OBJECT)
        return NULL;
    for (size_t i=0; i<haystack->v.object.size; i++)
        if (haystack->v.object.values[i].type == JSON_PRIMITIVE &&
                strcmp(haystack->v.object.names[i].v.value, needle) == 0)
            return haystack->v.object.values[i].v.value;
    return NULL;
}

const char *json_find_string(const json_value_t *haystack,
        const char *needle)
{
    if (!haystack || haystack->type != JSON_OBJECT)
        return NULL;
    for (size_t i=0; i<haystack->v.object.size; i++)
        if (haystack->v.object.values[i].type == JSON_STRING &&
                strcmp(haystack->v.object.names[i].v.value, needle) == 0)
            return haystack->v.object.values[i].v.value;
    return NULL;
}

int json_compare_string(const json_value_t *haystack, const char *name,
        const char *value)
{
    const char *tmp = json_find_string(haystack, name);
    if (tmp)
        return strcmp(tmp, value);
    else
        return INT_MIN;
}

json_value_t *json_parse(const char *body, size_t body_len)
{
    json_value_t *ret = NULL;
    jsmn_parser parser;
    unsigned int tok_len = 2;
    jsmntok_t *tok = calloc(tok_len, sizeof(*tok));
    if (!tok) {
        warn("json_parse: calloc failed");
        return NULL;
    }
    jsmn_init(&parser);
    while (1) {
        int r = jsmn_parse(&parser, body, body_len, tok, tok_len);
        if (r < 0) {
            if (r == JSMN_ERROR_NOMEM) {
                void *p = realloc(tok, sizeof(*tok) * tok_len * 2);
                if (!p) {
                    warn("json_parse: realloc failed");
                    break;
                }
                tok_len *= 2;
                tok = p;
            } else {
                warnx("json_parse: jsmn_parse failed with code %d", r);
                break;
            }
        } else {
            ret = calloc(1, sizeof(json_value_t));
            if (!ret) {
                warn("json_parse: calloc failed");
                break;
            }
            json_build(body, tok, parser.toknext, ret);
            break;
        }
    }
    free(tok);
    return ret;
}
