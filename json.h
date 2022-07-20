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

#ifndef __JSON_H__
#define __JSON_H__

typedef enum {
    JSON_UNDEFINED = 0,
    JSON_OBJECT = 1,
    JSON_ARRAY = 2,
    JSON_STRING = 3,
    JSON_PRIMITIVE = 4
} json_type_t;

struct json_value;

typedef struct json_object {
    size_t size;
    struct json_value *names;
    struct json_value *values;
} json_object_t;

typedef struct json_array {
    size_t size;
    struct json_value *values;
} json_array_t;

typedef struct json_value {
    json_type_t type;
    union
    {
        json_object_t object;
        json_array_t array;
        char *value;
    } v;
    struct json_value *parent;
} json_value_t;

json_value_t *json_parse(const char *body, size_t body_len);
void json_dump(FILE *f, const json_value_t *value);
void json_free(json_value_t *value);
const json_value_t *json_find(const json_value_t *haystack,
        const char *needle);
const char *json_find_value(const json_value_t *haystack,
        const char *needle);
const char *json_find_string(const json_value_t *haystack,
        const char *needle);
int json_compare_string(const json_value_t *haystack,
        const char *name, const char *value);

#endif

