/*
 * Copyright (C) 2020 Michel Stam <michel@reverze.net>
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
#include "idents.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

void idents_init(struct idents* id)
{
    memset((void*)id, 0, sizeof(struct idents));
    id->len = sizeof (char*);
}

int idents_alloc(struct idents* id)
{
    id->base = (char**) malloc(id->len);
    if (id->base) {
        id->end = ((char*) id->base) + id->len;
        id->strings = (char*) &(id->base[id->args+1]);
        id->cur_ptr = id->base;
        id->cur_str = id->strings;
        id->base[id->args] = NULL;
    }

    return (id->base == NULL);
}

int idents_commit(struct idents* id, size_t len)
{
    int res = 1;
    char* tmp;

    if (id->cur_ptr == &(id->base[id->args]))
        goto end;

    tmp = id->cur_str;

    id->cur_str += len;
    if (idents_left(id) <= 0) {
       id->cur_str = tmp;
       goto end;
    }
    *(id->cur_ptr) = tmp;
    id->cur_ptr ++;
    *(id->cur_str) = '\0';
    id->cur_str ++;

    res = 0;

end:
    return res;
}
