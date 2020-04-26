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

#ifndef __IDENTS_H__
#define __IDENTS_H__

#include <stdint.h>
#include <unistd.h>

struct idents {
    char** base;
    size_t len;
    int args;
    char* end;

    char* strings;
    char**cur_ptr;
    char* cur_str;
};


#define idents_addarg(i, l) (i)->len += l + sizeof(char*) + 1, (i)->args ++
#define idents_get(i) (i)->base
#define idents_here(i) (i)->cur_str
#define idents_left(i) ((i)->end - (i)->cur_str)

int idents_alloc(struct idents*);
int idents_commit(struct idents*, size_t);
void idents_init(struct idents*);

#endif
