/*
 * Copyright (C) 2019-2024 Nicola Di Lieto <nicola.dilieto@gmail.com>
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

#ifndef __UALPNC_H__
#define __UALPNC_H__

#include <stdio.h>

int ualpn_connect(const char *socket_path, FILE **f);
int ualpn_negotiate_version(FILE *f);
int ualpn_auth(FILE *f, const char *ident, const char *auth);
int ualpn_unauth(FILE *f, const char *ident);
void ualpn_disconnect(FILE *f);

#endif