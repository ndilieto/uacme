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

#ifndef __MSG_H__
#define __MSG_H__

#include <stddef.h>

extern int g_loglevel;

#ifdef __GNUC__
void __attribute__((format (printf, 2, 3))) msg(int level,
        const char *format, ...);
#else
void msg(int level, const char *format, ...);
#endif

void msg_hd(int level, const char *prefix, const void *data, size_t len);

#endif
