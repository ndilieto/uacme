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

#include "config.h"

#include <err.h>
#include <stdarg.h>

#include "msg.h"

int g_loglevel = 0;

void msg(int level, const char *format, ...)
{
    va_list ap;
    if (level > g_loglevel) return;
    va_start(ap, format);
    vwarnx(format, ap);
    va_end(ap);
}

