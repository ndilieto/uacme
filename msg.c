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

#include <ctype.h>
#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "msg.h"

int g_loglevel = 0;

void msg(int level, const char *format, ...)
{
    va_list ap;
    if (level > g_loglevel)
        return;
    va_start(ap, format);
    vwarnx(format, ap);
    va_end(ap);
}

void msg_hd(int level, const char *prefix, const void *data, size_t len)
{
    char *buf = NULL;
    size_t buf_size = 0;
    const unsigned char *d = data;

    if (level > g_loglevel)
        return;

    FILE *f = open_memstream(&buf, &buf_size);
    if (!f) {
        warn("msg_hd: open_memstream failed");
        return;
    }

    for (size_t o = 0; o < len; o += 0x10) {
        size_t i;
        if (fprintf(f, "%05zx: ", o) < 0) {
            warn("msg_hd: fprintf failed");
            fclose(f);
            goto out;
        }
        for (i = 0; i < 0x10; i++) {
            int r = o + i < len ?
                fprintf(f, "%02hhx %s", d[o + i], (i & 7) == 7 ? " " : "") :
                fprintf(f, "   %s", (i & 7) == 7 ? " " : "");
            if (r < 0) {
                warn("msg_hd: fprintf failed");
                fclose(f);
                goto out;
            }
        }
        if (fprintf(f, "|") < 0) {
            warn("msg_hd: fprintf failed");
            fclose(f);
            goto out;
        }
        for (i = 0; i < 0x10 && o + i < len; i++)
            if (fprintf(f, "%c", isprint(d[o + i]) ? d[o + i] : '.') < 0) {
                warn("msg_hd: fprintf failed");
                fclose(f);
                goto out;
            }
        if (fprintf(f, "|%s", o + i < len ? "\n" : "") < 0) {
            warn("msg_hd: fprintf failed");
            fclose(f);
            goto out;
        }
    }

    if (fclose(f)) {
        warn("msg_hd: fclose failed");
        goto out;
    }

    warnx("%s%s", prefix, buf);

out:
    free(buf);
    return;
}
