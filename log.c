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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"

void log_stderr(int priority, const char *format, ...)
{
    va_list ap;
    const char *pri;
    switch (priority) {
        case LOG_DEBUG:
            pri = "DEBUG";
            break;
        case LOG_INFO:
            pri = "INFO";
            break;
        case LOG_NOTICE:
            pri = "NOTICE";
            break;
        case LOG_WARNING:
            pri = "WARNING";
            break;
        case LOG_ERR:
            pri = "ERR";
            break;
        case LOG_CRIT:
            pri = "CRIT";
            break;
        default:
            pri = "UNKNOWN";
    }
    fprintf(stderr, "%ld [%s] ", (long)getpid(), pri);
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void (*log_func)(int priority, const char *format, ...) = log_stderr;

void set_log_func(void (*f)(int priority, const char *format, ...)) {
    log_func = f;
}

static void vmsgx(int priority, const char *format, va_list ap)
{
    int errno_save = errno;
    char *buf = NULL;
    size_t buf_size = 0;
    FILE *f = open_memstream(&buf, &buf_size);
    if (!f)
        log_func(LOG_ERR, "vmsg(%s, ...): open_memstream: %s",
                format, strerror(errno));
    else if (vfprintf(f, format, ap) < 0)
        log_func(LOG_ERR, "vmsg(%s, ...): vfprintf: %s",
                format, strerror(errno));
    else if (fflush(f) != 0)
        log_func(LOG_ERR, "vmsgx(%s, ...): fflush: %s",
                format, strerror(errno));
    else
        log_func(priority, "%s", buf);
    if (f)
        fclose(f);
    free(buf);
    errno = errno_save;
    return;
}

static void vmsg(int priority, const char *format, va_list ap)
{
    int errno_save = errno;
    char *buf = NULL;
    size_t buf_size = 0;
    FILE *f = open_memstream(&buf, &buf_size);
    if (!f)
        log_func(LOG_ERR, "vmsg(%s, ...): open_memstream: %s",
                format, strerror(errno));
    else if (vfprintf(f, format, ap) < 0)
        log_func(LOG_ERR, "vmsg(%s, ...): vfprintf: %s",
                format, strerror(errno));
    else if (fprintf(f, ": %s", strerror(errno_save)) < 0)
        log_func(LOG_ERR, "vmsg(%s, ...): fprintf: %s",
                format, strerror(errno));
    else if (fflush(f) != 0)
        log_func(LOG_ERR, "vmsgx(%s, ...): fflush: %s",
                format, strerror(errno));
    else
        log_func(priority, "%s", buf);
    if (f)
        fclose(f);
    free(buf);
    errno = errno_save;
    return;
}

DEFINE_LOG_FUNC(debug,  LOG_DEBUG)
DEFINE_LOG_FUNC(info,   LOG_INFO)
DEFINE_LOG_FUNC(notice, LOG_NOTICE)
DEFINE_LOG_FUNC(warn,   LOG_WARNING)
DEFINE_LOG_FUNC(err,    LOG_ERR)
DEFINE_LOG_FUNC(crit,   LOG_CRIT)

