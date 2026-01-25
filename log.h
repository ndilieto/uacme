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

#ifndef __LOG_H__
#define __LOG_H__
#include <syslog.h>

#ifdef __GNUC__
#define DECLARE_LOG_FUNC(func, level)           \
    void __attribute__((format (printf, 1, 2))) \
        func##x(const char *format, ...);       \
    void __attribute__((format (printf, 1, 2))) \
        func(const char *format, ...);
#else
#define DECLARE_LOG_FUNC(func, level)      \
    void func##x(const char *format, ...); \
    void func(const char *format, ...);
#endif

#define DEFINE_LOG_FUNC(func, level)       \
    void func##x(const char *format, ...)  \
    {                                      \
        va_list ap;                        \
        va_start(ap, format);              \
        vmsgx(level, format, ap);          \
        va_end(ap);                        \
    }                                      \
    void func(const char *format, ...)     \
    {                                      \
        va_list ap;                        \
        va_start(ap, format);              \
        vmsg(level, format, ap);           \
        va_end(ap);                        \
    }

DECLARE_LOG_FUNC(debug,  LOG_DEBUG)
DECLARE_LOG_FUNC(info,   LOG_INFO)
DECLARE_LOG_FUNC(notice, LOG_NOTICE)
DECLARE_LOG_FUNC(warn,   LOG_WARNING)
DECLARE_LOG_FUNC(err,    LOG_ERR)
DECLARE_LOG_FUNC(crit,   LOG_CRIT)

void log_stderr(int priority, const char *format, ...);
void set_log_func(void (*f)(int priority, const char *format, ...));

#endif
