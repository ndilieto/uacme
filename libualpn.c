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

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <err.h>

#include "ualpn.h"
#include "ualpnc.h"

static void safe_strncpy(char *dst, const char *src, size_t size)
{
    strncpy(dst, src, size - 1);
    dst[size - 1] = '\0';
}

int ualpn_connect(const char *socket_path, FILE **f)
{
    int fd;
    struct sockaddr_un sock_addr;

    memset(&sock_addr, 0, sizeof(sock_addr));
    safe_strncpy(sock_addr.sun_path, socket_path, sizeof(sock_addr.sun_path));
    sock_addr.sun_family = AF_UNIX;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        err(1, "failed to create socket");
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr))) {
        err(1, "failed to connect to unix://%s", socket_path);
        close(fd);
        return -1;
    }

    *f = fdopen(fd, "r+");
    if (!*f) {
        err(1, "fdopen failed");
        close(fd);
        return -1;
    }

    return 0;
}

int ualpn_negotiate_version(FILE *f)
{
    char *line = NULL;
    size_t len = 0;
    ssize_t r;

    r = getline(&line, &len, f);
    if (r == -1) {
        err(1, "failed to read version from server");
        free(line);
        return -1;
    }
    
    int server_min, server_max;
    if (sscanf(line, "VERSION %d %d", &server_min, &server_max) != 2) {
        errx(1, "invalid version response: %s", line);
        free(line);
        return -1;
    }
    
    int client_version = UALPN_PROTOCOL_VERSION_MAX < server_max ? 
                       UALPN_PROTOCOL_VERSION_MAX : server_max;
    if (client_version < server_min || client_version < UALPN_PROTOCOL_VERSION_MIN) {
        errx(1, "incompatible protocol versions (client: %d-%d, server: %d-%d)",
             UALPN_PROTOCOL_VERSION_MIN, UALPN_PROTOCOL_VERSION_MAX, server_min, server_max);
        free(line);
        return -1;
    }
    
    if (fprintf(f, "VERSION %d\n", client_version) < 0) {
        err(1, "failed to send version to server");
        free(line);
        return -1;
    }
    
    r = getline(&line, &len, f);
    if (r == -1) {
        err(1, "failed to read version response from server");
        free(line);
        return -1;
    }
    
    if (strncmp(line, "OK", 2) != 0) {
        errx(1, "version negotiation failed: %s", line);
        free(line);
        return -1;
    }
    
    free(line);
    return 0;
}

int ualpn_auth(FILE *f, const char *ident, const char *auth)
{
    char *line = NULL;
    size_t len = 0;
    ssize_t r;

    if (fprintf(f, "auth %s %s\n", ident, auth) < 0) {
        err(1, "failed to send auth command");
        return -1;
    }
    
    r = getline(&line, &len, f);
    if (r == -1) {
        err(1, "failed to read auth response");
        free(line);
        return -1;
    }
    
    int result = (strncmp(line, "OK", 2) == 0) ? 0 : -1;
    if (result != 0) {
        warnx("auth failed: %s", line);
    }
    
    free(line);
    return result;
}

int ualpn_unauth(FILE *f, const char *ident)
{
    char *line = NULL;
    size_t len = 0;
    ssize_t r;

    if (fprintf(f, "unauth %s\n", ident) < 0) {
        err(1, "failed to send unauth command");
        return -1;
    }
    
    r = getline(&line, &len, f);
    if (r == -1) {
        err(1, "failed to read unauth response");
        free(line);
        return -1;
    }
    
    int result = (strncmp(line, "OK", 2) == 0) ? 0 : -1;
    if (result != 0) {
        warnx("unauth failed: %s", line);
    }
    
    free(line);
    return result;
}

void ualpn_disconnect(FILE *f)
{
    if (f) {
        fclose(f);
    }
}