#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "ualpn.h"
#include "ualpnc.h"


static void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s method type ident token auth\n", progname);
    fprintf(stderr, "  method: begin, done, or failed\n");
    fprintf(stderr, "  type: challenge type (must be tls-alpn-01)\n");
    fprintf(stderr, "  ident: domain identifier\n");
    fprintf(stderr, "  token: unused but kept for compatibility\n");
    fprintf(stderr, "  auth: key authorization (used for begin only)\n");
}

int main(int argc, char *argv[])
{
    if (argc != 6) {
        usage(argv[0]);
        return 85; /* E_BADARGS */
    }

    const char *method = argv[1];
    const char *type = argv[2];
    const char *ident = argv[3];
    // arg 4 token unused
    const char *auth = argv[5];

    if (strcmp(type, "tls-alpn-01") != 0) {
        fprintf(stderr, "skipping %s\n", type);
        return 1;
    }

    FILE *f = NULL;
    int result = 1;

    if (ualpn_connect(DEFAULT_UALPN_SOCKET, &f) != 0) {
        return 1;
    }

    if (ualpn_negotiate_version(f) != 0) {
        ualpn_disconnect(f);
        return 1;
    }

    if (strcmp(method, "begin") == 0) {
        result = ualpn_auth(f, ident, auth) == 0 ? 0 : 1;
    } else if (strcmp(method, "done") == 0 || strcmp(method, "failed") == 0) {
        result = ualpn_unauth(f, ident) == 0 ? 0 : 1;
    } else {
        fprintf(stderr, "%s: invalid method\n", argv[0]);
        result = 1;
    }

    ualpn_disconnect(f);
    return result;
}
