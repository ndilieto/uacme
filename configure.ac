# Copyright (C) 2019-2026 Nicola Di Lieto <nicola.dilieto@gmail.com>
#
# This file is part of uacme.
#
# uacme is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# uacme is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ(2.53)
AC_INIT([uacme], [m4_esyscmd([build-aux/git-version-gen .tarball-version])])
AC_CONFIG_SRCDIR([uacme.c])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([subdir-objects])
AM_MAINTAINER_MODE([disable])
AM_SILENT_RULES([yes])
AX_IS_RELEASE([git-directory])
AX_CHECK_ENABLE_DEBUG([yes])

AC_USE_SYSTEM_EXTENSIONS
AC_PROG_SED
AC_PROG_GREP
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_CC
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = "xno"; then
    AC_MSG_ERROR([Could not find a C99 compatible compiler])
fi

AX_CHECK_COMPILE_FLAG([$CFLAGS -Wall], [WCFLAGS="-Wall"])
AX_CHECK_COMPILE_FLAG([$CFLAGS -Wextra], [WCFLAGS="$WCFLAGS -Wextra"])
AX_CHECK_COMPILE_FLAG([$CFLAGS -pedantic], [WCFLAGS="$WCFLAGS -pedantic"])
AX_CHECK_COMPILE_FLAG([$CFLAGS -fno-strict-aliasing],
                      [WCFLAGS="$WCFLAGS -fno-strict-aliasing"])
AC_SUBST([WCFLAGS])

AC_SYS_LARGEFILE
AC_CHECK_HEADERS([err.h], [],
                 AC_MSG_ERROR([uacme requires err.h]))
AC_CHECK_HEADERS([getopt.h], [],
                 AC_MSG_ERROR([uacme requires sys/wait.h]))
AC_CHECK_HEADERS([netdb.h], [],
                 AC_MSG_ERROR([uacme requires netdb.h]))
AC_CHECK_HEADERS([netinet/in.h], [],
                 AC_MSG_ERROR([uacme requires netinet/in.h]))
AC_CHECK_HEADERS([arpa/inet.h], [],
                 AC_MSG_ERROR([uacme requires arpa/inet.h]))
AC_CHECK_HEADERS([sys/socket.h], [],
                 AC_MSG_ERROR([uacme requires sys/socket.h]))
AC_CHECK_HEADERS([sys/stat.h], [],
                 AC_MSG_ERROR([uacme requires sys/stat.h]))
AC_CHECK_HEADERS([sys/types.h], [],
                 AC_MSG_ERROR([uacme requires sys/types.h]))
AC_CHECK_HEADERS([sys/wait.h], [],
                 AC_MSG_ERROR([uacme requires sys/wait.h]))
AC_CHECK_FUNCS([asprintf vasprintf], [],
               AC_MSG_ERROR([uacme requires (v)asprintf]))
AC_CHECK_FUNCS([getopt_long], [],
               AC_MSG_ERROR([uacme requires getopt_long]))
AC_CHECK_FUNCS([open_memstream], [],
               AC_MSG_ERROR([uacme requires open_memstream]))
AC_CHECK_FUNCS([strcasestr])
AC_CHECK_FUNCS([setproctitle])

if test -n "$PKG_CONFIG"; then
    PKGCONFIG="$PKG_CONFIG"
    if test -z "`$PKGCONFIG --version`"; then
        AC_MSG_ERROR([PKG_CONFIG is invalid])
    fi
else
    PKG_PROG_PKG_CONFIG([0.28])
    if test "x$PKG_CONFIG" = "x"; then
        AC_MSG_ERROR([Could not find pkg-config])
    else
        PKGCONFIG="$PKG_CONFIG"
    fi
fi

OPT_LIBCURL=yes
AC_ARG_WITH(libcurl,
[AS_HELP_STRING([--with-libcurl[[=PATH]]], [PATH is libcurl installation root])],
OPT_LIBCURL=$withval)

if test "x$OPT_LIBCURL" = "xno"; then
    AC_MSG_ERROR([libcurl must be enabled])
fi
if test "x$OPT_LIBCURL" = "xyes"; then
    AC_MSG_CHECKING([for libcurl >= 7.38.0])
    itexists=`$PKGCONFIG --exists 'libcurl >= 7.38.0' >/dev/null 2>&1 && echo 1`
    if test -z "$itexists"; then
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([libcurl not found])
    else
        CURL_LDADD=`$PKGCONFIG --libs-only-l libcurl`
        CURL_LDFLAGS=`$PKGCONFIG --libs-only-L --libs-only-other libcurl`
        CURL_CPPFLAGS=`$PKGCONFIG --cflags-only-I libcurl`
        CURL_CFLAGS=`$PKGCONFIG --cflags-only-other libcurl`
        version=`$PKGCONFIG --modversion libcurl`
        AC_MSG_RESULT([found $version])
        AC_MSG_CHECKING([for libcurl https support])
        https=`$PKGCONFIG --variable=supported_protocols libcurl 2>/dev/null | grep -q HTTPS && echo 1`
        if test -z "$https"; then
            AC_MSG_RESULT([no])
            AC_MSG_ERROR([libcurl does not support https])
        fi
        AC_MSG_RESULT([yes])
    fi
else
    CURL_LDADD=-lcurl
    CURL_LDFLAGS=-L$OPT_LIBCURL/lib$libsuff
    CURL_CPPFLAGS=-I$OPT_LIBCURL/include
    CURL_CFLAGS=
fi
AC_SUBST(CURL_LDADD)
AC_SUBST(CURL_LDFLAGS)
AC_SUBST(CURL_CPPFLAGS)
AC_SUBST(CURL_CFLAGS)

LIBS_ORIG=$LIBS
LDFLAGS_ORIG=$LDFLAGS
CPPFLAGS_ORIG=$CPPFLAGS
CFLAGS_ORIG=$CFLAGS
LIBS="$CURL_LDADD $LIBS"
LDFLAGS="$LDFLAGS $CURL_LDFLAGS"
CPPFLAGS="$CPPFLAGS $CURL_CPPFLAGS"
CFLAGS="$CFLAGS $CURL_CFLAGS"
AC_CHECK_LIB(curl, curl_global_init, [CURL_ENABLED=1],
             [AC_MSG_ERROR([libcurl check failed])])
LIBS=$LIBS_ORIG
LDFLAGS=$LDFLAGS_ORIG
CPPFLAGS=$CPPFLAGS_ORIG
CFLAGS=$CFLAGS_ORIG

OPT_MBEDTLS=no
AC_ARG_WITH(mbedtls,
[AS_HELP_STRING([--with-mbedtls[[=PATH]]], [build with mbedTLS, PATH is installation root])
AS_HELP_STRING([--without-mbedtls], [build without mbedTLS])],
OPT_MBEDTLS=$withval)

OPT_OPENSSL=no
AC_ARG_WITH(openssl,
[AS_HELP_STRING([--with-openssl[[=PATH]]], [build with OpenSSL, PATH is installation root])
AS_HELP_STRING([--without-openssl], [build without OpenSSL])],
OPT_OPENSSL=$withval)

if test "x$OPT_MBEDTLS" = "xno" -a "x$OPT_OPENSSL" = "xno"; then
    OPT_GNUTLS=yes
else
    OPT_GNUTLS=no
fi
AC_ARG_WITH([gnutls],
[AS_HELP_STRING([--with-gnutls[[=PATH]]], [build with GnuTLS, PATH is installation root])
AS_HELP_STRING([--without-gnutls], [build without GnuTLS])],
OPT_GNUTLS=$withval)

if test "x$OPT_GNUTLS" = "xno" -a "x$OPT_MBEDTLS" = "xno" -a "x$OPT_OPENSSL" = "xno"; then
    AC_MSG_ERROR([One of GnuTLS, OpenSSL or mbedTLS must be enabled])
fi
if test "x$OPT_GNUTLS" != "xno" -a "x$OPT_MBEDTLS" != "xno"; then
    AC_MSG_ERROR([GnuTLS and mbedTLS cannot be both enabled])
fi
if test "x$OPT_GNUTLS" != "xno" -a "x$OPT_OPENSSL" != "xno"; then
    AC_MSG_ERROR([GnuTLS and OpenSSL cannot be both enabled])
fi
if test "x$OPT_OPENSSL" != "xno" -a "x$OPT_MBEDTLS" != "xno"; then
    AC_MSG_ERROR([OpenSSL and mbedTLS cannot be both enabled])
fi

if test "x$OPT_GNUTLS" != "xno"; then
    addlib=""
    if test "x$OPT_GNUTLS" = "xyes"; then
        AC_MSG_CHECKING([for GnuTLS >= 3.3.30])
        itexists=`$PKGCONFIG --exists 'gnutls >= 3.3.30' >/dev/null 2>&1 && echo 1`
        if test -z "$itexists"; then
            AC_MSG_RESULT([no])
            AC_MSG_ERROR([gnutls not found])
        else
            addlib=`$PKGCONFIG --libs-only-l gnutls`
            addld=`$PKGCONFIG --libs-only-L gnutls`
            addcflags=`$PKGCONFIG --cflags-only-I gnutls`
            version=`$PKGCONFIG --modversion gnutls`
            gtlslib=`echo $addld | sed -e 's/-L//'`
            AC_MSG_RESULT([found $version])
        fi
    else
        addlib=-lgnutls
        addld=-L$OPT_GNUTLS/lib$libsuff
        addcflags=-I$OPT_GNUTLS/include
        gtlslib=$OPT_GNUTLS/lib$libsuff
    fi
    if test -n "$addlib"; then
        LIBS="$addlib $LIBS"
        LDFLAGS="$LDFLAGS $addld"
        if test "$addcflags" != "-I/usr/include"; then
            CPPFLAGS="$CPPFLAGS $addcflags"
        fi
        AC_CHECK_LIB(gnutls, gnutls_global_init,
                     [AC_DEFINE(USE_GNUTLS, 1, [if GnuTLS is enabled])
                      AC_SUBST(USE_GNUTLS, [1])
                      USE_GNUTLS="yes"],
                     [AC_MSG_ERROR([gnutls check failed])])
        AC_CHECK_FUNCS([gnutls_decode_rs_value], [], [NEED_LIBTASN1="yes"])
        AC_CHECK_FUNCS([gnutls_x509_crq_set_tlsfeatures], [],
                       [AC_MSG_NOTICE([--must-staple requires GnuTLS 3.5.1 or later])])
    fi
fi

if test "x$NEED_LIBTASN1" = "xyes"; then
    addlib=""
    AC_MSG_CHECKING([for libtasn1 >= 4.2])
    itexists=`$PKGCONFIG --exists 'libtasn1 >= 4.2' >/dev/null 2>&1 && echo 1`
    if test -z "$itexists"; then
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([libtasn1 not found])
    else
        addlib=`$PKGCONFIG --libs-only-l libtasn1`
        addld=`$PKGCONFIG --libs-only-L libtasn1`
        addcflags=`$PKGCONFIG --cflags-only-I libtasn1`
        version=`$PKGCONFIG --modversion libtasn1`
        tasn1lib=`echo $addld | sed -e 's/-L//'`
        AC_MSG_RESULT([found $version])
    fi
    if test -n "$addlib"; then
        LIBS="$addlib $LIBS"
        LDFLAGS="$LDFLAGS $addld"
        if test "$addcflags" != "-I/usr/include"; then
            CPPFLAGS="$CPPFLAGS $addcflags"
        fi
        AC_CHECK_LIB(tasn1, asn1_get_tag_der,
                     [AC_DEFINE(USE_LIBTASN1, 1, [if libtasn1 is enabled])
                      AC_SUBST(USE_LIBTASN1, [1])
                      LIBTASN1_ENABLED=1
                      USE_LIBTASN1="yes"],
                     [AC_MSG_ERROR([libtasn1 check failed])])
    fi
fi

if test "x$OPT_OPENSSL" != "xno"; then
    addlib=""
    if test "x$OPT_OPENSSL" = "xyes"; then
        AC_MSG_CHECKING([for OpenSSL >= 1.1.1])
        itexists=`$PKGCONFIG --exists 'openssl >= 1.1.1' >/dev/null 2>&1 && echo 1`
        if test -z "$itexists"; then
            AC_MSG_RESULT([no])
            AC_MSG_ERROR([openssl not found])
        else
            addlib=`$PKGCONFIG --libs-only-l openssl`
            addld=`$PKGCONFIG --libs-only-L openssl`
            addcflags=`$PKGCONFIG --cflags-only-I openssl`
            version=`$PKGCONFIG --modversion openssl`
            openssllib=`echo $addld | sed -e 's/-L//'`
            AC_MSG_RESULT([found $version])
        fi
    else
        addlib="-lssl -lcrypto"
        addld=-L$OPT_OPENSSL/lib$libsuff
        addcflags=-I$OPT_OPENSSL/include
        openssllib=$OPT_OPENSSL/lib$libsuff
    fi
    if test -n "$addlib"; then
        LIBS="$addlib $LIBS"
        LDFLAGS="$LDFLAGS $addld"
        if test "$addcflags" != "-I/usr/include"; then
            CPPFLAGS="$CPPFLAGS $addcflags"
        fi
        AC_CHECK_LIB(ssl, OpenSSL_version_num,
                     [AC_DEFINE(USE_OPENSSL, 1, [if OpenSSL is enabled])
                      AC_SUBST(USE_OPENSSL, [1])
                      USE_OPENSSL="yes"],
                     [AC_MSG_ERROR([openssl check failed])])
        AC_MSG_CHECKING([if OpenSSL is really LibreSSL])
        AC_COMPILE_IFELSE([AC_LANG_SOURCE([#include <openssl/crypto.h>
                           int main() {return LIBRESSL_VERSION_NUMBER;}])],
            LIBRESSL=yes
            AC_MSG_RESULT([yes]),
            AC_MSG_RESULT([no]))
    fi
fi
AM_CONDITIONAL(ENABLE_READFILE, test "x$USE_OPENSSL" != "xyes")

if test "x$OPT_MBEDTLS" != "xno"; then
    addlib="-lmbedtls -lmbedx509 -lmbedcrypto"
    if test "x$OPT_MBEDTLS" = "xyes"; then
        addld=""
        addcflags=""
    else
        addld=-L$OPT_MBEDTLS/lib$libsuff
        addcflags=-I$OPT_MBEDTLS/include
    fi
    LIBS="$addlib $LIBS"
    LDFLAGS="$LDFLAGS $addld"
    CPPFLAGS="$CPPFLAGS $addcflags"
    AC_CHECK_LIB(mbedtls, mbedtls_entropy_init,
                 [AC_DEFINE(USE_MBEDTLS, 1, [if mbedTLS is enabled])
                  AC_SUBST(USE_MBEDTLS, [1])
                  USE_MBEDTLS="yes"],
                 [AC_MSG_ERROR([mbedtls check failed])])
    if test "x$USE_MBEDTLS" = "xyes"; then
        AC_MSG_NOTICE([detected mbedTLS])
    fi
fi

if test "x$LIBRESSL" = "xyes"; then
    OPT_UALPN=no
else
    OPT_UALPN=yes
fi
AC_ARG_WITH(ualpn,
[AS_HELP_STRING([--with-ualpn], [enable ualpn])
AS_HELP_STRING([--without-ualpn], [disable ualpn])], OPT_UALPN=$withval)

if test "x$OPT_UALPN" != "xno"; then
    if test "x$LIBRESSL" = "xyes"; then
        AC_MSG_ERROR([ualpn is not compatible with LibreSSL])
    fi
    AM_PROG_AR
    AC_CHECK_HEADERS([netinet/tcp.h], [],
                     AC_MSG_ERROR([ualpn requires netinet/tcp.h]))
    AC_CHECK_HEADERS([sys/mman.h], [],
                     AC_MSG_ERROR([ualpn requires sys/mman.h]))
    AC_CHECK_HEADERS([sys/resource.h], [],
                     AC_MSG_ERROR([ualpn requires sys/resource.h]))
    AC_CHECK_HEADERS([sys/uio.h], [],
                     AC_MSG_ERROR([ualpn requires sys/uio.h]))
    AC_CHECK_HEADERS([sys/un.h], [],
                     AC_MSG_ERROR([ualpn requires sys/un.h]))
    AC_CHECK_FUNCS([mmap],[],
                   AC_MSG_ERROR([ualpn requires mmap]))
    AC_MSG_CHECKING([if mmap(MAP_ANON|MAP_SHARED) works])
    AC_RUN_IFELSE([AC_LANG_SOURCE([#include <sys/mman.h>
                     int main() {return mmap(0, 4096, PROT_READ|PROT_WRITE,
                        MAP_ANON|MAP_SHARED, -1, 0) == MAP_FAILED;}])],
        [
            AC_DEFINE(HAVE_MAP_ANON, 1, [if mmap(MAP_ANON|MAP_SHARED) works])
            AC_MSG_RESULT([yes])
        ], [
            AC_MSG_RESULT([no])
            AC_MSG_CHECKING([if mmap("/dev/zero", MAP_SHARED) works])
            AC_RUN_IFELSE([AC_LANG_SOURCE([#include <sys/mman.h>
                             #include <sys/stat.h>
                             #include <fcntl.h>
                             int main() {return mmap(0, 4096, PROT_READ|PROT_WRITE,
                                MAP_ANON|MAP_SHARED, open("/dev/zero", O_RDWR), 0) ==
                                MAP_FAILED;}])],
                AC_DEFINE(HAVE_MAP_DEVZERO, 1, [if mmap("/dev/zero", MAP_SHARED) works])
                AC_MSG_RESULT([yes]),
                AC_MSG_RESULT([no])
                AC_MSG_ERROR([ualpn requires MAP_ANON or mmap("/dev/zero", MAP_SHARED)]))
        ], [
            AC_COMPILE_IFELSE([AC_LANG_SOURCE([#include <sys/mman.h>
                             int main() {return mmap(0, 4096, PROT_READ|PROT_WRITE,
                                MAP_ANON|MAP_SHARED, -1, 0) == MAP_FAILED;}])],
                AC_DEFINE(HAVE_MAP_ANON, 1, [if mmap(MAP_ANON|MAP_SHARED) works])
                AC_MSG_RESULT([yes]),
                AC_MSG_RESULT([no])
                AC_MSG_NOTICE([falling back to mmap("/dev/zero", MAP_SHARED)])
                AC_DEFINE(HAVE_MAP_DEVZERO, 1, [if mmap("/dev/zero", MAP_SHARED) works]))
        ])
    AC_ARG_ENABLE(splice, AS_HELP_STRING([--disable-splice], [disable splice]))
    if test "x$enable_splice" != "xno"; then
        AC_CHECK_FUNCS([splice])
    fi
    LIBS_ORIG=$LIBS
    LIBS=
    AC_SEARCH_LIBS([sem_init], [pthread], [],
                   AC_MSG_ERROR([sem_init not found]))
    AC_SEARCH_LIBS([ev_version_major], [ev], [],
                   [AC_MSG_NOTICE([libev not found, using included copy])
                    with_included_libev=yes
                    m4_include([libev/libev.m4])])
    UALPN_LDADD=$LIBS
    LIBS=$LIBS_ORIG
fi
AC_SUBST(UALPN_LDADD)
AM_CONDITIONAL(ENABLE_UALPN, test "x$OPT_UALPN" = "xyes")
AM_CONDITIONAL(ENABLE_LIBEV, test "x$with_included_libev" = "xyes")

default_docs="yes"
AC_ARG_ENABLE(docs,
  [AC_HELP_STRING([--disable-docs], [do not build and install documentation])],
    [],enable_docs=$default_docs)
AM_CONDITIONAL(ENABLE_DOCS, test "x$enable_docs" = "xyes")
if test "x$enable_docs" = "xyes"; then
    AC_PATH_PROG(A2X, a2x, no)
    AC_PATH_PROG(ASCIIDOC, asciidoc, no)
    AS_IF([test "x$A2X" = "xno"], [AC_MSG_ERROR([Could not find a2x.])])
    AS_IF([test "x$ASCIIDOC" = "xno"], [AC_MSG_ERROR([Could not find asciidoc.])])
fi

AS_CASE([$prefix:$localstatedir],
        [NONE:'${prefix}/var' | /usr:'${prefix}/var' | /usr/local:'${prefix}/var'],
         [localstatedir=/var; AC_MSG_NOTICE([--localstatedir defaulted to /var])])
AC_SUBST([localstatedir])

AS_CASE([$prefix:$sysconfdir],
        [NONE:'${prefix}/etc' | /usr:'${prefix}/etc' | /usr/local:'${prefix}/etc'],
         [sysconfdir=/etc; AC_MSG_NOTICE([--sysconfdir defaulted to /etc])])
AC_SUBST([sysconfdir])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
