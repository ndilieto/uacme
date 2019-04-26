# Copyright (C) 2019 Nicola Di Lieto <nicola.dilieto@gmail.com>
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
AC_CONFIG_MACRO_DIRS([build-aux/m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects])
AM_SILENT_RULES([yes])
AX_IS_RELEASE([git-directory])
AX_CHECK_ENABLE_DEBUG([yes])

if test -z "$SED"; then
    AC_PATH_PROG([SED], [sed], [not_found],
                 [$PATH:/usr/bin:/usr/local/bin])
    if test -z "$SED" || test "$SED" = "not_found"; then
        AC_MSG_ERROR([sed not found in PATH. Cannot continue without sed.])
    fi
fi
AC_SUBST([SED])

AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = "xno"; then
    AC_MSG_ERROR([Could not find a C99 compatible compiler])
fi
AC_CHECK_FUNCS([asprintf vasprintf], [],
               AC_MSG_ERROR([(v)asprintf not found]))

if test -n "$PKG_CONFIG"; then
    PKGCONFIG="$PKG_CONFIG"
else
    AC_PATH_TOOL([PKGCONFIG], [pkg-config], [no],
                 [$PATH:/usr/bin:/usr/local/bin])
fi

OPT_LIBCURL=yes
AC_ARG_WITH(libcurl,dnl
    AC_HELP_STRING([--with-libcurl=PATH],[PATH is libcurl installation root]),
    OPT_LIBCURL=$withval)

if test X"$OPT_LIBCURL" = Xno; then
    AC_MSG_ERROR([libcurl must be enabled])
fi
if test X"$OPT_LIBCURL" = Xyes; then
    if test X"$PKGCONFIG" != Xno; then
        AC_MSG_CHECKING([for libcurl >= 7.38])
        itexists=`$PKGCONFIG --exists 'libcurl >= 7.38' >/dev/null 2>&1 && echo 1`
        if test -z "$itexists"; then
            AC_MSG_RESULT([no])
            AC_MSG_ERROR([libcurl not found])
        else
            addlib=`$PKGCONFIG --libs-only-l libcurl`
            addld=`$PKGCONFIG --libs-only-L libcurl`
            addcflags=`$PKGCONFIG --cflags-only-I libcurl`
            version=`$PKGCONFIG --modversion libcurl`
            curllib=`echo $addld | $SED -e 's/-L//'`
            AC_MSG_RESULT([found $version])
        fi
    fi
else
    addlib=-lcurl
    addld=-L$OPT_LIBCURL/lib$libsuff
    addcflags=-I$OPT_LIBCURL/include
    curllib=$OPT_LIBCURL/lib$libsuff
fi
LIBS="$addlib $LIBS"
LDFLAGS="$LDFLAGS $addld"
if test "$addcflags" != "-I/usr/include"; then
    CPPFLAGS="$CPPFLAGS $addcflags"
fi
AC_CHECK_LIB(curl, curl_global_init, [CURL_ENABLED=1],
             [AC_MSG_ERROR([libcurl check failed])])
if test -n "$curllib"; then
    if test X"$cross_compiling" != Xyes; then
        UACME_LIBRARY_PATH="$UACME_LIBRARY_PATH:$curllib"
        export UACME_LIBRARY_PATH
        AC_MSG_NOTICE([Added $curllib to UACME_LIBRARY_PATH])
    fi
fi

OPT_MBEDTLS=no
AC_ARG_WITH(mbedtls,dnl
    AC_HELP_STRING([--with-mbedtls=PATH],[enable mbedTLS, PATH is installation root])
    AC_HELP_STRING([--without-mbedtls], [disable mbedTLS detection]),
    OPT_MBEDTLS=$withval)
if test "$OPT_MBEDTLS" = no; then
    OPT_GNUTLS=yes
else
    OPT_GNUTLS=no
fi
AC_ARG_WITH(gnutls,dnl
    AC_HELP_STRING([--with-gnutls=PATH],[enable GnuTLS, PATH is installation root])
    AC_HELP_STRING([--without-gnutls], [disable GnuTLS detection]),
    OPT_GNUTLS=$withval)
if test X"$OPT_GNUTLS" = Xno -a X"$OPT_MBEDTLS" = Xno; then
    AC_MSG_ERROR([Either GnuTLS or mbedTLS must be enabled])
fi
if test X"$OPT_GNUTLS" != Xno -a X"$OPT_MBEDTLS" != Xno; then
    AC_MSG_ERROR([GnuTLS and mbedTLS cannot be both enabled])
fi
 
if test X"$OPT_GNUTLS" != Xno; then
    addlib=""
    if test X"$OPT_GNUTLS" = Xyes; then
        if test X"$PKGCONFIG" != Xno; then
            AC_MSG_CHECKING([for GnuTLS >= 3.3])
            itexists=`$PKGCONFIG --exists 'gnutls >= 3.3' >/dev/null 2>&1 && echo 1`
            if test -z "$itexists"; then
                AC_MSG_RESULT([no])
                AC_MSG_ERROR([gnutls not found])
            else
                addlib=`$PKGCONFIG --libs-only-l gnutls`
                addld=`$PKGCONFIG --libs-only-L gnutls`
                addcflags=`$PKGCONFIG --cflags-only-I gnutls`
                version=`$PKGCONFIG --modversion gnutls`
                gtlslib=`echo $addld | $SED -e 's/-L//'`
                AC_MSG_RESULT([found $version])
            fi
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
                      GNUTLS_ENABLED=1
                      USE_GNUTLS="yes"],
                     [AC_MSG_ERROR([gnutls check failed])])
        if test X"$USE_GNUTLS" = Xyes; then
            if test -n "$gtlslib"; then
                if test X"$cross_compiling" != Xyes; then
                    UACME_LIBRARY_PATH="$UACME_LIBRARY_PATH:$gtlslib"
                    export UACME_LIBRARY_PATH
                    AC_MSG_NOTICE([Added $gtlslib to UACME_LIBRARY_PATH])
                fi
            fi
        fi
    fi
fi

if test X"$OPT_MBEDTLS" != Xno; then
    if test X"$OPT_MBEDTLS" = Xyes; then
        OPT_MBEDTLS=""
    fi
    if test -z "$OPT_MBEDTLS" ; then
        AC_CHECK_LIB(mbedtls, mbedtls_entropy_init,
                     [AC_DEFINE(USE_MBEDTLS, 1, [if mbedTLS is enabled])
                      AC_SUBST(USE_MBEDTLS, [1])
                      MBEDTLS_ENABLED=1
                      USE_MBEDTLS="yes"],
                     [], -lmbedtls -lmbedx509 -lmbedcrypto)
    fi
    addld=""
    addlib=""
    addcflags=""
    mbedtlslib=""
    if test X"$USE_MBEDTLS" != Xyes; then
        addld=-L$OPT_MBEDTLS/lib$libsuff
        addcflags=-I$OPT_MBEDTLS/include
        mbedtlslib=$OPT_MBEDTLS/lib$libsuff
        LDFLAGS="$LDFLAGS $addld"
        if test "$addcflags" != "-I/usr/include"; then
            CPPFLAGS="$CPPFLAGS $addcflags"
        fi
        AC_CHECK_LIB(mbedtls, mbedtls_entropy_init,
                     [AC_DEFINE(USE_MBEDTLS, 1, [if mbedTLS is enabled])
                      AC_SUBST(USE_MBEDTLS, [1])
                      MBEDTLS_ENABLED=1
                      USE_MBEDTLS="yes"],
                     [AC_MSG_ERROR([mbedtls check failed])],
                     -lmbedtls -lmbedx509 -lmbedcrypto)
    fi
    if test X"$USE_MBEDTLS" = Xyes; then
        AC_MSG_NOTICE([detected mbedTLS])
        LIBS="-lmbedtls -lmbedx509 -lmbedcrypto $LIBS"
        if test -n "$mbedtlslib"; then
            if test X"$cross_compiling" != Xyes; then
                UACME_LIBRARY_PATH="$UACME_LIBRARY_PATH:$mbedtlslib"
                export UACME_LIBRARY_PATH
                AC_MSG_NOTICE([Added $mbedtlslib to UACME_LIBRARY_PATH])
            fi
        fi
    fi
fi

AC_REVISION([m4_esyscmd_s([git describe --always])])
AC_PATH_PROG(A2X, a2x, :)
AC_PATH_PROG(ASCIIDOC, asciidoc, :)
AS_IF([test "$A2X" = :], [AC_MSG_WARN([Could not find a2x.])])
AS_IF([test "$ASCIIDOC" = :], [AC_MSG_WARN([Could not find asciidoc.])])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

