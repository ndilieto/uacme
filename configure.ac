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
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AC_PROG_CC_C99
if test "x$ac_cv_prog_cc_c99" = "xno"; then
    AC_MSG_ERROR([Could not find a C99 compatible compiler])
fi
AC_CHECK_FUNCS([asprintf vasprintf], [],
               AC_MSG_ERROR([(v)asprintf not found]))
PKG_CHECK_MODULES([CURL], [libcurl >= 7.0])
PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.3])
AC_REVISION([m4_esyscmd_s([git describe --always])])
AC_PATH_PROG(A2X, a2x, :)
AC_PATH_PROG(ASCIIDOC, asciidoc, :)
AS_IF([test "$A2X" = :], [AC_MSG_WARN([Could not find a2x.])])
AS_IF([test "$ASCIIDOC" = :], [AC_MSG_WARN([Could not find asciidoc.])])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

