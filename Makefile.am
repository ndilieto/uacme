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

ACLOCAL_AMFLAGS=-I build-aux/m4
ARFLAGS=cr

bin_PROGRAMS = uacme

if ENABLE_UALPN
bin_PROGRAMS += ualpn

ualpn_SOURCES = ualpn.c base64.c base64.h log.c log.h sglib.h
ualpn_CPPFLAGS = -DRUNSTATEDIR="\"${runstatedir}\""
		 -DSYSCONFDIR="\"${sysconfdir}\""
ualpn_CFLAGS = $(WCFLAGS)
if ENABLE_LIBEV
ualpn_SOURCES += libev/ev.h
ualpn_CPPFLAGS += -Ilibev
ualpn_LDADD = libev.a $(UALPN_LDADD)

noinst_LIBRARIES = libev.a
libev_a_SOURCES = libev/ev.c
else
ualpn_LDADD = $(UALPN_LDADD)
endif
endif

uacme_SOURCES = uacme.c base64.c base64.h crypto.c crypto.h \
		curlwrap.c curlwrap.h json.c json.h jsmn.h \
		msg.c msg.h
uacme_CPPFLAGS = -DRUNSTATEDIR="\"${runstatedir}\"" \
		 -DSYSCONFDIR="\"${sysconfdir}\"" \
		 $(CURL_CPPFLAGS)
uacme_CFLAGS = $(CURL_CFLAGS) $(WCFLAGS)
uacme_LDFLAGS = $(CURL_LDFLAGS)
uacme_LDADD = $(CURL_LDADD)

if ENABLE_READFILE
uacme_SOURCES += read-file.c read-file.h
endif

BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@

dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version

dist_pkgdata_SCRIPTS = uacme.sh nsupdate.sh
if ENABLE_UALPN
dist_pkgdata_SCRIPTS += ualpn.sh
endif

if ENABLE_DOCS
dist_man1_MANS = uacme.1
dist_html_DATA = docs/uacme.html

if ENABLE_UALPN
dist_man1_MANS += ualpn.1
dist_html_DATA += docs/ualpn.html

ualpn.1: ualpn.1.txt $(top_srcdir)/.version
	$(AM_V_GEN)$(A2X) -L -d manpage -f manpage \
	    -a revision=$(VERSION) \
	    -a sysconfdir="${sysconfdir}" \
	    -a runstatedir="${runstatedir}" $<

docs/ualpn.html: ualpn.1.txt $(top_srcdir)/.version
	$(AM_V_GEN)$(ASCIIDOC) -d manpage -b html5 -o $@ \
	    -a revision=$(VERSION) \
	    -a sysconfdir="${sysconfdir}" \
	    -a runstatedir="${runstatedir}" $<
endif

uacme.1: uacme.1.txt $(top_srcdir)/.version
	$(AM_V_GEN)$(A2X) -L -d manpage -f manpage \
	    -a revision=$(VERSION) \
	    -a sysconfdir="${sysconfdir}" \
	    -a runstatedir="${runstatedir}" $<

docs/uacme.html: uacme.1.txt $(top_srcdir)/.version
	$(AM_V_GEN)$(ASCIIDOC) -d manpage -b html5 -o $@ \
	    -a revision=$(VERSION) \
	    -a sysconfdir="${sysconfdir}" \
	    -a runstatedir="${runstatedir}" $<
endif

.PHONY: valgrind
valgrind: uacme
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes \
	    --num-callers=20 --track-fds=yes --log-file=valgrind.log \
	    $(builddir)/uacme $(VALGRIND_UACME_ARGS)

EXTRA_DIST = GNUmakefile build-aux/git-version-gen uacme.sh nsupdate.sh \
	     uacme.1.txt uacme.1 docs/uacme.html ualpn.1.txt ualpn.1 \
	     docs/ualpn.html libev/ev_epoll.c libev/ev_iouring.c \
	     libev/ev_kqueue.c libev/ev_linuxaio.c libev/ev_poll.c \
	     libev/ev_port.c libev/ev_select.c libev/ev_vars.h \
	     libev/ev_wrap.h README.md
CLEANFILES = valgrind.log
