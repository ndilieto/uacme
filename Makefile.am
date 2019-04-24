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

bin_PROGRAMS = uacme
uacme_SOURCES = uacme.c base64.c base64.h crypto.c crypto.h \
		curlwrap.c curlwrap.h json.c json.h jsmn.h \
		msg.c msg.h read-file.c read-file.h

BUILT_SOURCES = $(top_srcdir)/.version $(top_srcdir)/docs/index.html
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@

$(top_srcdir)/docs/index.html: uacme.1.html
	cp uacme.1.html $@

dist-hook:
	echo $(VERSION) > $(distdir)/.tarball-version

dist_man1_MANS = uacme.1
dist_pkgdata_SCRIPTS = uacme.sh
dist_html_DATA = uacme.1.html

uacme.1: uacme.1.txt
	$(A2X) -d manpage -f manpage $<

uacme.1.html: uacme.1.txt
	$(ASCIIDOC) -d manpage -b html5 $<

.PHONY: valgrind
valgrind: uacme
	valgrind --tool=memcheck --leak-check=yes --show-reachable=yes \
	    --num-callers=20 --track-fds=yes --log-file=valgrind.log \
	    $(builddir)/uacme $(VALGRIND_UACME_ARGS)

EXTRA_DIST = GNUmakefile build-aux/git-version-gen uacme.sh uacme.1.txt \
	     uacme.1 uacme.1.html
CLEANFILES = uacme.1 uacme.1.html valgrind.log
