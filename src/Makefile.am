distdir = ../$(PACKAGE)-$(VERSION)/src
dist_HEADERS = lstore_private.h

BUILT_SOURCES = diag.c diag.h
EXTRA_DIST = diag.txt gen-diag
CLEANFILES = $(BUILT_SOURCES) *.core
#CLEANFILES += *.in

lib_LTLIBRARIES = libmrkdb.la

nobase_include_HEADERS = mrkdb/lstore.h mrkdb/kvp.h

noinst_HEADERS =

libmrkdb_la_SOURCES = lstore.c kvp.c
nodist_libmrkdb_la_SOURCES = diag.c
if DEBUG
DEBUG_FLAGS = -g -O0 @CLANG_DEBUG@
else
DEBUG_FLAGS = -DNDEBUG -O3
endif
libmrkdb_la_CFLAGS = $(DEBUG_FLAGS) -Wall -Wextra -Werror -g -std=c99 -I$(includedir)

libmrkdb_la_LDFLAGS = -version-info 0:0:0 -lmrkcommon

SUBDIRS = . test

diag.c diag.h: diag.txt
	$(AM_V_GEN) cat diag.txt | sort -u | /bin/sh ./gen-diag mrkdb

run: all
	for i in $(bin_PROGRAMS); do if test -x ./$$i; then LD_LIBRARY_PATH=$(libdir) ./$$i; fi; done;

testrun:
	for i in $(SUBDIRS); do if test "$$i" != "."; then cd $$i && $(MAKE) testrun && cd ..; fi; done;
