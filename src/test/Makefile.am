AUTOMAKE_OPTIONS = foreign
CLEANFILES = *.core
#CLEANFILES += *.in

noinst_PROGRAMS=testfoo testmacros testlstore testkvp testtraversedir

distdir = ../../$(PACKAGE)-$(VERSION)/src/test
dist_HEADERS = unittest.h

BUILT_SOURCES = ../diag.c ../diag.h

if DEBUG
DEBUG_FLAGS = -g -O0 @CLANG_DEBUG@
#DEBUG_FLAGS = -g -O0 @CLANG_DEBUG@ -DTRRET_DEBUG
else
DEBUG_FLAGS = -DNDEBUG -O3
endif
CFLAGS = $(DEBUG_FLAGS) -Wall -Wextra -Werror -std=c99 -I.. -I$(HOME)/include
LDFLAGS += -lmrkcommon

testfoo_SOURCES = ../diag.c testfoo.c
testfoo_CFLAGS =
testfoo_LDFLAGS =

testmacros_SOURCES = ../diag.c testmacros.c
testmacros_CFLAGS =
testmacros_LDFLAGS =

testlstore_SOURCES = ../diag.c ../lstore.c testlstore.c
testlstore_CFLAGS =
testlstore_LDFLAGS =

testkvp_SOURCES = ../diag.c ../lstore.c ../kvp.c testkvp.c
testkvp_CFLAGS =
testkvp_LDFLAGS =

testtraversedir_SOURCES = ../diag.c ../lstore.c ../kvp.c testtraversedir.c
testtraversedir_CFLAGS =
testtraversedir_LDFLAGS =

../diag.c ../diag.h: ../diag.txt
	sh ../gen-diag

testrun: all
	for i in $(noinst_PROGRAMS); do if test -x ./$$i; then LD_LIBRARY_PATH=$(libdir) ./$$i; fi; done;
