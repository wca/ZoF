include $(top_srcdir)/config/Rules.am

# Unconditionally enable debugging for zdb
AM_CPPFLAGS += -DDEBUG -UNDEBUG

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = zdb

if BUILD_FREEBSD
zdb_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	-lgeom -L/usr/local/lib -lintl
else
zdb_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libzpool/libzpool.la
endif

zdb_SOURCES = \
	zdb.c \
	zdb_il.c \
	zdb.h


