AUTOMAKE_OPTIONS=foreign subdir-objects

SUBDIRS = 
EXTRA_DIST = cmdline.ggo cmdline.patch \
linux/Makefile linux/xt_coova.c linux/xt_coova.h \
linux/ipt_coova.h linux/libxt_coova.c \
cmdline.mini.sh cmdline.mini.gen 

chilliincludedir = $(includedir)/chilli
chilliinclude_HEADERS = \
chilli.h session.h garden.h radius.h options.h \
tun.h ippool.h md5.h redir.h dhcp.h iphash.h \
radius_coovachilli.h ssl.h dns.h net.h \
pkt.h conn.h lookup.h chilli_limits.h cmdline.h debug.h \
radius_pkt.h ../bstring/bstrlib.h ../config.h system.h \
cmdsock.h

lib_LTLIBRARIES = libchilli.la
sbin_PROGRAMS = \
chilli chilli_response chilli_radconfig chilli_opt chilli_query

suid_programs =

libchilli_la_SOURCES = \
chilli.c tun.c ippool.c radius.c md5.c redir.c dhcp.c \
iphash.c lookup.c system.h util.c options.c statusfile.c conn.c sig.c \
garden.c dns.c session.c pkt.c chksum.c net.c safe.c \
sfhash.c cmdsock.c

if WITH_SSL
libchilli_la_SOURCES += ssl.c ms_chap.c
endif

chilli_SOURCES= main.c
chilli_radconfig_SOURCES = main-radconfig.c 
chilli_response_SOURCES = main-response.c 
chilli_query_SOURCES = main-query.c 
chilli_opt_SOURCES = main-opt.c cmdline.c

libchilli_la_LIBADD = $(top_builddir)/bstring/libbstring.la \
	$(top_builddir)/json/libjson.la

if WITH_OPENSSL
libchilli_la_LIBADD += ${LIBSSL}
endif

LDADD = libchilli.la ${LIBRT} $(top_builddir)/bstring/libbstring.la ${LIBJSON} \
	$(top_builddir)/json/libjson.la

if WITH_OPENSSL
LDADD += ${LIBSSL}
endif

AM_CFLAGS = -D_GNU_SOURCE -Wall -fno-builtin -fno-strict-aliasing \
  -fomit-frame-pointer -funroll-loops -pipe -I$(top_builddir)/bstring \
 -I$(top_builddir)/json \
 -DDEFCHILLICONF='"$(sysconfdir)/chilli.conf"'\
 -DDEFPIDFILE='"$(localstatedir)/run/chilli.pid"'\
 -DDEFSTATEDIR='"$(localstatedir)/run"'\
 -DSBINDIR='"$(sbindir)"' 

if WITH_NETFILTER_COOVA
SUBDIRS += linux
libchilli_la_SOURCES += kcoova.c
endif

if !HAVE_STRLCPY
libchilli_la_SOURCES += ../extern/strlcpy.c
endif

install-exec-hook:
	@for f in $(suid_programs); do \
		echo "Setting SUID on $(DESTDIR)$(sbindir)/$$f !"; \
		chown root $(DESTDIR)$(sbindir)/$$f; \
		chmod u+s $(DESTDIR)$(sbindir)/$$f; \
	done

main-opt.c: cmdline.c cmdline.h

cmdline.c cmdline.h: cmdline.ggo cmdline.patch
	cat cmdline.ggo | gengetopt -C 
	cp cmdline.c cmdline.c.orig
	patch -p0 < cmdline.patch

cmdline.mini.gen: cmdline.ggo 
	sh cmdline.mini.sh > cmdline.mini.gen

cmdline.mini.c: cmdline.mini.gen
