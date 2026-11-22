# http://mij.oltrelinux.com/devel/autoconf-automake/

bin_PROGRAMS = openfortivpn
common_sources = src/config.c src/config.h src/hdlc.c src/hdlc.h \
		       src/http.c src/http.h src/http_chunks.c src/http_chunks.h \
		       src/io.c src/io.h \
			   src/http_server.c src/ipv4.c \
		       src/ipv4.h src/log.c src/log.h src/tunnel.c \
		       src/tunnel.h src/ssl.h src/xml.c \
		       src/xml.h src/userinput.c src/userinput.h \
		       src/ipv6.c src/ipv6.h
openfortivpn_SOURCES = $(common_sources) src/main.c
openfortivpn_CPPFLAGS = -DSYSCONFDIR=\"$(sysconfdir)\" \
			-DPPP_PATH=\"@PPP_PATH@\" \
			-DNETSTAT_PATH=\"@NETSTAT_PATH@\" \
			-DRESOLVCONF_PATH=\"@RESOLVCONF_PATH@\" \
			-DREVISION=\"@REVISION@\" \
			 $(OPENSSL_CFLAGS) $(LIBSYSTEMD_CFLAGS) $(LIBXML2_CFLAGS)
openfortivpn_CFLAGS = -Wall -pedantic
openfortivpn_LDADD = $(OPENSSL_LIBS) $(LIBSYSTEMD_LIBS) $(LIBXML2_LIBS)

check_PROGRAMS = http-chunks-test http-requests-test
TESTS = $(check_PROGRAMS)
http_chunks_test_SOURCES = tests/http-chunks.c src/http_chunks.c src/http_chunks.h
http_chunks_test_CPPFLAGS = -I$(srcdir)/src

http_requests_test_SOURCES = tests/http-requests.c $(common_sources)
http_requests_test_CPPFLAGS = $(openfortivpn_CPPFLAGS) -I$(srcdir)/src \
			      -DSSL_read=test_SSL_read -DSSL_write=test_SSL_write
http_requests_test_LDADD = $(openfortivpn_LDADD)

if HAVE_IPV6_TUNNEL
check_PROGRAMS += ipv6-test
ipv6_test_SOURCES = tests/ipv6.c src/ipv6.c src/ipv6.h src/http_chunks.c src/http_chunks.h
ipv6_test_CPPFLAGS = -I$(srcdir)/src $(LIBXML2_CFLAGS)
ipv6_test_LDADD = $(LIBXML2_LIBS)
endif

PATHFILES =
CLEAN_LOCALS =
EXTRA_DIST = \
	autogen.sh \
	CHANGELOG.md \
	LICENSE \
	LICENSE.OpenSSL \
	README.md

DISTCHECK_CONFIGURE_FLAGS = \
	CFLAGS=-Werror \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

# configuration file template
datadir=$(prefix)/share/@PACKAGE@
data_DATA=etc/openfortivpn/config.template

EXTRA_DIST += $(data_DATA)

# initial configuration file
confdir=$(sysconfdir)/@PACKAGE@

etc/openfortivpn/config: $(srcdir)/etc/openfortivpn/config.template
	@$(MKDIR_P) etc/openfortivpn
	$(AM_V_GEN)$(SED) -e '/^#/n;/^\s*$$/n;s/^/# /' $(srcdir)/etc/openfortivpn/config.template >$@

install-data-hook: etc/openfortivpn/config
	if ! test -f $(DESTDIR)$(confdir)/config ; then \
		$(MKDIR_P) $(DESTDIR)$(confdir) ; \
		$(INSTALL) -m 600 etc/openfortivpn/config \
			$(DESTDIR)$(confdir)/config ; \
	fi

clean-local-config:
	-rm -f $(top_builddir)/etc/openfortivpn/config

CLEAN_LOCALS += clean-local-config

# systemd service file
PATHFILES += lib/systemd/system/openfortivpn@.service

if HAVE_SYSTEMD
lib/systemd/system/openfortivpn@.service: $(srcdir)/lib/systemd/system/openfortivpn@.service.in
	@$(MKDIR_P) lib/systemd/system
	$(AM_V_GEN)$(SED) -e 's|[@]BINDIR[@]|$(bindir)|g;s|[@]SYSCONFDIR[@]|$(sysconfdir)|g' $(srcdir)/lib/systemd/system/openfortivpn@.service.in >$@

systemdsystemunit_DATA = lib/systemd/system/openfortivpn@.service

clean-local-systemd:
	-rm -f $(top_builddir)/lib/systemd/system/openfortivpn@.service

CLEAN_LOCALS += clean-local-systemd
endif

# man page
PATHFILES += doc/openfortivpn.1
dist_man_MANS = doc/openfortivpn.1

doc/openfortivpn.1: $(srcdir)/doc/openfortivpn.1.in
	@$(MKDIR_P) doc
	$(AM_V_GEN)$(SED) -e 's|[@]SYSCONFDIR[@]|$(sysconfdir)|g;s|[@]DATADIR[@]|$(datadir)|g' $(srcdir)/doc/openfortivpn.1.in >$@

clean-local-man:
	-rm -f $(top_builddir)/doc/openfortivpn.1

CLEAN_LOCALS += clean-local-man


EXTRA_DIST += $(PATHFILES:=.in)

all-local: etc/openfortivpn/config

clean-local: $(CLEAN_LOCALS)
