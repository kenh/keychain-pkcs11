##
## Our Makefile.am template for Makefile.in (and eventually, Makefile)
##
## Process this with automake to generate Makefile.in (or better yet,
## use autoreconf)
##

## Search for Autoconf macros here
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall

lib_LTLIBRARIES = keychain-pkcs11.la
dist_man8_MANS = keychain-pkcs11.man
check_PROGRAMS = pkcs11_test

keychain_pkcs11_la_SOURCES = \
			keychain_pkcs11.c \
			keychain_pkcs11.h \
			debug.c \
			debug.h \
			tables.c \
			tables.h \
			localauth.m \
			localauth.h \
			certutil.c \
			certutil.h \
			mypkcs11.h \
			pkcs11.h \
			pkcs11f.h \
			pkcs11n.h \
			pkcs11t.h \
			#

keychain_pkcs11_la_LDFLAGS = \
			-module \
			-avoid-version \
			-export-symbols-regex '^C_' \
			-framework Security \
			-framework LocalAuthentication \
			#
##
## For reasons I do not understand, on MacOS X libtool creates a ".so"
## file if you specify -module, instead of a .dylib.  Create a symbolic
## link in the installation directory so programs that want a .dylib will
## work

install-exec-hook:
	cd $(DESTDIR)$(libdir) && \
		rm -f keychain-pkcs11.dylib && \
		$(LN_S) keychain-pkcs11.so keychain-pkcs11.dylib

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/keychain-pkcs11.dylib

##
## Sources for our test program; only built by "make check"
##

pkcs11_test_SOURCES = pkcs11_test.c pkcs11_test.h debug.c debug.h

##
## We add this here so debug.c will be compiled with a different object
## name and not conflict with the use of debug.c in the shared library.
##
pkcs11_test_CFLAGS = $(AM_CFLAGS)

##
## Extra files that need to appear in our distribution that Automake won't
## include by default
##

EXTRA_DIST = README.md
