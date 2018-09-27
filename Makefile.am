##
## Our Makefile.am template for Makefile.in (and eventually, Makefile)
##
## Process this with automake to generate Makefile.in (or better yet,
## use autoreconf)
##

## Search for Autoconf macros here
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -Wall
AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = keychain-pkcs11.la
dist_man8_MANS = man/keychain-pkcs11.man
check_PROGRAMS = pkcs11_test

keychain_pkcs11_la_SOURCES = \
			src/keychain_pkcs11.c \
			src/debug.c \
			src/tables.c \
			src/localauth.m \
			src/certutil.c \
			include/debug.h \
			include/keychain_pkcs11.h \
			include/localauth.h \
			include/tables.h \
			include/certutil.h \
			include/mypkcs11.h \
			include/pkcs11.h \
			include/pkcs11f.h \
			include/pkcs11n.h \
			include/pkcs11t.h \
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

pkcs11_test_SOURCES = \
		test/pkcs11_test.c \
		src/debug.c \
		test/pkcs11_test.h \
		include/debug.h \
		#

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
