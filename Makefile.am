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
check_PROGRAMS = pkcs11_test

keychain_pkcs11_la_SOURCES = \
			keychain_pkcs11.c \
			mypkcs11.h \
			pkcs11.h \
			pkcs11f.h \
			pkcs11n.h \
			pkcs11t.h \
			#

keychain_pkcs11_la_LDFLAGS = -module -avoid-version -export-symbols-regex '^C_' -framework Security

pkcs11_test_SOURCES = pkcs11_test.c pkcs11_test.h debug.c debug.h

.PHONY: adebug
adebug: pkcs11_test
	cp pkcs11_test /tmp/ssh-pkcs11-helper
