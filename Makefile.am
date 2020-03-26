##
## Our Makefile.am template for Makefile.in (and eventually, Makefile)
##
## Process this with automake to generate Makefile.in (or better yet,
## use autoreconf)
##

AM_CFLAGS = -Wall
AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = keychain-pkcs11.la
dist_man8_MANS = man/keychain-pkcs11.man
check_PROGRAMS = pkcs11_test pktest

keychain_pkcs11_la_SOURCES = \
			src/keychain_pkcs11.c \
			src/debug.c \
			src/tables.c \
			src/localauth.m \
			src/certutil.c \
			src/ccglue.c \
			include/debug.h \
			include/keychain_pkcs11.h \
			include/localauth.h \
			include/tables.h \
			include/certutil.h \
			include/ccglue.h \
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
			-shrext ".dylib" \
			-framework Security \
			-framework LocalAuthentication \
			#

##
## Sources for our test programs; only built by "make check"
##

pkcs11_test_SOURCES = \
		test/pkcs11_test.c \
		src/debug.c \
		test/pkcs11_test.h \
		include/debug.h \
		#

pktest_SOURCES = \
		test/pktest.c \
		src/debug.c \
		include/debug.h \
		#

##
## We add this here so debug.c will be compiled with a different object
## name and not conflict with the use of debug.c in the shared library.
##
pkcs11_test_CFLAGS = $(AM_CFLAGS)
pktest_CFLAGS = $(AM_CFLAGS)

##
## Extra files that need to appear in our distribution that Automake won't
## include by default
##

EXTRA_DIST = README.md

##
## A rule to build our distribution package
##


PACKAGEBUILDDIR=/tmp/packagebuild
CLEANFILES=$(PACKAGE_NAME)-*.pkg
.PHONY: package
package:
	rm -rf $(PACKAGEBUILDDIR)
	$(MAKE) install DESTDIR=$(PACKAGEBUILDDIR)
	rm -f $(PACKAGEBUILDDIR)$(libdir)/keychain-pkcs11.la
	$(CODESIGN) --timestamp --sign "$(APP_SIGNING_ID)" $(PACKAGEBUILDDIR)$(libdir)/keychain-pkcs11.dylib
##	pkgbuild \
##		--root "$(PACKAGEBUILDDIR)$(prefix)" \
##		--identifier "$(APPIDENTIFIER)" \
##		--install-location "$(prefix)" \
##		$(PACKAGE_NAME)-$(PACKAGE_VERSION).pkg
	productbuild \
		--identifier "$(APPIDENTIFIER)" \
		--sign "$(INSTALLER_SIGN_CN)" \
		--timestamp \
		--root $(PACKAGEBUILDDIR) \
		$(PACKAGE_NAME)-$(PACKAGE_VERSION).pkg
