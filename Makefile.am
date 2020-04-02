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
NOTARIZE_STATUS=/tmp/notarize-status
CLEANFILES=$(PACKAGE_NAME)-*.pkg
.PHONY: package product destdir package-signed package-unsigned product-signed product-unsigned notarize

PACKAGE_FLAGS = \
	--root "$(PACKAGEBUILDDIR)" \
	--identifier "$(APPIDENTIFIER)" \
	--install-location "/" \
	--version $(PACKAGE_VERSION) \
	#

PACKAGE_SIGN_FLAGS = \
	--sign "$(INSTALLER_SIGN_CN)" \
	--timestamp \
	#

## Common framework to create a DESTDIR for a package

destdir:
	rm -rf $(PACKAGEBUILDDIR)
	$(MAKE) install DESTDIR=$(PACKAGEBUILDDIR)
	rm -f $(PACKAGEBUILDDIR)$(libdir)/keychain-pkcs11.la
	if [ "$(APP_SIGNING_ID)" != "unknown" ]; then \
	  $(CODESIGN) --timestamp --sign "$(APP_SIGNING_ID)" $(PACKAGEBUILDDIR)$(libdir)/keychain-pkcs11.dylib; \
	fi

## Build a component package using pkgbuild

package: destdir
	@if [ "$(INSTALLER_SIGN_CN)" != "unknown" ]; then \
		$(MAKE) package-signed; \
	else \
		$(MAKE) package-unsigned; \
	fi

package-signed:
	$(PKGBUILD) $(PACKAGE_FLAGS) $(PACKAGE_SIGN_FLAGS) \
		$(PACKAGE_NAME)-$(PACKAGE_VERSION).pkg

package-unsigned:
	$(PKGBUILD) $(PACKAGE_FLAGS) \
		$(PACKAGE_NAME)-$(PACKAGE_VERSION).pkg

product: destdir
	$(PRODUCTBUILD) \
		--identifier "$(APPIDENTIFIER)" \
		--sign "$(INSTALLER_SIGN_CN)" \
		--timestamp \
		--root $(PACKAGEBUILDDIR) \
		--version $(PACKAGE_VERSION) \
		$(PACKAGE_NAME)-$(PACKAGE_VERSION).pkg

##
## Submit to the notarization service and wait for it to complete, then
## staple the package
##

notarize:
	@if [ "$(NOTARIZATION_ID)" = "unknown" -o "$(NOTARIZATION_PW)" = "unknown" ]; then \
		echo "NOTARIZATION_ID and NOTARIZATION_PW must be set for notarization support"; \
		exit 1; \
	fi
	rm -f $(NOTARIZE_STATUS)
	$(XCRUN) altool --notarize-app \
		-u "$(NOTARIZATION_ID)" \
		-p "$(NOTARIZATION_PW)" \
		--asc-provider "$(ASC_PROVIDER)" \
		--primary-bundle-id "$(APPIDENTIFIER)" \
		--output-format xml \
		-f $(PACKAGE_NAME)-$(PACKAGE_VERSION).pkg \
		> $(NOTARIZE_STATUS)
	@UUID=`$(PLBUDDY) -c "Print :notarization-upload:RequestUUID" $(NOTARIZE_STATUS)`; \
	  echo "Waiting for notarization status for request ID $$UUID"; \
	  while true; do \
	    $(XCRUN) altool \
		--notarization-info $$UUID \
		-u "$(NOTARIZATION_ID)" \
		-p "$(NOTARIZATION_PW)" \
		--output-format xml > $(NOTARIZE_STATUS); \
	    if [ $$? -ne 0 ]; then \
	      echo "altool failed"; \
	      exit 1; \
	    fi; \
	    STATUS=`$(PLBUDDY) -c "Print :notarization-info:Status" $(NOTARIZE_STATUS)`; \
	    if [ "$$STATUS" != "in progress" ]; then \
	      break; \
	    fi; \
	    sleep 10; \
	  done; \
	  if [ "$$STATUS" != "success" ]; then \
	    echo "Notarization failed, check $(NOTARIZE_STATUS) for more info"; \
	    echo "Log file URL is: "; \
	    $(PLBUDDY) -c "Print :notarization-info:LogFileURL" $(NOTARIZE_STATUS); \
	    exit 1; \
	  fi; \
	  echo "Notarization successful"
	$(XCRUN) stapler staple $(PACKAGE_NAME)-$(PACKAGE_VERSION).pkg
