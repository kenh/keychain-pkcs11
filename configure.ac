dnl
dnl Our configure.ac template
dnl Process with autoconf (or better yet, autoreconf) to get configure
dnl

AC_PREREQ([2.68])

AC_INIT([keychain-pkcs11], [0.9.5], [kenh@cmf.nrl.navy.mil])
AC_CONFIG_SRCDIR([src/keychain_pkcs11.c])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects 1.14])
AC_PROG_CC([clang])
AC_PROG_OBJC([clang])
AM_PROG_AR

LT_PREREQ([2.4.6])
LT_INIT([disable-static dlopen])

AC_CHECK_FUNCS([setprogname])

default_APPIDENTIFIER="mil.navy.nrl.cmf.pkcs11"
AC_ARG_VAR([APPIDENTIFIER],
	   [Application bundle identifier of package, defaults to 'mil.navy.nrl.cmf.pkcs11'])
KC_SIGNING

: "${APPIDENTIFIER=$default_APPIDENTIFIER}"

AC_DEFINE_UNQUOTED([APPIDENTIFIER], ["$APPIDENTIFIER"],
	[Application bundle identifier of package])
AC_SUBST([APPIDENTIFIER])

AC_CONFIG_FILES([Makefile packaging/distribution.xml]
		[packaging/resources/welcome.rtf:packaging/resources/welcome-in.rtf])

AC_CONFIG_HEADER([include/config.h])
AC_OUTPUT
