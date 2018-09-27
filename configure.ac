dnl
dnl Our configure.ac template
dnl Process with autoconf (or better yet, autoreconf) to get configure
dnl

AC_PREREQ([2.68])

AC_INIT([keychain-pkcs11], [0.9], [kenh@cmf.nrl.navy.mil])
AC_CONFIG_SRCDIR([src/keychain_pkcs11.c])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects 1.14])
AC_PROG_CC([clang])
AC_PROG_OBJC([clang])
AM_PROG_AR
AC_PROG_LN_S

LT_PREREQ([2.4.6])
LT_INIT([disable-static dlopen])

AC_CHECK_FUNCS([setprogname])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADER([include/config.h])
AC_OUTPUT
