dnl
dnl Our configure.ac template
dnl Process with autoconf (or better yet, autoreconf) to get configure
dnl

AC_PREREQ([2.68])

AC_INIT([keychain-pkcs11], [1.0], [kenh@cmf.nrl.navy.mil])
AC_CONFIG_SRCDIR([pkcs11_test.c])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects 1.12])
AM_PROG_CC_C_O
AM_PROG_AR

LT_PREREQ([2.4.6])
LT_INIT([disable-static dlopen])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
