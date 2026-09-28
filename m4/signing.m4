dnl
dnl Extract out signing identifier from keychain
dnl
dnl Note the use of autoconf quadragraphs in the sed expression to
dnl determine the ASC provider
dnl

AC_DEFUN([KC_SIGNING],[
AC_ARG_VAR([APP_SIGNING_ID], [SHA-1 hash of application signing certificate])
AC_ARG_VAR([INSTALLER_SIGN_CN], [Common name of installer signing certificate])
AC_ARG_VAR([ASC_PROVIDER], ["Short name" of provider to use])
AC_ARG_VAR([NOTARIZATION_ID], [Userid to use for notarization])
AC_ARG_VAR([NOTARIZATION_PW], [Password to use for notarization, see altool(1) for details])
AC_ARG_VAR([CODESIGN], [Path to codesign program])
AC_ARG_VAR([XCRUN], [Path to xcrun program])
AC_ARG_VAR([PKGBUILD], [Path to pkgbuild program])
AC_ARG_VAR([PRODUCTBUILD], [Path to productbuild program])
AC_ARG_VAR([PLBUDDY], [Path to PlistBuddy program])
AC_PATH_PROG([SECURITY], [security], [missing])
AC_PATH_PROG([CODESIGN], [codesign], [missing])
AC_PATH_PROG([XCRUN], [xcrun], [missing])
AC_PATH_PROG([PRODUCTBUILD], [productbuild], [missing])
AC_PATH_PROG([PRODUCTSIGN], [productsign], [missing])
AC_PATH_PROG([PKGBUILD], [pkgbuild], [missing])
AC_PATH_PROG([PLBUDDY], [PlistBuddy], [missing],
	     [/usr/libexec$PATH_SEPARATOR$PATH])
AC_PROG_AWK
AC_PROG_SED
AC_PROG_GREP
AS_IF([test -z "$APP_SIGNING_ID"],[
  AC_MSG_CHECKING([for application developer certificate in keychain])
  APP_SIGNING_ID=`${SECURITY} find-certificate -Z -c "Developer ID Application:" | ${GREP} 'SHA-1' | ${AWK} 'NF { print $NF }'`
  AS_IF([test -z "$APP_SIGNING_ID"],[
    AC_MSG_RESULT([not found, disabling application code signing])
    APP_SIGNING_ID="unknown"
  ],[AC_MSG_RESULT([$APP_SIGNING_ID])])
], [AC_MSG_NOTICE([Using specified application signing ID $APP_SIGNING_ID])])
AS_IF([test -z "$INSTALLER_SIGN_CN"],[
  AC_MSG_CHECKING([for installer developer certificate in keychain])
  INSTALLER_SIGN_CN=`${SECURITY} find-certificate -Z -c "Developer ID Installer:" | ${GREP} '"alis"<blob>=' | ${SED} -e 's/.*="\(.*\)"$/\1/'`
  AS_IF([test -z "$INSTALLER_SIGN_CN"],[
    AC_MSG_RESULT([not found, disabling installer signing])
    INSTALLER_SIGN_CN="unknown"
  ],[AC_MSG_RESULT([$INSTALLER_SIGN_CN])])
], [AC_MSG_NOTICE([Using specified installer signing ID $INSTALLER_SIGN_CN])])
AS_IF([test -z "$ASC_PROVIDER"],[
  AS_IF([test "$INSTALLER_SIGN_CN" != "unknown"],[
    AC_MSG_CHECKING([For ASC provider in signing certificate])
    ASC_PROVIDER=`AS_ECHO(["$INSTALLER_SIGN_CN"]) | ${SED} -e 's/.*(\(@<:@A-Za-z0-9@:>@*\))$/\1/'`
    AS_IF([test "$ASC_PROVIDER" = "$INSTALLER_SIGN_CN"],[
      AC_MSG_ERROR([not found, specify manually])])
    AC_MSG_RESULT([$ASC_PROVIDER])
  ])
],[AC_MSG_NOTICE([Using specified team identifier $ASC_PROVIDER])])
AS_IF([test -z "$NOTARIZATION_ID"],[
  AC_MSG_NOTICE([No NOTARIZATION_ID given, disabling notarization])
  NOTARIZATION_ID="unknown"
  NOTARIZATION_PW="unknown"])
AS_IF([test -z "$NOTARIZATION_PW"],[
  AC_MSG_NOTICE([No NOTARIZATION_PW given, disabling notarization])
  NOTARIZATION_ID="unknown"
  NOTARIZATION_PW="unknown"])
])dnl
