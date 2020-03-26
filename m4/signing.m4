dnl
dnl Extract out signing identifier from keychain
dnl

AC_DEFUN([KC_SIGNING],[
AC_ARG_VAR([APP_SIGNING_ID], [SHA-1 hash of application signing certificate])
AC_ARG_VAR([INSTALLER_SIGN_CN], [Common name of installer signing certificate])
AC_ARG_VAR([CODESIGN], [Path to codesign program])
AC_ARG_VAR([XCRUN], [Path to xcrun program])
AC_ARG_VAR([PRODUCTBUILD], [Path to productbuild program])
AC_PATH_PROG([SECURITY], [security], [missing])
AC_PATH_PROG([CODESIGN], [codesign], [missing])
AC_PATH_PROG([XCRUN], [xcrun], [missing])
AC_PATH_PROG([PRODUCTBUILD], [productbuild], [missing])
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
  ],[AC_MSG_RESULT([$INSTALLER_SIGN_CN"])])
], [AC_MSG_NOTICE([Using specified installer signing ID $INSTALLER_SIGN_CN])])
])dnl
