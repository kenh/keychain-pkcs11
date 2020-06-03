/*
 * Things we export from the main keychain_pkcs11 module
 */

#ifndef __KEYCHAIN_PKCS11_H__
#define __KEYCHAIN_PKCS11_H__ 1

#include <os/log.h>

extern os_log_t logsys;

/*
 * I guess the API lied; os_log_debug() REALLY can't take a const char *,
 * it has to be a string constant.  Dammit.  End the string in a "%@" to
 * print the error string.
 */

#define LOG_SEC_ERR(fmt, errnum) \
do { \
	CFStringRef errstr = SecCopyErrorMessageString(errnum, NULL); \
	os_log_debug(logsys, fmt, errstr); \
	CFRelease(errstr); \
} while (0)

/*
 * Log a message about a particular Core Foundation type; use this to log
 * if you get a type you aren't expecting.  Message will be logged in the
 * form:
 *
 * your log message: type
 */

extern void logtype(const char *, CFTypeRef);

/*
 * Add a token to the master slot list
 */

extern void add_token_id(CFStringRef tokendid);

/*
 * Remove a token from the master slot list
 */

extern void remove_token_id(CFStringRef tokenid);

#endif /* __KEYCHAIN_PKCS11_H__ */
