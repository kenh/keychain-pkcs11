/*
 * Test program for the Apple Security framework
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <os/log.h>

typedef unsigned long int CK_RV;

#include "localauth.h"

os_log_t logsys;

static void usage(const char *);
static void listitems(void);
static char *getstrcopy(CFStringRef);

static enum { ident } class = ident;

int
main(int argc, char *argv[])
{
	if (argc < 2)
		usage(argv[0]);

	if (strcmp(argv[1], "list") == 0)
		listitems();
	exit(0);
}

static void
usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s command [option [option ...]]\n", argv0);
	fprintf(stderr, "Valid commands:\n");
	fprintf(stderr, "\tlist\tList matching items (default is "
		"'ident')\n");
	exit(1);
}

static void
listitems(void)
{
	CFMutableDictionaryRef query = NULL;
	CFStringRef qclass;
	CFTypeRef result = NULL;
	int i;
	OSStatus ret;

	query = CFDictionaryCreateMutable(NULL, 0,
					  &kCFTypeDictionaryKeyCallBacks,
					  &kCFTypeDictionaryValueCallBacks);

	switch (class) {
	case ident:
		qclass = kSecClassIdentity;
		break;
	default:
		fprintf(stderr, "Internal error: class %d unknown\n", class);
		exit(1);
	}

	CFDictionaryAddValue(query, kSecClass, qclass);
//	CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
	CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll);

	ret = SecItemCopyMatching(query, &result);

	if (ret) {
		CFStringRef err = SecCopyErrorMessageString(ret, NULL);
		char *errstr = NULL;

		if (err == NULL) {
			fprintf(stderr, "SecItemCopyMatching failed %d\n", ret);
		} else {
			errstr = getstrcopy(err);
			fprintf(stderr, "SecItemCopyMatching failed: %s (%d)\n",
				errstr, ret);
		}

		if (errstr)
			free(errstr);
		if (err)
			CFRelease(err);
		goto out;
	}

	if (CFGetTypeID(result) != CFArrayGetTypeID()) {
		fprintf(stderr, "Was expecting a CFArray as query return\n");
		exit(1);
	}

	printf("%d item%s:\n", (int) CFArrayGetCount(result),
	       CFArrayGetCount(result) != 1 ? "s" : "");
	for (i = 0; i < CFArrayGetCount(result); i++) {
		CFTypeRef item = CFArrayGetValueAtIndex(result, i);
		CFStringRef desc = CFCopyDescription(item);
		char *descstr = getstrcopy(desc);

		printf("item %d\t- %s\n", i + 1, descstr);

		free(descstr);
		CFRelease(desc);
	}

out:
	if (query)
		CFRelease(query);

	if (result)
		CFRelease(result);

	return;
}

static char *
getstrcopy(CFStringRef string)
{
	const char *s = CFStringGetCStringPtr(string, kCFStringEncodingUTF8);

	if (! s) {
		CFIndex len = CFStringGetLength(string);
		CFIndex size = CFStringGetMaximumSizeForEncoding(len,
						kCFStringEncodingUTF8) + 1;

		char *p = malloc(size);

		if (! CFStringGetCString(string, p, size,
					 kCFStringEncodingUTF8)) {
			free(p);
			return strdup("Unknown string");
		}

		return p;
	} else {
		return strdup(s);
	}
}
