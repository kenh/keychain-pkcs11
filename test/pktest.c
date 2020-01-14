/*
 * Test driver for keychain-pkcs11
 *
 * The flow of the original test program got too complicated, so I
 * decided to write a (hopefully) simpler program, or at least one
 * that is more straightforward to use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <dlfcn.h>

#include "mypkcs11.h"

static CK_MECHANISM_TYPE mech_to_type(const char *);
static void usage(const char *);
static char *default_library = ".libs/keychain-pkcs11.dylib";

int
main(int argc, char *argv[])
{
	int c;
	char *library = default_library;
	void *handle;
	int list_private = 0;
	int list_public = 0;
	CK_FUNCTION_LIST_PTR p11;
	CK_RV (*getflist)(CK_FUNCTION_LIST_PTR_PTR);
	CK_RV rv;

	struct option longopts[] = {
		{ "library",	required_argument,	NULL, 'l' },
		{ "list-private", no_argument,		&list_private, 1 },
		{ "list-public", no_argument,		&list_public, 1 },
		{ NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (c) {
		case 'l':
			library = optarg;
			break;
		case '?':
			usage(argv[0]);
			break;
		case 0:
			break;
		default:
			printf("Option: %c\n", c);
			break;
		}
	}

	if (!(handle = dlopen(library, RTLD_NOW))) {
		fprintf(stderr, "Unable to dlopen %s: %s\n", library,
			dlerror());
		exit(1);
	}

	if (!(getflist = dlsym(handle, "C_GetFunctionList"))) {
		fprintf(stderr, "Unable to resolve C_GetFunctionList: %s\n",
			dlerror());
		exit(1);
	}

	rv = (*getflist)(&p11);

	dlclose(handle);

	exit(0);
}

static void
usage(const char *argv0)
{
	printf("Usage: %s [option] [...option]\n\n", argv0);
	printf("Options are:\n");
	printf("\t--library LIBRARY\tPKCS#11 module to load\n");
	printf("\t\t\t\tDefault is %s\n", default_library);

	exit(1);
}
