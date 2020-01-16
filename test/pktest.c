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
#include "debug.h"

static CK_MECHANISM_TYPE mech_to_type(const char *);
static void usage(const char *);
static char *default_library = ".libs/keychain-pkcs11.dylib";

#define CHECKRV(func) \
	do { \
		if (rv != CKR_OK) { \
			fprintf(stderr, "Call to " #func " failed: %s\n", \
				getCKRName(rv)); \
			goto out; \
		} \
	} while (0)

#define STR(x) stringify(x, sizeof(x))

struct flags {
	const char *name;
	CK_FLAGS value;
};

#define FV(name) { #name, name }
static struct flags slotflags[] = {
	FV(CKF_TOKEN_PRESENT),
	FV(CKF_REMOVABLE_DEVICE),
	FV(CKF_HW_SLOT),
	{ NULL, 0 }
};

static void flags_dump(struct flags *, CK_FLAGS);

enum cmd { NOCOMMAND, LISTSLOTS };

struct cmdlist {
	int		command;
	struct cmdlist	*next;
};

static void add_command(struct cmdlist **, struct cmdlist **, int);

int
main(int argc, char *argv[])
{
	int c;
	char *library = default_library, *end;
	void *handle;
	int list_private = 0;
	int list_public = 0;
	int slot_given = 0;
	int token_present = 0;
	int i;
	bool initialized = false;
	int nextcmd = NOCOMMAND;
	CK_FUNCTION_LIST_PTR p11;
	CK_SLOT_ID slot;
	CK_RV (*getflist)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
	CK_RV rv = CKR_OK;
	CK_ULONG count;
	CK_SLOT_ID *slotlist;
	CK_SLOT_INFO slotinfo;
	struct cmdlist *cmdhead = NULL, *cmdtail = NULL, *ccmd;

	struct option longopts[] = {
		{ "library",	required_argument, NULL, 'l' },
		{ "list-private", no_argument,	&list_private, 1 },
		{ "list-public", no_argument,	&list_public, 1 },
		{ "present",	no_argument,	&token_present, 1 },
		{ "not-present", no_argument,	&token_present, 0 },
		{ "slot",	required_argument, NULL, 's' },
		{ "no-slot",	no_argument,	&slot_given, 0 },
		{ "list-slots",	no_argument,	&nextcmd, LISTSLOTS },
		{ NULL, 0, NULL, 0 }
	};

	while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (c) {
		case 'l':
			library = optarg;
			break;
		case 's':
			slot = strtol(optarg, &end, 10);
			if (*optarg != '\0' && *end != '\0') {
				fprintf(stderr, "Invalid slot: %s\n", optarg);
				exit(1);
			}
			slot_given = 1;
			break;

		case '?':
			usage(argv[0]);
			break;
		case 0:
			if (nextcmd != NOCOMMAND) {
				add_command(&cmdhead, &cmdtail, nextcmd);
				nextcmd = NOCOMMAND;
			}
			break;
		default:
			printf("Option: %c\n", c);
			break;
		}
	}

	if (! cmdhead) {
		fprintf(stderr, "No command given\n");
		exit(1);
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

	CHECKRV(GetFunctionList);

	rv = p11->C_Initialize(NULL);

	CHECKRV(C_Initialize);

while ((ccmd = cmdhead)) {
	switch (ccmd->command) {
	case LISTSLOTS:
		/*
		 * We don't care if a slot was given or not.
		 */

		rv = p11->C_GetSlotList(token_present, NULL, &count);

		CHECKRV(C_GetSlotList);

		slotlist = malloc(sizeof(*slotlist) * count);

		rv = p11->C_GetSlotList(token_present, slotlist, &count);

		CHECKRV(C_GetSlotList);

		printf("%lu slots found\n", count);
		for (i = 0; i < count; i++) {
			rv = p11->C_GetSlotInfo(slotlist[i], &slotinfo);
			CHECKRV(C_GetSlotInfo);
			printf("Slot %lu:\n", slotlist[i]);
			printf("Slot Description: %s\n",
			       STR(slotinfo.slotDescription));
			printf("Slot Manufacturer: %s\n",
			        STR(slotinfo.manufacturerID));
			printf("Slot flags: ");
			flags_dump(slotflags, slotinfo.flags);
			printf("\n");
		}
		break;
	}

	cmdhead = cmdhead->next;
	free(ccmd);
}
out:
	if (initialized)
		p11->C_Finalize(NULL);

	dlclose(handle);

	exit(rv == CKR_OK ? 0 : 1);
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

static void
add_command(struct cmdlist **head, struct cmdlist **tail, int command)
{
	struct cmdlist *cmdentry = malloc(sizeof(*cmdentry));

	cmdentry->command = command;
	cmdentry->next = NULL;

	if (! *head) {
		*head = cmdentry;
		*tail = cmdentry;
	} else {
		(*tail)->next = cmdentry;
		*tail = cmdentry;
	}
}

static void
flags_dump(struct flags *flagmap, CK_FLAGS flags){
	int i;
	bool hit = false;

	for (i = 0; flagmap[i].name != NULL; i++) {
		if (flags & flagmap[i].value) {
			printf("%s%s", hit ? "|" : "", flagmap[i].name);
			hit = true;
		}
	}
}
