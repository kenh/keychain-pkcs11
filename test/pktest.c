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

#include "mypkcs11.h"

static CK_MECHANISM_TYPE mech_to_type(const char *);

int
main(int argc, char *argv[])
{
	
