/*
 * Functions to interface with the LAContext structures we need to use
 * to input the PIN to our tokens.
 */

#import <LocalAuthentication/LocalAuthentication.h>

#include "localauth.h"

/*
 * Allocate and return a new LAContext
 */

void *
lacontext_new(void)
{
	LAContext *lac = [[LAContext alloc] init];

	/*
	 * Since we are not using ARC, I believe this is correct; we
	 * should release this object when we are done.
	 *
	 * If we ever end up using ARC, then probably the thing to
	 * do is use (__bridge_retained void *)
	 */

	return lac;
}

void
lacontext_free(void *l)
{
	LAContext *lac = (LAContext *) l;

	[lac release];
}
