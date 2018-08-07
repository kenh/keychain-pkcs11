/*
 * Functions to interface with the LAContext structures we need to use
 * to input the PIN to our tokens.
 */

#import <LocalAuthentication/LocalAuthentication.h>

#include <os/log.h>

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

bool
lacontext_auth(void *l, unsigned char *bytes, size_t len, void *sec)
{
	LAContext *lac = (LAContext *) l;
	NSData *password = [NSData dataWithBytes:bytes length: len];
	SecAccessControlRef secaccess = sec;
	__block BOOL b;
	__block NSError *e_ref = NULL;
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);

	b = [lac setCredential: password
#if 0
				type: LACredentialTypeApplicationPassword];
#endif
				type: -3];

	[password release];

	if (b != TRUE)
		return false;

#if 0
	lac.interactionNotAllowed = TRUE;
#endif

	[lac evaluateAccessControl: secaccess
			operation: LAAccessControlOperationUseKeySign
			localizedReason: @"Requesting key access"
			reply: ^(BOOL success, NSError *err) {
				b = success;
				if (! success)
					e_ref = err;
				dispatch_semaphore_signal(sema);
			}];

	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
	dispatch_release(sema);

	return b == YES ? true : false;
}
