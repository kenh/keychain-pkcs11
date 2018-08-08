/*
 * Functions to interface with the LAContext structures we need to use
 * to input the PIN to our tokens.
 *
 * This deserves some explanation.
 *
 * If you want to feed in the PIN/password to authenticate to the smartcard
 * (instead of letting the popup UI dialog do it for you) here's what you
 * have to do.
 *
 * - Create a new LAContext (see lacontext_new()).
 * - Attach it to the Security identity.  The way you seem to do this
 *   is search for identities and request a "persistent reference" to
 *   the identity (using kSecReturnPersistentRef).  You then again
 *   call SecItemCopyMatching(), passing in the query dictionary the
 *   persistent reference using kSecAttrPersistentRef.  At this point you
 *   ALSO pass in the LAContext you allocated above using the
 *   kSecUseAuthenticationContext key.  This will get converted internally
 *   to an ACM context in the Security framework.  What's an ACM context?
 *   I HAVE NO IDEA.  But that's part of the magic you need to do.  This
 *   bit of magic is at least hinted at in the Apple header files for
 *   the Security framework.  This happens in our code in the functions
 *   scan_identities() and add_identity() (in keychain_pkcs11.c)
 * - You need to save the Access Control object for the private key
 *   you want to authenticate to (you can get this via SecCopyKeyAttributes()
 *   and extract that reference from the dictionary using the
 *   kSecAttrAccessControl key).  The identity also has a (different)
 *   access control object, so make sure you get the one associated with
 *   the key (see getaccesscontrol(), keychain_pkcs11.c)
 * - When you actually want to SET and VERIFY the PIN with the smartcard,
 *   you first need to call the LAContext setCredential method with the PIN
 *   as the password argument AND you need to have a credential type of -3.
 *   Why -3?  I HAVE NO GODDAMN IDEA!  THAT IS ABSOLUTELY NOT DOCUMENTED
 *   ANYWHERE.  But that's what you need to do, because if you DON'T do
 *   that it doesn't work.  (How did I figure that out, you ask?  I spent
 *   a lot of time hunched over my keyboard with with lldb and
 *   ssh-keychain.dylib). Once you set the PIN, you can call the
 *   evaluateAccessControl method with the access control object you
 *   saved earlier) to verify the PIN and then you can use the various
 *   private key functions without having to re-enter the PIN again inside
 *   a UI dialog box.  This all happens in lacontext_auth().
 *
 * Seriously, Apple?  WHAT THE HELL, MAN???!?  I can forgive the whole
 * business with the LAContext and the Access Control object; that's
 * documented only a little less than anything else in the Security framework
 * and at least that interface is public.  I can even forgive you making
 * ssh-keychain.dylib erroring out unless your argv[0] is "ssh-pkcs11-helper",
 * because you obviously wanted to make ssh work with the smartcard framework
 * but didn't want to write and support a whole PKCS#11 module (which as
 * I've learned is a giant pain in the patoot) so you implemented just enough
 * to make ssh work.  But the whole business with requring the credential
 * type to be -3?  What possible motiviation is there for THAT?  What, did
 * you think you were the only person on the ENTIRE PLANET WHO MIGHT WANT
 * TO PROGRAMMATICALLY GIVE A PIN TO A SMARTCARD??!?!?
 *
 * Curse you, unnamed Apple developer who implemented that -3 abomination.
 * Curse you with the fire of thousand suns.
 *
 * I still think Apple is a net positive in the Universe, but it's things
 * like this that sometimes make me think Peggy is right about you.
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
