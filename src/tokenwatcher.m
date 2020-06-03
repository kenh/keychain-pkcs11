/*
 * Our interface to the Token Watcher API
 *
 * Rather than relying on scanning for new or removed identities
 * using SecItemCopyMatching(), I decided to use the TkTokenWatcher
 * interface to get events for inserted or removed tokens.
 *
 * The way this works is we register a TkTokenWatcher insertion handler
 * that gets called when a new token is inserted.  In the insertion
 * handler we try to add the token to our smartcard database.  If the
 * addition is successful we then register a removal handler.
 *
 * One important note: right now testing has shown that when you register
 * an insertion handler, you get insertion handlers called for all
 * inserted smartcards *before* the call to setInsertionHandler returns.
 * We kind of depend on this behavior now, because otherwise we'd need
 * to iterate through all of the available smartcards and THEN call the
 * insertion handler function and deal with any duplicate registrations.
 * If this behavior changes, we'll have to rethink how this works.
 */

#import <CryptoTokenKit/CryptoTokenKit.h>

#include <stdio.h>
#include <stdlib.h>
#include "keychain_pkcs11.h"
#include "tokenwatcher.h"

static TKTokenWatcher *tkwatcher = NULL;

static void add_token(NSString *, TKTokenWatcher *);
static void remove_token(NSString *);

/*
 * Calling this function means that insertion handlers will be called
 * for any existing tokens.  So be sure to NOT call this with any locks
 * held.
 */

void
start_token_watcher(void)
{
	/*
	 * If we've already got a watcher instance, then just return.
	 * This shouldn't happen.
	 */

	if (tkwatcher)
		return;

	tkwatcher = [TKTokenWatcher new];

	[tkwatcher setInsertionHandler:
		^(NSString *t) { add_token(t, tkwatcher); }];

	/*
	 * By this point, all insertion handlers should be called
	 */
}

void stop_token_watcher(void)
{
	if (tkwatcher) {
		[tkwatcher release];
		tkwatcher = NULL;
	}
}

static void
add_token(NSString *tokenid, TKTokenWatcher *watcher)
{
	/*
	 * Call the main library to add the token to the slot list
	 */

	add_token_id((CFStringRef) tokenid);

	/*
	 * After we register the token, register a removal handler
	 */

	[watcher addRemovalHandler:
		^(NSString *t) { remove_token(t); } forTokenID: tokenid];
}

/*
 * Remove a token from the main library.  We shouldn't need to do anything
 * else, because the removal handler should be de-registered after we
 * are called.
 */

static void
remove_token(NSString *tokenid)
{
	remove_token_id((CFStringRef) tokenid);
}
