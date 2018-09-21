/*
 * A list of our interfaces to talk to the LocalAuthentication Framework,
 * which only has an Objective-C interface.
 */

#ifndef __LOCALAUTH_H__
#define __LOCALAUTH_H__ 1

/*
 * The type of usage we want to authenticate for this key.
 */

enum la_keyusage {
	USAGE_SIGN,		/* Key signature */
	USAGE_DECRYPT,		/* Key decryption */
};

void *lacontext_new(void);
void lacontext_free(void *);
CK_RV lacontext_auth(void *, unsigned char *, size_t, void *, enum la_keyusage);
void lacontext_logout(void *);

#endif /* __LOCALAUTH_H__ */
