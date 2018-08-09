/*
 * A list of our interfaces to talk to the LocalAuthentication Framework,
 * which only has an Objective-C interface.
 */

#ifndef __LOCALAUTH_H__
#define __LOCALAUTH_H__ 1

void *lacontext_new(void);
void lacontext_free(void *);
CK_RV lacontext_auth(void *, unsigned char *, size_t, void *);
void lacontext_logout(void *);

extern os_log_t logsys;

#endif /* __LOCALAUTH_H__ */
