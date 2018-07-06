/*
 * Our main driver for the keychain_pkcs11 module
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <os/log.h>

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "mypkcs11.h"
#include "debug.h"

/*
 * Handling PKCS11 locking.  If we can use native locking with pthreads
 * (CKF_OS_LOCKING_OK) then we do that.  Otherwise we use the API-suppled
 * mutex calls.
 */

typedef union {
	pthread_mutex_t pt;
	void * ck;
} kc_mutex;

static int use_mutex = 0;
static CK_RV (*createmutex)(CK_VOID_PTR_PTR) = NULL;
static CK_RV (*destroymutex)(CK_VOID_PTR) = NULL;
static CK_RV (*lockmutex)(CK_VOID_PTR) = NULL;
static CK_RV (*unlockmutex)(CK_VOID_PTR) = NULL;
#define CREATE_MUTEX(mutex) \
do { \
	int rc; \
	if (use_mutex) { \
		if (createmutex) { \
			rc = (*createmutex)(&mutex.ck); \
		} else { \
			rc = pthread_mutex_init(&mutex.pt, NULL); \
		} \
		if (rc) { \
			os_log_debug(logsys, "create_mutex returned %d", rc); \
		} \
	} \
} while (0)
#define DESTROY_MUTEX(mutex) \
do { \
	int rc; \
	if (use_mutex) { \
		if (destroymutex) { \
			rc = (*destroymutex)(&mutex.ck); \
		} else { \
			rc = pthread_mutex_destroy(&mutex.pt, NULL); \
		} \
		if (rc) { \
			os_log_debug(logsys, "destroy_mutex returned %d", rc); \
		} \
	} \
} while (0)
#define LOCK_MUTEX(mutex) \
do { \
	int rc; \
	if (use_mutex) { \
		if (lockmutex) { \
			rc = (*lockmutex)(&mutex.ck); \
		} else { \
			rc = pthread_mutex_lock(&mutex.pt); \
		} \
		if (rc) { \
			os_log_debug(logsys, "lock_mutex returned %d", rc); \
		} \
	} \
} while (0)
#define UNLOCK_MUTEX(mutex) \
do { \
	int rc; \
	if (use_mutex) { \
		if (unlockmutex) { \
			rc = (*unlockmutex)(&mutex.ck); \
		} else { \
			rc = pthread_mutex_unlock(&mutex.pt, NULL); \
		} \
		if (rc) { \
			os_log_debug(logsys, "unlock_mutex returned %d", rc); \
		} \
	} \
} while (0)


static kc_mutex slot_mutex;
/*
 * Stuff required for logging; we're using the MacOS X native os_log
 * facility.  To get logs out of this, see log(1).  Specifically, if you
 * want debugging logs, try:
 *
 * log stream --predicate 'subsystem = "mil.navy.nrl.cmf.pkcs11"' --level debug
 */

static void log_init(void);
static os_log_t logsys;
static pthread_once_t loginit = PTHREAD_ONCE_INIT;
#define LOGINIT() pthread_once(&loginit, log_init)

/*
 * Declarations for our list of exported PKCS11 functions that we return
 * using C_GetFunctionList()
 */

static CK_FUNCTION_LIST function_list = {
	{ 2, 40 },	/* We support 2.40 of PKCS#11 */
	/* This seems strange to me, but I guess it's what everyone else does */
#undef CK_PKCS11_FUNCTION_INFO
#define CK_PKCS11_FUNCTION_INFO(name) name ,
#include "pkcs11f.h"
};
#undef CK_PKCS11_FUNCTION_INFO

#define NOTSUPPORTED(name, args) \
CK_RV name args { \
	LOGINIT(); \
	os_log_debug(logsys, "Function " #name " called (NOT SUPPORTED!)"); \
	return CKR_FUNCTION_NOT_SUPPORTED; \
}

/*
 * Our implementation of C_GetFunctionList(), which just returns a pointer
 * to our function list
 */

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pPtr)
{
	LOGINIT();

	if (! pPtr) {
		os_log_debug(logsys, "C_GetFunctionList called (bad arguments)");
		return CKR_ARGUMENTS_BAD;
	}

	*pPtr = &function_list;

	os_log_debug(logsys, "C_GetFunctionList called (successful)");

	return CKR_OK;
}

/*
 * These are in PKCS11 order, to make searching easier
 */

CK_RV C_Initialize(CK_VOID_PTR p)
{
	CK_C_INITIALIZE_ARGS_PTR init = (CK_C_INITIALIZE_ARGS_PTR) p;

	LOGINIT();
	os_log_debug(logsys, "C_Initialize called");

	if (init) {
		if (init->pReserved) {
			os_log_debug(logsys, "pReserved set, returning");
			return CKR_ARGUMENTS_BAD;
		}
		if (init->flags & CKF_OS_LOCKING_OK) {
			use_mutex = 1;
			os_log_debug(logsys, "OS_LOCKING_OK set, using "
				     "pthread locking");
		} else if (init->CreateMutex || init->DestroyMutex ||
			   init->LockMutex || init->UnlockMutex) {
			use_mutex = 1;
			createmutex = init->CreateMutex;
			destroymutex = init->DestroyMutex;
			lockmutex = init->LockMutex;
			unlockmutex = init->UnlockMutex;
			os_log_debug(logsys, "Using caller-supplied locking "
				     "functions");
		} else {
			use_mutex = 0;
			os_log_debug(logsys, "Not performing any locking");
		}
	} else {
		os_log_debug(logsys, "init was set to NULL");
	}

	if (use_mutex)
		CREATE_MUTEX(slot_mutex);

	return CKR_OK;
}

NOTSUPPORTED(C_Finalize, (CK_VOID_PTR p))
NOTSUPPORTED(C_GetInfo, (CK_INFO_PTR p))
/* C_GetFunctionList declared above */
NOTSUPPORTED(C_GetSlotList, (CK_BBOOL token_present, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR slot_num))
NOTSUPPORTED(C_GetSlotInfo, (CK_SLOT_ID slot_id, CK_SLOT_INFO_PTR slot_info))
NOTSUPPORTED(C_GetTokenInfo, (CK_SLOT_ID slot_id, CK_TOKEN_INFO_PTR token_info))
NOTSUPPORTED(C_GetMechanismList, (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE_PTR mechlist, CK_ULONG_PTR mechnum))
NOTSUPPORTED(C_GetMechanismInfo, (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE mechtype, CK_MECHANISM_INFO_PTR mechinfo))
NOTSUPPORTED(C_InitToken, (CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen, CK_UTF8CHAR_PTR label))
NOTSUPPORTED(C_InitPIN, (CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen))
NOTSUPPORTED(C_SetPIN, (CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR oldpin, CK_ULONG oldpinlen, CK_UTF8CHAR_PTR newpin, CK_ULONG newpinlen))
NOTSUPPORTED(C_OpenSession, (CK_SLOT_ID slot_id, CK_FLAGS flags, CK_VOID_PTR app_callback, CK_NOTIFY notify_callback, CK_SESSION_HANDLE_PTR session))
NOTSUPPORTED(C_CloseSession, (CK_SESSION_HANDLE session))
NOTSUPPORTED(C_CloseAllSessions, (CK_SLOT_ID slot_id))
NOTSUPPORTED(C_GetSessionInfo, (CK_SESSION_HANDLE session, CK_SESSION_INFO_PTR session_info))
NOTSUPPORTED(C_GetOperationState, (CK_SESSION_HANDLE session, CK_BYTE_PTR opstate, CK_ULONG_PTR opstatelen))
NOTSUPPORTED(C_SetOperationState, (CK_SESSION_HANDLE session, CK_BYTE_PTR opstate, CK_ULONG opstatelen, CK_OBJECT_HANDLE enckey, CK_OBJECT_HANDLE authkey))
NOTSUPPORTED(C_Login, (CK_SESSION_HANDLE session, CK_USER_TYPE usertype, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen))
NOTSUPPORTED(C_Logout, (CK_SESSION_HANDLE session))
NOTSUPPORTED(C_CreateObject, (CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template, CK_ULONG num_attributes, CK_OBJECT_HANDLE_PTR object))
NOTSUPPORTED(C_CopyObject, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG num_attributes, CK_OBJECT_HANDLE_PTR new_object))
NOTSUPPORTED(C_DestroyObject, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object))
NOTSUPPORTED(C_GetObjectSize, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ULONG_PTR size))
NOTSUPPORTED(C_GetAttributeValue, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG count))
NOTSUPPORTED(C_SetAttributeValue, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG count))
NOTSUPPORTED(C_FindObjectsInit, (CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template, CK_ULONG count))
NOTSUPPORTED(C_FindObjects, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR object, CK_ULONG maxcount, CK_ULONG_PTR count))
NOTSUPPORTED(C_FindObjectsFinal, (CK_SESSION_HANDLE session))
NOTSUPPORTED(C_EncryptInit, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key))
NOTSUPPORTED(C_Encrypt, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen, CK_BYTE_PTR outdata, CK_ULONG_PTR outdatalen))
NOTSUPPORTED(C_EncryptUpdate, (CK_SESSION_HANDLE session, CK_BYTE_PTR inpart, CK_ULONG inpartlen, CK_BYTE_PTR outpart, CK_ULONG_PTR outpartlen))
NOTSUPPORTED(C_EncryptFinal, (CK_SESSION_HANDLE session, CK_BYTE_PTR lastpart, CK_ULONG_PTR lastpartlen))
NOTSUPPORTED(C_DecryptInit, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key))
NOTSUPPORTED(C_Decrypt, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen, CK_BYTE_PTR outdata, CK_ULONG_PTR outdatalen))
NOTSUPPORTED(C_DecryptUpdate, (CK_SESSION_HANDLE session, CK_BYTE_PTR inpart, CK_ULONG inpartlen, CK_BYTE_PTR outpart, CK_ULONG_PTR outpartlen))
NOTSUPPORTED(C_DecryptFinal, (CK_SESSION_HANDLE session, CK_BYTE_PTR lastpart, CK_ULONG_PTR lastpartlen))
NOTSUPPORTED(C_DigestInit, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech))
NOTSUPPORTED(C_Digest, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen, CK_BYTE_PTR digest, CK_ULONG_PTR digestlen))
NOTSUPPORTED(C_DigestUpdate, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen))
NOTSUPPORTED(C_DigestKey, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key))
NOTSUPPORTED(C_DigestFinal, (CK_SESSION_HANDLE session, CK_BYTE_PTR digest, CK_ULONG_PTR digestlen))
NOTSUPPORTED(C_SignInit, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key))
NOTSUPPORTED(C_Sign, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen))
NOTSUPPORTED(C_SignUpdate, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen))
NOTSUPPORTED(C_SignFinal, (CK_SESSION_HANDLE session, CK_BYTE_PTR sig, CK_ULONG_PTR siglen))
NOTSUPPORTED(C_SignRecoverInit, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key))
NOTSUPPORTED(C_SignRecover, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen))
NOTSUPPORTED(C_VerifyInit, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key))
NOTSUPPORTED(C_Verify, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen, CK_BYTE_PTR sig, CK_ULONG siglen))
NOTSUPPORTED(C_VerifyUpdate, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen))
NOTSUPPORTED(C_VerifyFinal, (CK_SESSION_HANDLE session, CK_BYTE_PTR sig, CK_ULONG siglen))
NOTSUPPORTED(C_VerifyRecoverInit, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key))
NOTSUPPORTED(C_VerifyRecover, (CK_SESSION_HANDLE session, CK_BYTE_PTR sig, CK_ULONG siglen, CK_BYTE_PTR outdata, CK_ULONG_PTR outdatalen))
NOTSUPPORTED(C_DigestEncryptUpdate, (CK_SESSION_HANDLE session, CK_BYTE_PTR inpart, CK_ULONG inpartlen, CK_BYTE_PTR outdata, CK_ULONG_PTR outdatalen))
NOTSUPPORTED(C_DecryptDigestUpdate, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen, CK_BYTE_PTR outdata, CK_ULONG_PTR outdatalen))
NOTSUPPORTED(C_SignEncryptUpdate, (CK_SESSION_HANDLE session, CK_BYTE_PTR inpart, CK_ULONG inpartlen, CK_BYTE_PTR outdata, CK_ULONG_PTR outdatalen))
NOTSUPPORTED(C_DecryptVerifyUpdate, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen, CK_BYTE_PTR outdata, CK_ULONG_PTR outdatalen))
NOTSUPPORTED(C_GenerateKey, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key))
NOTSUPPORTED(C_GenerateKeyPair, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR pub_template, CK_ULONG pub_count, CK_ATTRIBUTE_PTR priv_template, CK_ULONG priv_count, CK_OBJECT_HANDLE_PTR pubkey, CK_OBJECT_HANDLE_PTR privkey))
NOTSUPPORTED(C_WrapKey, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE wrapkey, CK_OBJECT_HANDLE key, CK_BYTE_PTR outkey, CK_ULONG_PTR outkeylen));
NOTSUPPORTED(C_UnwrapKey, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE unwrapkey, CK_BYTE_PTR wrappedkey, CK_ULONG wrappedkeylen, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR outkey))
NOTSUPPORTED(C_DeriveKey, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE basekey, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR outkey))
NOTSUPPORTED(C_SeedRandom, (CK_SESSION_HANDLE session, CK_BYTE_PTR seed, CK_ULONG seedlen))
NOTSUPPORTED(C_GenerateRandom, (CK_SESSION_HANDLE session, CK_BYTE_PTR randomdata, CK_ULONG randomlen))
NOTSUPPORTED(C_GetFunctionStatus, (CK_SESSION_HANDLE session))
NOTSUPPORTED(C_CancelFunction, (CK_SESSION_HANDLE session))
NOTSUPPORTED(C_WaitForSlotEvent, (CK_SESSION_HANDLE session, CK_SLOT_ID_PTR slot_id, CK_VOID_PTR reserved))

/*
 * Make sure the our custom logging system is enabled
 */

static void log_init(void)
{
	logsys = os_log_create("mil.navy.nrl.cmf.pkcs11", "general");
}
