/*
 * Our main driver for the keychain_pkcs11 module
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>
#include <os/log.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>

#include "mypkcs11.h"
#include "localauth.h"
#include "certutil.h"
#include "debug.h"
#include "tables.h"
#include "config.h"

/*
 * The domain we use for our application; used by log messages and preferences
 */

#define APP_DOMAIN "mil.navy.nrl.cmf.pkcs11"

/* We currently support 2.40 of Cryptoki */

#define CK_MAJOR_VERSION 2
#define CK_MINOR_VERSION 40

/* Our slot number we use */
#define KEYCHAIN_SLOT	1

/* Return CKR_SLOT_ID_INVALID if we are given anything except KEYCHAIN_SLOT */
#define CHECKSLOT(slot) \
do { \
	if (slot != KEYCHAIN_SLOT || !have_slot) { \
		os_log_debug(logsys, "Slot %lu is invalid, returning " \
			     "CKR_SLOT_ID_INVALID", slot); \
		return CKR_SLOT_ID_INVALID; \
	} \
} while (0)

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
			rc = pthread_mutex_destroy(&mutex.pt); \
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
			rc = pthread_mutex_unlock(&mutex.pt); \
		} \
		if (rc) { \
			os_log_debug(logsys, "unlock_mutex returned %d", rc); \
		} \
	} \
} while (0)

static kc_mutex id_mutex;
static kc_mutex sess_mutex;

/*
 * Our list of identities that is stored on our smartcard
 */

struct id_info {
	SecIdentityRef		ident;
	SecCertificateRef	cert;
	SecKeyRef		privkey;
	SecKeyRef		pubkey;
	CK_KEY_TYPE		keytype;
	SecAccessControlRef	secaccess;
	char *			label;
	bool			privcansign;
	bool			privcandecrypt;
	bool			pubcanverify;
	bool			pubcanencrypt;
};

static struct id_info *id_list = NULL;
static unsigned int id_list_count = 0;		/* Number of valid entries */
static unsigned int id_list_size = 0;		/* Number of alloc'd entries */
static bool id_list_init = false;
static bool have_slot = false;			/* True if we have a slot */
static bool ask_pin = false;			/* Should we ask for a PIN? */
static bool logged_in = false;			/* Are we logged into card? */
static void *lacontext = NULL;			/* LocalAuth context */

static int scan_identities(void);
static int add_identity(CFDictionaryRef);
static SecAccessControlRef getaccesscontrol(CFDictionaryRef);
static void id_list_free(void);
static CK_KEY_TYPE convert_keytype(CFNumberRef);
static void token_logout(void);

/*
 * Our object list and the functions to handle them
 *
 * The object types we support are:
 *
 * Certificates (CKO_CERTFICATE).  We only support X.509 certificates
 * Public keys (CKO_PUBLIC_KEY).
 * Private keys (CKO_PRIVATE_KEY).
 *
 * The general rule is the CKA_ID attribute for any of those should all
 * match for a given identity.  I implemented this so the CKA_ID
 * is a CK_ULONG that is an index into our identity array.  This is
 * arbitrary; we could just match on any byte string.
 *
 * Previously I had implemented each object list as part of a session, but
 * really the object space is per-token, so I changed the implementation to
 * be global (since right now the Security framework only supports one token).
 *
 * Since the object list contains pointers into the id list, we are using
 * the id mutex to lock the object list as well.
 */

struct obj_info {
	unsigned int		id_index;
	unsigned char		id_value[sizeof(CK_ULONG)];
	CK_OBJECT_CLASS		class;
	CK_ATTRIBUTE_PTR	attrs;
	unsigned int		attr_count;
	unsigned int		attr_size;
};

#define LOG_DEBUG_OBJECT(obj, se) \
	os_log_debug(logsys, "Object %lu (%s)", obj, \
		     getCKOName(se->obj_list[obj].class));

static void build_objects(int);
static void obj_free(struct obj_info **, unsigned int *, unsigned int *);

static struct obj_info *id_obj_list = NULL;	/* Identity object list */
static unsigned int id_obj_count = 0;		/* Identity object list count */
static unsigned int id_obj_size = 0;		/* Size of identity obj_list */

/*
 * Our session information.  Anything that modifies a session will need to
 * lock that particular session.  We keep an array of pointers to sessions
 * available; if we need more then reallocate the array.
 *
 * Note that "sess_mutex" is for locking the overall session array,
 * but each session also has a mutex.  Sigh.  Is this overkill?  I have
 * no idea.
 *
 * SecKeyAlgorithms are currently constant CFStringRef so we shouldn't
 * have to worry about maintaing references to it using CFRetain/CFRelease().
 */

struct session {
	kc_mutex 	mutex;			/* Session mutex */
	struct obj_info *obj_list;		/* Pointer to object list */
	unsigned int	obj_list_count;		/* Copy of object count */
	unsigned int	obj_search_index;	/* Current search index */
	CK_ATTRIBUTE_PTR search_attrs;		/* Search attributes */
	unsigned int	search_attrs_count;	/* Search attribute count */
	SecKeyAlgorithm	sig_alg;		/* Signing algorithm */
	SecKeyRef	sig_key;		/* Key for signing */
	size_t		sig_size;		/* Size of sig, 0 is unknown */
	SecKeyAlgorithm ver_alg;		/* Verify algorithm */
	SecKeyRef	ver_key;		/* Verify key */
};

static struct session **sess_list = NULL;	/* Yes, array of pointers */
static unsigned int sess_list_count = 0;
static unsigned int sess_list_size = 0;
static void sess_free(struct session *);
static void sess_list_free(void);

/*
 * Return CKR_SESSION_HANDLE_INVALID if we don't have a valid session
 * for this handle
 */

#define CHECKSESSION(session, var) \
do { \
	LOCK_MUTEX(sess_mutex); \
	session--; \
	if (session > sess_list_count || sess_list[session] == NULL) { \
		os_log_debug(logsys, "Session handle %lu is invalid, " \
			     "returning CKR_SESSION_HANDLE_INVALID", session); \
		UNLOCK_MUTEX(sess_mutex); \
		return CKR_SESSION_HANDLE_INVALID; \
	} \
	var = sess_list[session]; \
	UNLOCK_MUTEX(sess_mutex); \
} while (0)
/*
 * Our attribute list used for searching
 */

static bool search_object(struct obj_info *, CK_ATTRIBUTE_PTR, unsigned int);
static CK_ATTRIBUTE_PTR find_attribute(struct obj_info *, CK_ATTRIBUTE_TYPE);
static void dump_attribute(const char *, CK_ATTRIBUTE_PTR);

/*
 * Various other utility functions we need
 */

static void sprintfpad(unsigned char *, size_t, const char *, ...);
static void logtype(const char *, CFTypeRef);
static bool boolfromdict(const char *, CFDictionaryRef, CFTypeRef);
static char *getstrcopy(CFStringRef);
static bool prefkey_found(const char *, const char *);
#ifdef KEYCHAIN_DEBUG
void dumpdict(const char *, CFDictionaryRef);
#endif /* KEYCHAIN_DEBUG */

/*
 * Stuff required for logging; we're using the MacOS X native os_log
 * facility.  To get logs out of this, see log(1).  Specifically, if you
 * want debugging logs, try:
 *
 * log stream --predicate 'subsystem = "mil.navy.nrl.cmf.pkcs11"' --level debug
 */

static void log_init(void *);
os_log_t logsys;
static dispatch_once_t loginit;

/*
 * I guess the API lied; os_log_debug() REALLY can't take a const char *,
 * it has to be a string constant.  Dammit.  End the string in a "%@" to
 * print the error string.
 */

#define LOG_SEC_ERR(fmt, errnum) \
do { \
	CFStringRef errstr = SecCopyErrorMessageString(errnum, NULL); \
	os_log_debug(logsys, fmt, errstr); \
	CFRelease(errstr); \
} while (0)

/*
 * Declarations for our list of exported PKCS11 functions that we return
 * using C_GetFunctionList()
 */

static CK_FUNCTION_LIST function_list = {
	{ CK_MAJOR_VERSION, CK_MINOR_VERSION },
	/* This seems strange to me, but I guess it's what everyone else does */
#undef CK_PKCS11_FUNCTION_INFO
#define CK_PKCS11_FUNCTION_INFO(name) name ,
#include "pkcs11f.h"
};
#undef CK_PKCS11_FUNCTION_INFO

/*
 * Some convenience functions we use for things we have to continually do
 */

#define FUNCINIT(func) \
do { \
	dispatch_once_f(&loginit, NULL, log_init); \
	os_log_debug(logsys, #func " called"); \
} while (0)

#define FUNCINITCHK(func) \
	FUNCINIT(func); \
do { \
	if (! initialized) { \
		os_log_debug(logsys, #func " returning NOT_INITIALIZED"); \
		return CKR_CRYPTOKI_NOT_INITIALIZED; \
	} \
} while (0)

#define NOTSUPPORTED(name, args) \
CK_RV name args { \
	FUNCINITCHK(name); \
	os_log_debug(logsys, "Function " #name " returning NOT SUPPORTED!"); \
	return CKR_FUNCTION_NOT_SUPPORTED; \
}

#define RET(name, val) \
do { \
	os_log_debug(logsys, #name " returning %s", getCKRName(val)); \
	return val; \
} while (0)

static int initialized = 0;

/*
 * Our implementation of C_GetFunctionList(), which just returns a pointer
 * to our function list
 */

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pPtr)
{
	FUNCINIT(C_GetFunctionList);

	if (! pPtr) {
		RET(C_GetFunctionList, CKR_ARGUMENTS_BAD);
	}

	*pPtr = &function_list;

	RET(C_GetFunctionList, CKR_OK);
}

/*
 * These are in PKCS11 order, to make searching easier
 */

/*
 * Initialize the library and setup anything we need.
 */

CK_RV C_Initialize(CK_VOID_PTR p)
{
	CK_C_INITIALIZE_ARGS_PTR init = (CK_C_INITIALIZE_ARGS_PTR) p;
	const char *progname;

	FUNCINIT(C_Initialize);

	if (initialized) {
		RET(C_Initialized, CKR_CRYPTOKI_ALREADY_INITIALIZED);
	}

	if (init) {
		if (init->pReserved) {
			os_log_debug(logsys, "pReserved set, returning");
			RET(C_Initialized, CKR_ARGUMENTS_BAD);
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

	CREATE_MUTEX(id_mutex);
	CREATE_MUTEX(sess_mutex);

	/*
	 * By default we let the Security framework pop up a dialog box
	 * when the PIN is needed, and we will set
	 * CKF_PROTECTED_AUTHENTICATION_PATH in the token information
	 * structure to indicate that the application should NOT prompt
	 * for a PIN.  But some programs are buggy, so let's make it
	 * configurable.  Check to see if the current program name exists
	 * in the "askPIN" preference in our configuration domain (currently
	 * that is "mil.navy.nrl.cmf.pkcs11").  The program name is whatever
	 * is returned by getprogname().  If that program exists, then we
	 * will allow the PIN to be set via C_Login().
	 */

	progname = getprogname();

	if (! prefkey_found("askPIN", progname)) {
		os_log_debug(logsys, "Program \"%{public}s\" is NOT set to "
			     "ask for PIN, will let Security ask for the PIN",
			     progname);
		ask_pin = false;
	} else {
		os_log_debug(logsys, "Program \"%{public}s\" IS set to ask "
			     "for a PIN, we will prompt for the PIN",
			     progname);
		ask_pin = true;
	}

	initialized = 1;

	RET(C_Initalize, CKR_OK);
}

/*
 * Clean up everything from the library
 */

CK_RV C_Finalize(CK_VOID_PTR p)
{
	FUNCINITCHK(C_Finalize);

	if (p) {
		os_log_debug(logsys, "pReserved is non-NULL");
		RET(C_Finalize, CKR_ARGUMENTS_BAD);
	}

	LOCK_MUTEX(id_mutex);
	LOCK_MUTEX(sess_mutex);

	obj_free(&id_obj_list, &id_obj_count, &id_obj_size);
	id_list_free();
	lacontext_free(lacontext);
	lacontext = NULL;
	logged_in = false;

	UNLOCK_MUTEX(sess_mutex);
	UNLOCK_MUTEX(id_mutex);

	DESTROY_MUTEX(id_mutex);
	DESTROY_MUTEX(sess_mutex);

	use_mutex = 0;
	initialized = 0;
	have_slot = false;

	RET(C_Finalize, CKR_OK);
}

CK_RV C_GetInfo(CK_INFO_PTR p)
{
	FUNCINITCHK(C_GetInfo);

	if (! p) {
		RET(C_GetInfo, CKR_ARGUMENTS_BAD);
	}

	p->cryptokiVersion.major = CK_MAJOR_VERSION;
	p->cryptokiVersion.minor = CK_MINOR_VERSION;

	p->flags = 0;

	sprintfpad(p->manufacturerID, sizeof(p->manufacturerID),
		   "U.S. Naval Research Lab");

	sprintfpad(p->libraryDescription, sizeof(p->libraryDescription),
		   "Keychain PKCS#11 Bridge Library");

	p->libraryVersion.major = 1;
	p->libraryVersion.minor = 0;

	RET(C_GetInfo, CKR_OK);
}

/* C_GetFunctionList declared above */

CK_RV C_GetSlotList(CK_BBOOL token_present, CK_SLOT_ID_PTR slot_list,
		    CK_ULONG_PTR slot_num)
{
	CK_RV rv;

	FUNCINITCHK(C_GetSlotList);

	os_log_debug(logsys, "tokens_present = %{bool}d, slot_list = %p, "
		     "slot_num = %d", token_present, slot_list,
		     (int) *slot_num);

	/*
	 * We need to rescan our identity list if we haven't been initialized.
	 *
	 * We used to do a rescan if slot_list was NULL, but it got to be
	 * too hard to allow a rescan and keep references to identities
	 * if we had open sessions.  So for now the only way to rescan the
	 * slot list (and check for different identities) is to call
	 * C_Initialize() again (which means calling C_Finalize()) which
	 * will reset all of the identity information.  My reading of
	 * PKCS#11 says that's ok.
	 */

	LOCK_MUTEX(id_mutex);

	if (! id_list_init) {
		if (scan_identities()) {
			rv = CKR_FUNCTION_FAILED;
			goto out;
		}
	}

	/*
	 * So, here's the rule.  We only have one "slot"; tests show
	 * that at least on High Sierra, multiple readers pluggged in
	 * don't work, you can only see one.  So we only return one slot,
	 * with a slot number of 1.  If token_present is false, we ALWAYS
	 * return the slot; if token_present is true, then we return the
	 * slot only if we have identities (because we search for hardware
	 * token identities, this means we have a hardware token)
	 */

	rv = CKR_OK;

	if (!token_present || id_list_count > 0) {
		if (slot_list) {
			if (*slot_num == 0)
				rv = CKR_BUFFER_TOO_SMALL;
			else
				slot_list[0] = KEYCHAIN_SLOT;/* Our only slot */
		}
		*slot_num = 1;
		have_slot = true;
	} else {
		/*
		 * If we're here, token_present is TRUE and we have no
		 * identities, so return zero slots
		 */
		*slot_num = 0;
		have_slot = false;
	}

out:
	UNLOCK_MUTEX(id_mutex);
	RET(C_GetSlotList, rv);
}

/*
 * Return information about a "slot"
 */

CK_RV C_GetSlotInfo(CK_SLOT_ID slot_id, CK_SLOT_INFO_PTR slot_info)
{
	FUNCINITCHK(C_GetSlotInfo);

	os_log_debug(logsys, "slot_id = %d, slot_info = %p", (int) slot_id,
		     slot_info);

	CHECKSLOT(slot_id);

	if (! slot_info)
		RET(C_GetSlotInfo, CKR_ARGUMENTS_BAD);

	/*
	 * We can't really get any useful information out of the Security
	 * framework in terms of information about the "slot" (the reader).
	 * I don't really think it is useful anyway, so just fill in some
	 * dummy values.  The one valid thing we return is the
	 * CKF_TOKEN_PRESENT flag if we have a token inserted or not.
	 */

	sprintfpad(slot_info->slotDescription,
		  sizeof(slot_info->slotDescription), "%s",
		  id_list_count > 0 ? id_list[0].label :
		  	"Keychain PKCS#11 Bridge Library Virtual Slot");
	sprintfpad(slot_info->manufacturerID,
		   sizeof(slot_info->manufacturerID), "%s",
		   "U.S. Naval Research Lab");

	slot_info->flags = CKF_HW_SLOT | CKF_REMOVABLE_DEVICE;

	LOCK_MUTEX(id_mutex);
	if (id_list_count > 0)
		slot_info->flags |= CKF_TOKEN_PRESENT;
	UNLOCK_MUTEX(id_mutex);

	slot_info->hardwareVersion.major = 1;
	slot_info->hardwareVersion.minor = 0;
	slot_info->firmwareVersion.major = 1;
	slot_info->firmwareVersion.minor = 0;

	RET(C_GetSlotInfo, CKR_OK);
}

/*
 * Return information about a token.  Most of this stuff is fabricated;
 * a lot of it doesn't matter, as it deals with things we don't support.
 */

CK_RV C_GetTokenInfo(CK_SLOT_ID slot_id, CK_TOKEN_INFO_PTR token_info)
{
	FUNCINITCHK(C_GetTokenInfo);

	os_log_debug(logsys, "slot_id = %d, token_info = %p", (int) slot_id,
		     token_info);

	CHECKSLOT(slot_id);

	if (! token_info)
		RET(C_GetTokenInfo, CKR_ARGUMENTS_BAD);

	/*
	 * Since this is used as label in a number of places to display
	 * to the user, make it something useful.  Pick the first certificate
	 * we found (if available) and return the subject summary as
	 * the token label.
	 */

	LOCK_MUTEX(id_mutex);

	if (id_list_count > 0) {
		CFStringRef summary;
		char *label;

		summary = SecCertificateCopySubjectSummary(id_list[0].cert);

		if (summary) {
			label = getstrcopy(summary);
		} else {
			label = strdup("Unknown Keychain Token");
		}

		sprintfpad(token_info->label, sizeof(token_info->label),
			   "%s", label);

		free(label);
		if (summary)
			CFRelease(summary);
	} else {
		sprintfpad(token_info->label, sizeof(token_info->label), "%s",
			   "Keychain PKCS#11 Virtual Token");
	}

	UNLOCK_MUTEX(id_mutex);

	sprintfpad(token_info->manufacturerID,
		   sizeof(token_info->manufacturerID), "%s",
		   "Unknown Manufacturer");
	sprintfpad(token_info->model, sizeof(token_info->model), "%s",
		   "Unknown Model");
	sprintfpad(token_info->serialNumber, sizeof(token_info->serialNumber),
		   "%s", "000001");
	/*
	 * We can't do any administrative operations, really, from the
	 * Security framework, so basically make it so the token is
	 * read/only.
	 */
	token_info->flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED |
			    CKF_USER_PIN_INITIALIZED |
			    CKF_TOKEN_INITIALIZED;

	/* 
	 * If we were set to to NOT ask for a PIN in C_Login (see
	 * the function C_Initialize for more info) then set the flag
	 * CKF_PROTECTED_AUTHENTICATION_PATH.
	 */

	if (ask_pin) {
		os_log_debug(logsys, "We are NOT setting the flag "
			     "CKF_PROTECTED_AUTHENTICATION_PATH");
	} else {
		os_log_debug(logsys, "We ARE setting the flag "
			     "CKF_PROTECTED_AUTHENTICATION_PATH");
		token_info->flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
	}

	token_info->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	token_info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
	token_info->ulMaxRwSessionCount = 0;
	token_info->ulRwSessionCount = 0;
	token_info->ulMaxPinLen = 255;
	token_info->ulMinPinLen = 1;
	token_info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	token_info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	token_info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	token_info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	token_info->hardwareVersion.major = 1;
	token_info->hardwareVersion.minor = 0;
	token_info->firmwareVersion.major = 1;
	token_info->firmwareVersion.minor = 0;
	sprintfpad(token_info->utcTime, sizeof(token_info->utcTime),
		   "%s", "1970010100000000");

	RET(C_GetTokenInfo, CKR_OK);
}

/*
 * Return our list of mechanisms that we support.
 */

CK_RV C_GetMechanismList(CK_SLOT_ID slot_id, CK_MECHANISM_TYPE_PTR mechlist,
			 CK_ULONG_PTR mechnum)
{
	int i;

	FUNCINITCHK(C_GetMechanismList);

	os_log_debug(logsys, "slot_id = %lu, mechlist = %p, mechnum = %lu",
		     slot_id, mechlist, *mechnum);

	CHECKSLOT(slot_id);

	/*
	 * It's hard to know exactly what all mechanisms are supported by
	 * a particular token, but we can probably safely return all of the
	 * RSA ones at least (since those should work with any RSA key)
	 */

	/*
	 * Return the list count (and CKR_OK) if mechlist was NULL
	 */

	if (!mechlist) {
		*mechnum = keychain_mechmap_size;
		RET(C_GetMechanismList, CKR_OK);
	}

	/*
	 * Return our mechanisms (or CKR_BUFFER_TOO_SMALL)
	 */

	if (*mechnum < keychain_mechmap_size) {
		*mechnum = keychain_mechmap_size;
		RET(C_GetMechanismList, CKR_BUFFER_TOO_SMALL);
	}

	for (i = 0; i < keychain_mechmap_size; i++)
		mechlist[i] = keychain_mechmap[i].cki_mech;

	RET(C_GetMechanismList, CKR_OK);
}

/*
 * Return information on a particular mechanism.
 *
 * It's not clear how important this information is, at least for
 * callers of our library.  Return some stuff that seems reasonable.
 */

CK_RV C_GetMechanismInfo(CK_SLOT_ID slot_id, CK_MECHANISM_TYPE mechtype,
			 CK_MECHANISM_INFO_PTR mechinfo)
{
	int i;

	FUNCINITCHK(C_GetMechanismInfo);

	os_log_debug(logsys, "slot_id = %lu, mechtype = %s, mechinfo = %p",
		     slot_id, getCKMName(mechtype), mechinfo);

	CHECKSLOT(slot_id);

	for (i = 0; i < keychain_mechmap_size; i++) {
		if (mechtype == keychain_mechmap[i].cki_mech) {
			mechinfo->ulMinKeySize = keychain_mechmap[i].min_keylen;
			mechinfo->ulMaxKeySize = keychain_mechmap[i].max_keylen;
			mechinfo->flags = keychain_mechmap[i].usage_flags;
			RET(C_GetMechanismInfo, CKR_OK);
		}
	}

	RET(C_GetMechanismInfo, CKR_MECHANISM_INVALID);
}

NOTSUPPORTED(C_InitToken, (CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen, CK_UTF8CHAR_PTR label))
NOTSUPPORTED(C_InitPIN, (CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen))
NOTSUPPORTED(C_SetPIN, (CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR oldpin, CK_ULONG oldpinlen, CK_UTF8CHAR_PTR newpin, CK_ULONG newpinlen))

/*
 * Open a "session". Right now this is mostly a no-op.
 */

CK_RV C_OpenSession(CK_SLOT_ID slot_id, CK_FLAGS flags,
		    CK_VOID_PTR app_callback, CK_NOTIFY notify_callback,
		    CK_SESSION_HANDLE_PTR session)
{
	struct session *sess;
	int i;

	FUNCINITCHK(C_OpenSession);

	os_log_debug(logsys, "slot_id = %d, flags = %#lx, app_callback = %p, "
		     "notify_callback = %p, session_handle = %p", (int) slot_id,
		     flags, app_callback, notify_callback, session);

	CHECKSLOT(slot_id);

	if (! (flags & CKF_SERIAL_SESSION))
		RET(C_OpenSession, CKR_SESSION_PARALLEL_NOT_SUPPORTED);

	if (flags & CKF_RW_SESSION)
		RET(C_OpenSession, CKR_TOKEN_WRITE_PROTECTED);

	sess = malloc(sizeof(*sess));
	CREATE_MUTEX(sess->mutex);
	sess->obj_list = id_obj_list;
	sess->obj_list_count = id_obj_count;
	sess->search_attrs = NULL;
	sess->search_attrs_count = 0;
	sess->sig_key = NULL;
	sess->ver_key = NULL;

	LOCK_MUTEX(sess_mutex);

	/*
	 * See if we can find a free slot in our session list
	 */

	for (i = 0; i < sess_list_size; i++) {
		if (sess_list[i] == NULL) {
			sess_list[i] = sess;
			*session = i + 1;
			goto out;
		}
	}

	/*
	 * Looks like we need to grow the session list
	 */

	sess_list_size += 5;

	sess_list = realloc(sess_list, sess_list_size * sizeof(*sess_list));

	for (i = sess_list_count + 1; i < sess_list_size; i++)
		sess_list[i] = NULL;

	sess_list[sess_list_count] = sess;

	*session = ++sess_list_count;
out:
	UNLOCK_MUTEX(sess_mutex);

	RET(C_OpenSession, CKR_OK);
}

CK_RV C_CloseSession(CK_SESSION_HANDLE session)
{
	struct session *se;
	int i;

	FUNCINITCHK(C_CloseSession);

	os_log_debug(logsys, "session = %d", (int) session);

	CHECKSESSION(session, se);

	LOCK_MUTEX(id_mutex);
	LOCK_MUTEX(sess_mutex);

	sess_free(se);

	sess_list[session] = NULL;

	for (i = 0; i < sess_list_count; i++)
		if (sess_list[i] != NULL)
			goto cont;

	token_logout();

cont:
	UNLOCK_MUTEX(sess_mutex);
	UNLOCK_MUTEX(id_mutex);

	RET(C_CloseSession, CKR_OK);
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slot_id)
{
	CHECKSLOT(slot_id);

	LOCK_MUTEX(id_mutex);
	LOCK_MUTEX(sess_mutex);
	sess_list_free();
	token_logout();
	UNLOCK_MUTEX(sess_mutex);
	UNLOCK_MUTEX(id_mutex);

	RET(C_CloseAllSessions, CKR_OK);
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE session,
		       CK_SESSION_INFO_PTR session_info)
{
	struct session *se;

	FUNCINITCHK(C_GetSessionInfo);

	os_log_debug(logsys, "session = %d, session_info = %p",
		     (int) session, session_info);

	CHECKSESSION(session, se);

	if (session > sess_list_count || sess_list[session] == NULL)
		RET(C_GetSessionInfo, CKR_SESSION_HANDLE_INVALID);

	if (!session_info)
		RET(C_GetSessionInfo, CKR_ARGUMENTS_BAD);

	session_info->slotID = KEYCHAIN_SLOT;
	session_info->state = logged_in ? CKS_RO_USER_FUNCTIONS :
						CKS_RO_PUBLIC_SESSION;
	session_info->flags = CKF_SERIAL_SESSION ;
	session_info->ulDeviceError = 0;

	RET(C_GetSessionInfo, CKR_OK);
}

NOTSUPPORTED(C_GetOperationState, (CK_SESSION_HANDLE session, CK_BYTE_PTR opstate, CK_ULONG_PTR opstatelen))
NOTSUPPORTED(C_SetOperationState, (CK_SESSION_HANDLE session, CK_BYTE_PTR opstate, CK_ULONG opstatelen, CK_OBJECT_HANDLE enckey, CK_OBJECT_HANDLE authkey))

/*
 * Login to token.  If we actually get passed a PIN here, feed it into the
 * LAContext methods in localauth.m.
 */

CK_RV C_Login(CK_SESSION_HANDLE session, CK_USER_TYPE usertype,
	      CK_UTF8CHAR_PTR pin, CK_ULONG pinlen)
{
	struct session *se;
	int i;
	CK_RV rv = CKR_OK;
	FUNCINITCHK(C_Login);

	os_log_debug(logsys, "session = %d, user_type = %lu", (int) session,
		     usertype);

	CHECKSESSION(session, se);

	LOCK_MUTEX(id_mutex);
	LOCK_MUTEX(se->mutex);

	/*
	 * I went back and forth here; I finally decided that if a PIN
	 * was passed into this function then we should set it.  We
	 * use the sme PIN for all private keys; that seems a safe assumption
	 * for now
	 */

	if (pin) {
		for (i = 0; i < id_list_count; i++) {
			enum la_keyusage usage;

			os_log_debug(logsys, "Setting PIN for identity %d", i);

			usage = id_list[i].privcansign ? USAGE_SIGN :
								USAGE_DECRYPT;

			if ((rv = lacontext_auth(lacontext, pin, pinlen,
						 id_list[i].secaccess,
						 usage)) != CKR_OK) {
				/*
				 * The real error should have been logged
				 * in lacontext_auth().
				 */
				goto out;
			}
		}
	} else {
		os_log_debug(logsys, "We are NOT setting the PIN");
	}

	logged_in = true;

out:
	UNLOCK_MUTEX(se->mutex);
	UNLOCK_MUTEX(id_mutex);

	RET(C_Login, rv);
}

/*
 * If we set a null password, then that will remove our existing credentials.
 */

CK_RV C_Logout(CK_SESSION_HANDLE session)
{
	struct session *se;
	FUNCINITCHK(C_Logout);

	os_log_debug(logsys, "session = %d", (int) session);

	CHECKSESSION(session, se);

	LOCK_MUTEX(id_mutex);
	LOCK_MUTEX(se->mutex);

	token_logout();

	UNLOCK_MUTEX(se->mutex);
	UNLOCK_MUTEX(id_mutex);
	RET(C_Logout, CKR_OK);
}

NOTSUPPORTED(C_CreateObject, (CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template, CK_ULONG num_attributes, CK_OBJECT_HANDLE_PTR object))
NOTSUPPORTED(C_CopyObject, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG num_attributes, CK_OBJECT_HANDLE_PTR new_object))
NOTSUPPORTED(C_DestroyObject, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object))
NOTSUPPORTED(C_GetObjectSize, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ULONG_PTR size))

/*
 * Return the value of an attribute for an object
 */

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
			  CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	struct session *se;
	CK_RV rv = CKR_OK;
	int i;
	CK_ATTRIBUTE_PTR attr;

	FUNCINITCHK(C_GetAttributeValue);

	os_log_debug(logsys, "session = %d, object = %d, template = %p, "
		     "count = %d", (int) session, (int) object, template,
		     (int) count);

	CHECKSESSION(session, se);

	LOCK_MUTEX(se->mutex);

	object--;

	if (object >= se->obj_list_count) {
		UNLOCK_MUTEX(se->mutex);
		RET(C_GetAttributeValue, CKR_OBJECT_HANDLE_INVALID);
	}

	LOG_DEBUG_OBJECT(object, se);

	for (i = 0; i < count; i++) {
		os_log_debug(logsys, "Retrieving attribute: %s",
			     getCKAName(template[i].type));
		if ((attr = find_attribute(&se->obj_list[object],
					   template[i].type))) {
			if (! template[i].pValue) {
				template[i].ulValueLen = attr->ulValueLen;
				os_log_debug(logsys, "pValue was NULL, just "
					     "returning length (%lu)",
					     attr->ulValueLen);
			} else {
				if (template[i].ulValueLen < attr->ulValueLen) {
					template[i].ulValueLen =
							attr->ulValueLen;
					os_log_debug(logsys, "Attribute: "
						     "buffer too small "
						     "(%lu, %lu)",
						     template[i].ulValueLen,
						     attr->ulValueLen);
					rv = CKR_BUFFER_TOO_SMALL;
				} else {
					memcpy(template[i].pValue, attr->pValue,
					       attr->ulValueLen);
					template[i].ulValueLen =
							attr->ulValueLen;
					os_log_debug(logsys, "Copied over "
						     "attribute (%lu, %lu)",
						     template[i].ulValueLen,
						     attr->ulValueLen);
				}
			}
		} else {
			os_log_debug(logsys, "Attribute not found");
			template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}

	UNLOCK_MUTEX(se->mutex);

	RET(C_GetAttributeValue, rv);
}

NOTSUPPORTED(C_SetAttributeValue, (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG count))

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template,
			CK_ULONG count)
{
	struct session *se;
	int i;

	FUNCINITCHK(C_FindObjectsInit);

	os_log_debug(logsys, "session = %d, template = %p, count = %lu",
		     (int) session, template, count);

	CHECKSESSION(session, se);

	LOCK_MUTEX(se->mutex);

	se->obj_search_index = 0;

	/*
	 * Copy all of our attributes to search against later
	 */

	se->search_attrs = count ? malloc(sizeof(CK_ATTRIBUTE) * count) : NULL;
	se->search_attrs_count = count;

	for (i = 0; i < count; i++) {
		se->search_attrs[i].type = template[i].type;
		se->search_attrs[i].ulValueLen = template[i].ulValueLen;
		if (se->search_attrs[i].ulValueLen ==
					CK_UNAVAILABLE_INFORMATION) {
			se->search_attrs[i].pValue = NULL;
		} else {
			se->search_attrs[i].pValue =
					malloc(se->search_attrs[i].ulValueLen);
			memcpy(se->search_attrs[i].pValue, template[i].pValue,
			       se->search_attrs[i].ulValueLen);
		}
		dump_attribute("Search template", &se->search_attrs[i]);
	}

	UNLOCK_MUTEX(se->mutex);

	RET(C_FindObjectsInit, CKR_OK);
}

/*
 * Return object identifiers that match our search template.  Right now we
 * ignore the session handle, but we'll fix that later.
 */

CK_RV C_FindObjects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR object,
		    CK_ULONG maxcount, CK_ULONG_PTR count)
{
	struct session *se;
	unsigned int rc = 0;

	FUNCINITCHK(C_FindObjects);

	os_log_debug(logsys, "session = %d, objhandle = %p, maxcount = %lu, "
		     "count = %p", (int) session, object, maxcount, count);

	CHECKSESSION(session, se);

	if (! object || maxcount == 0)
		RET(C_FindObjects, CKR_ARGUMENTS_BAD);

	LOCK_MUTEX(se->mutex);

	for (; se->obj_search_index < se->obj_list_count;
						se->obj_search_index++) {
		if (search_object(&se->obj_list[se->obj_search_index],
				  se->search_attrs, se->search_attrs_count)) {
			object[rc++] = se->obj_search_index + 1;
			if (rc >= maxcount) {
				*count = rc;
				se->obj_search_index++;
				os_log_debug(logsys, "Found %u object%s",
					     rc, rc == 1 ? "" : "s");
				UNLOCK_MUTEX(se->mutex);
				RET(C_FindObjects, CKR_OK);
			}
		}
	}

	os_log_debug(logsys, "Found %u object%s", rc, rc == 1 ? "" : "s");
	*count = rc;

	UNLOCK_MUTEX(se->mutex);
	RET(C_FindObjects, CKR_OK);
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE session)
{
	struct session *se;
	int i;

	FUNCINITCHK(C_FindObjectsFinal);

	CHECKSESSION(session, se);

	LOCK_MUTEX(se->mutex);

	os_log_debug(logsys, "session = %d", (int) session);

	for (i = 0; i < se->search_attrs_count; i++)
		free(se->search_attrs[i].pValue);

	free(se->search_attrs);
	se->search_attrs = NULL;
	se->search_attrs_count = 0;

	UNLOCK_MUTEX(se->mutex);

	RET(C_FindObjectsFinal, CKR_OK);
}

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

/*
 * Start a signature operation.  Our global assumption is that the signature
 * is only done with a private key; if that changes then we need to change
 * this code.
 */

CK_RV C_SignInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
		 CK_OBJECT_HANDLE object)
{
	struct session *se;
	int i;

	FUNCINITCHK(C_SignInit);

	os_log_debug(logsys, "session = %d, mechanism = %s, object = %d",
		    (int) session, getCKMName(mech->mechanism), (int) object);

	CHECKSESSION(session, se);

	LOCK_MUTEX(id_mutex);
	LOCK_MUTEX(se->mutex);

	object--;

	if (object >= se->obj_list_count) {
		UNLOCK_MUTEX(se->mutex);
		RET(C_SignInit, CKR_KEY_HANDLE_INVALID);
	}

	if (! id_list[se->obj_list[object].id_index].privcansign) {
		UNLOCK_MUTEX(se->mutex);
		RET(C_SignInit, CKR_KEY_FUNCTION_NOT_PERMITTED);
	}

	/*
	 * Right now we are assuming only a private key can do signing.
	 * Change this assumption in the future if necessary
	 */

	if (se->obj_list[object].class != CKO_PRIVATE_KEY) {
		UNLOCK_MUTEX(se->mutex);
		UNLOCK_MUTEX(id_mutex);
		RET(C_SignInit, CKR_KEY_TYPE_INCONSISTENT);
	}

	/*
	 * Map our mechanism onto what we need for signing
	 */

	for (i = 0; i < keychain_mechmap_size; i++) {
		if (mech->mechanism == keychain_mechmap[i].cki_mech) {
			if (se->sig_key)
				CFRelease(se->sig_key);
			se->sig_key =
				id_list[se->obj_list[object].id_index].privkey;
			CFRetain(se->sig_key);
			se->sig_alg = *keychain_mechmap[i].sec_signmech;
			if (keychain_mechmap[i].blocksize_out) {
				se->sig_size = SecKeyGetBlockSize(se->sig_key);
			} else {
				se->sig_size = 0;
			}

			UNLOCK_MUTEX(se->mutex);
			UNLOCK_MUTEX(id_mutex);
			RET(C_SignInit, CKR_OK);
		}
	}

	UNLOCK_MUTEX(se->mutex);
	UNLOCK_MUTEX(id_mutex);

	RET(C_SignInit, CKR_MECHANISM_INVALID);
}

/*
 * Actually sign the data
 */
CK_RV C_Sign(CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen,
	     CK_BYTE_PTR sig, CK_ULONG_PTR siglen)
{
	struct session *se;
	CFDataRef inref, outref;
	CFErrorRef err;
	CK_RV rv = CKR_OK;
#ifdef KEYCHAIN_DEBUG
	char *file;
#endif /* KEYCHAIN_DEBUG */

	FUNCINITCHK(C_Sign);

	os_log_debug(logsys, "session = %d, indata = %p, inlen = %d, "
		     "outdata = %p, outlen = %d", (int) session, indata,
		     (int) indatalen, sig, (int) *siglen);

	CHECKSESSION(session, se);

	LOCK_MUTEX(id_mutex);
	LOCK_MUTEX(se->mutex);

#ifdef KEYCHAIN_DEBUG
	if ((file = getenv("KEYCHAIN_PKCS11_SIGN_DATAFILE"))) {
		FILE *f = fopen(file, "w");

		if (! f) {
			os_log_debug(logsys, "Failed to open \"%s\": "
				     "%{darwin.errno}d", file, errno);
		} else {
			fwrite(indata, indatalen, 1, f);
			fclose(f);
		}
	}
#endif /* KEYCHAIN_DEBUG */

	/*
	 * If we know our mechanism output size, check first to see if the
	 * output buffer is big enough.
	 */

	if (se->sig_size && se->sig_size > *siglen) {
		os_log_debug(logsys, "Output size is %d, but our output "
			     "buffer is %d", (int) se->sig_size, (int) *siglen);
		*siglen = se->sig_size;
		UNLOCK_MUTEX(se->mutex);
		UNLOCK_MUTEX(id_mutex);
		RET(C_Sign, sig == NULL ? CKR_OK : CKR_BUFFER_TOO_SMALL);
	}

	inref = CFDataCreateWithBytesNoCopy(NULL, indata, indatalen,
					    kCFAllocatorNull);

	outref = SecKeyCreateSignature(se->sig_key, se->sig_alg, inref, &err);

	CFRelease(inref);
	UNLOCK_MUTEX(se->mutex);
	UNLOCK_MUTEX(id_mutex);

	if (! outref) {
		os_log_debug(logsys, "SecKeyCreateSignature failed: "
			     "%{public}@", err);
		CFRelease(err);
		RET(C_Sign, CKR_GENERAL_ERROR);
	}

	if (*siglen < CFDataGetLength(outref)) {
		rv = CKR_BUFFER_TOO_SMALL;
	} else {
		memcpy(sig, CFDataGetBytePtr(outref), CFDataGetLength(outref));
		/*
		 * If the signature was successful, release our key reference
		 */
		CFRelease(se->sig_key);
		se->sig_key = NULL;
		se->sig_size = 0;
	}

	*siglen = CFDataGetLength(outref);

	CFRelease(outref);

#if KEYCHAIN_DEBUG
	if ((file = getenv("KEYCHAIN_PKCS11_SIGN_SIGFILE"))) {
		FILE *f = fopen(file, "w");

		if (! f) {
			os_log_debug(logsys, "Failed to open \"%s\": "
				     "%{darwin.errno}d", file, errno);
		} else {
			fwrite(sig, *siglen, 1, f);
			fclose(f);
		}
	}
#endif /* KEYCHAIN_DEBUG */
	RET(C_Sign, rv); ;
}

NOTSUPPORTED(C_SignUpdate, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen))
NOTSUPPORTED(C_SignFinal, (CK_SESSION_HANDLE session, CK_BYTE_PTR sig, CK_ULONG_PTR siglen))
NOTSUPPORTED(C_SignRecoverInit, (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key))
NOTSUPPORTED(C_SignRecover, (CK_SESSION_HANDLE session, CK_BYTE_PTR indata, CK_ULONG indatalen, CK_BYTE_PTR sig, CK_ULONG_PTR siglen))

CK_RV C_VerifyInit(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
		   CK_OBJECT_HANDLE key)
{
	struct session *se;
	int i;

	FUNCINITCHK(C_VerifyInit);

	os_log_debug(logsys, "session = %d, mechanism = %s, object = %d",
		    (int) session, getCKMName(mech->mechanism), (int) key);

	CHECKSESSION(session, se);

	LOCK_MUTEX(id_mutex);
	LOCK_MUTEX(se->mutex);

	key--;

	if (key >= se->obj_list_count) {
		UNLOCK_MUTEX(se->mutex);
		UNLOCK_MUTEX(id_mutex);
		RET(C_VerifyInit, CKR_KEY_HANDLE_INVALID);
	}
		
	if (! id_list[se->obj_list[key].id_index].pubcanverify) {
		UNLOCK_MUTEX(se->mutex);
		UNLOCK_MUTEX(id_mutex);
		RET(C_VerifyInit, CKR_KEY_FUNCTION_NOT_PERMITTED);
	}

	if (se->obj_list[key].class != CKO_PUBLIC_KEY) {
		UNLOCK_MUTEX(se->mutex);
		UNLOCK_MUTEX(id_mutex);
		RET(C_SignInit, CKR_KEY_TYPE_INCONSISTENT);
	}

	/*
	 * Map our mechanism onto what we need for verification
	 */

	for (i = 0; i < keychain_mechmap_size; i++) {
		if (mech->mechanism == keychain_mechmap[i].cki_mech) {
			if (se->ver_key)
				CFRelease(se->ver_key);
			se->ver_key =
				id_list[se->obj_list[key].id_index].pubkey;
			CFRetain(se->ver_key);
			se->ver_alg = *keychain_mechmap[i].sec_signmech;
			UNLOCK_MUTEX(se->mutex);
			UNLOCK_MUTEX(id_mutex);
			RET(C_VerifyInit, CKR_OK);
		}
	}

	UNLOCK_MUTEX(se->mutex);
	UNLOCK_MUTEX(id_mutex);

	RET(C_VerifyInit, CKR_MECHANISM_INVALID);
}

CK_RV C_Verify(CK_SESSION_HANDLE session, CK_BYTE_PTR indata,
	       CK_ULONG indatalen, CK_BYTE_PTR sig, CK_ULONG siglen)
{
	struct session *se;
	CFDataRef inref, sigref;
	CFErrorRef err;
	CK_RV rv = CKR_OK;

	FUNCINITCHK(C_Verify);

	os_log_debug(logsys, "session = %d, indata = %p, inlen = %d, "
		     "outdata = %p, outlen = %d", (int) session, indata,
		     (int) indatalen, sig, (int) siglen);

	CHECKSESSION(session, se);

	inref = CFDataCreateWithBytesNoCopy(NULL, indata, indatalen,
					    kCFAllocatorNull);
	sigref = CFDataCreateWithBytesNoCopy(NULL, sig, siglen,
					     kCFAllocatorNull);

	LOCK_MUTEX(id_mutex);
	LOCK_MUTEX(se->mutex);

	if (!SecKeyVerifySignature(se->ver_key, se->ver_alg, inref, sigref,
				   &err)) {
		os_log_debug(logsys, "VerifySignature failed: %{public}@", err);
		CFRelease(err);
		rv = CKR_SIGNATURE_INVALID;
	}

	/*
	 * Always release the key reference at this point
	 */

	CFRelease(se->ver_key);
	se->ver_key = NULL;

	UNLOCK_MUTEX(se->mutex);
	UNLOCK_MUTEX(id_mutex);
	CFRelease(inref);
	CFRelease(sigref);

	RET(C_Verify, rv);
}

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
 * Use the Security framework to scan for any identities that are provided
 * by a smartcard, and copy out useful information from them.
 *
 * So, how does this work?
 *
 * We call SecItemCopyMatching() to find any "identities" known by the
 * Security framework.  An identity is a private key with a matching
 * certificate.  We restrict the search to tokens that live on smartcards.
 * Returns -1 on failure, 0 on success.
 *
 * Should be called with id_mutex locked.
 */ 

static int
scan_identities(void)
{
	CFDictionaryRef query;
	CFTypeRef result;
	CFTypeID resid;
	int ret;

	/*
	 * Our keys to create our query dictionary; note that the order
	 * keys and values need to match up.
	 *
	 * Here's what's the query dictionary means:
	 *
	 * kSecClass = kSecClassIdentity
	 *	This means we're searching for "identities" (certificates
	 *	with corresponding private key objects).
	 * kSecMatchLimit = kSecMatchLimitAll
	 *	Without this, we only get one identity.  Setting this means
	 *	our return value could be a list of identities.  If we get
	 *	more than one identity returned then the result will be
	 *	a CFArrayRef, otherwise it will be a CFDictionaryRef
	 *	(see below).
	 * kSecAttrAccessGroup = kSecAttrAccessGroupToken
	 *	This will limit the search to identities which are in the
	 *	"Token" Access group; this means smartcards.  This isn't
	 *	documented very well, but I see that the security tool
	 *	"list-smartcards" command uses this so I feel it's pretty
	 *	safe to rely on this search key for now.
	 * kSecReturnPersistentRef = kCFBooleanTrue
	 *	This means return a "persisistent" reference to the identity
	 *      (in a CFDataRef).  In earlier versions we would use
	 *      kSecReturnRef to get the SecIdentityRef, but we need to
	 *      bind a LAContext to the identity, and we do that by
	 *      using the persistent ref to retrieve the ACTUAL SecIdentityRef
	 *      and feeding in the LAContext into that query by using
	 *	kSecUseAUthenticationContext.  That actually happens later
	 *	in add_identity().  See comments in localauth.m for more
	 *	information.  The persistent ref ends up in the dictionary
	 *	under the kSecValuePersistentRef.
	 * kSecReturnAttributes = kCFBooleanTrue
	 *	This means we return all of the attributes for each identity.
	 *	We can use this to get access to things like the label
	 *	for the identity.
	 *
	 * Because we ask for all of the Attributes using kSecReturnAttributes
	 * the return value is a CFDictionaryRef containing all of the
	 * various attributes.  If we get more than one identity back, then
	 * we will get a CFArrayRef, with each entry in the array containing
	 * the CFDictionaryRef for that attribute.
	 *
	 * Whew.
	 */

	const void *keys[] = {
		kSecClass,
		kSecMatchLimit,
		kSecAttrAccessGroup,
		kSecReturnPersistentRef,
		kSecReturnAttributes,
	};
	const void *values[] = {
		kSecClassIdentity,		/* kSecClass */
		kSecMatchLimitAll,		/* kSecMatchLimit */
		kSecAttrAccessGroupToken,	/* kSecAttrAccessGroup */
		kCFBooleanTrue,			/* kSecReturnPersistentRef */
		kCFBooleanTrue,			/* kSecReturnAttributes */
	};

	/*
	 * Clear out all previous identity entries and object tree
	 */

	obj_free(&id_obj_list, &id_obj_count, &id_obj_size);
	id_list_free();

	if (lacontext != NULL)
		lacontext_free(lacontext);

	lacontext = lacontext_new();

	/*
	 * Create the query dictionary for SecCopyItemMatching(); see above
	 */

	query = CFDictionaryCreate(NULL, keys, values,
				   sizeof(keys)/sizeof(keys[0]),
				   &kCFTypeDictionaryKeyCallBacks,
				   &kCFTypeDictionaryValueCallBacks);

	if (query == NULL) {
		os_log_debug(logsys, "query dictionary creation returned NULL");
		return -1;
	}

	/*
	 * This is where the actual query happens
	 */

	ret = SecItemCopyMatching(query, &result);

	CFRelease(query);

	if (ret) {
		/*
		 * Handle the case where we just don't see any matching
		 * results.
		 */

		if (ret == errSecItemNotFound) {
			os_log_debug(logsys, "No identities returned");
			id_list_init = true;
			return 0;
		}

		LOG_SEC_ERR("SecItemCopyMatching failed: %@", ret);
		return -1;
	}

	/*
	 * Check to see if we got an array (more than one identity) or
	 * a dictionary (a single item).
	 */

	resid = CFGetTypeID(result);

	if (resid == CFArrayGetTypeID()) {
		unsigned int i, count = CFArrayGetCount(result);

		os_log_debug(logsys, "%u identities found", count);

		for (i = 0; i < count; i++)  {
			os_log_debug(logsys, "Copying identity %u", i + 1);

			if (add_identity(CFArrayGetValueAtIndex(result, i))) {
				ret = -1;
				goto out;
			}
		}
	} else if (resid == CFDictionaryGetTypeID()) {
		os_log_debug(logsys, "1 identity found");
		if (add_identity(result)) {
			ret = -1;
			goto out;
		}
	} else {
		logtype("Unexpected type from SecCopyItemMatching", result);
		ret = -1;
		goto out;
	}

	ret = 0;
	id_list_init = true;

	/*
	 * Rebuild our object tree since we've finished the identity scan
	 */

	build_objects(0);

out:
	CFRelease(result);
	return ret;
}

/*
 * Add an identity to our identity list.  Takes a CFDictionaryRef with
 * all of the identity attributes (and persistent reference) in it.
 */

static int
add_identity(CFDictionaryRef dict)
{
	CFStringRef label;
	CFNumberRef keytype;
	CFTypeRef refresult;
	CFDictionaryRef refquery, keydict;
	CFDataRef p_ref;
	OSStatus ret;
	int i = id_list_count;

	/*
	 * Our query dictionary for SecItemCopyMatching.  Here are the
	 * components of our query dictionary:
	 *
	 * kSecClass = kSecClassIdentity
	 *	See scan_identities() for more details, but this limits us to
	 *	only retrieving identities.
	 * kSecMatchLimit = kSecMatchLimitOne
	 *	Because we're using the persistent reference (see below)
	 *	we really only want one response (and we should only get one)
	 *	so set the match limit to one so we only get back a single
	 *	response.
	 * kSecReturnRef = kCFBooleanTrue
	 *	We set this to indicate that we want an identity reference
	 *	back (SecIdentityRef); this should be the only thing returned
	 *	because we set no other return keys and we are requesting
	 *	only one.
	 * kSecUseAuthenticationContext = LAContext
	 *	This is covered in more detail in localauth.m, but the idea
	 *	here is this is a Local Authentication context created by
	 *	the LAContext class.  When converting from a persistent ref
	 *	to a SecIdentityRef and an auth context is passed in via
	 *	kSecUseAuthenticationContext, it is converted by the Security
	 *	framework internally to an ACM context and we can then later
	 *	use the LAContext methods to authentication to the token.
	 * kSecValuePersistentRef = persistent reference
	 *	This is the persistent reference generated in the attribute
	 *	dictionary when we did the search for all identities in
	 *	scan_identities().  The reason we get a persistent reference
	 *	in scan_identities() and then convert it to a "real" reference
	 *	(e.g., SecIdentityRef) is so we can bind the LAContext
	 *	to the identity so we have the ability to input the PIN
	 *	via the PKCS#11 API (rather than let the Security framework
	 *	ask for it).  It is worth noting that there is ALSO an
	 *	attribute key called "kSecAttrPersistentReference"; as far
	 *	as I can tell, that key is not used for anything.  The
	 *	Apple documentation says to convert a persistent reference
	 *	to a normal reference you should pass in the persistent
	 *	reference in a CFArray using the kSecMatchItemList, but
	 *	I can definitely say that at least for me, this did not work.
	 */

	const void *keys[] = {
		kSecClass,
		kSecMatchLimit,
		kSecReturnRef,
		kSecUseAuthenticationContext,
#define AUTHC_INDEX	3
		kSecValuePersistentRef,
#define P_REF_INDEX	4
	};

	const void *values[] = {
		kSecClassIdentity,		/* kSecClass */
		kSecMatchLimitOne,		/* kSecMatchLimit */
		kCFBooleanTrue,			/* kSecReturnRef */
		NULL,				/* UseAuthtenticationContext */
		NULL,				/* PersistentReference */
	};

	/*
	 * If we don't have enough id entries, allocate some more.
	 */

	if (++id_list_count > id_list_size) {
		id_list_size += 5;
		id_list = realloc(id_list, sizeof(*id_list) * id_list_size);
	}

	id_list[i].ident = NULL;
	id_list[i].cert = NULL;
	id_list[i].privkey = NULL;
	id_list[i].pubkey = NULL;
	id_list[i].label = NULL;
	id_list[i].secaccess = NULL;

	if (! CFDictionaryGetValueIfPresent(dict, kSecValuePersistentRef,
					    (const void **)&p_ref)) {
		os_log_debug(logsys, "Persistent id reference not found");
		return -1;
	}

	/*
	 * Use our shared LAContext and feed it into the query using the
	 * kSecUseAuthenticationContext key.  We also feed in the persistent
	 * reference to extract the REAL identity reference (SecIdentityRef).
	 * This will attach the LAContext to the identity.
	 */

	values[AUTHC_INDEX] = lacontext;
	values[P_REF_INDEX] = p_ref;

	refquery = CFDictionaryCreate(NULL, keys, values,
				      sizeof(keys)/sizeof(keys[0]),
				      &kCFTypeDictionaryKeyCallBacks,
				      &kCFTypeDictionaryValueCallBacks);

	if (refquery == NULL) {
		os_log_debug(logsys, "Persistent ref query dictionary "
			     "creation returned NULL");
		return -1;
	}

	ret = SecItemCopyMatching(refquery, &refresult);

	CFRelease(refquery);

	if (ret) {
		LOG_SEC_ERR("Persistent ref SecItemCopyMatching "
			    "failed: %@", ret);
		return -1;
	}

	if (CFGetTypeID(refresult) != SecIdentityGetTypeID()) {
		logtype("Was expecting a SecIdentityRef, but got: ", refresult);
		CFRelease(refresult);
		return -1;
	}

	/*
	 * No need to retain; we own this as a result of it coming out of
	 * SecItemCopyMatching
	 */

	id_list[i].ident = (SecIdentityRef) refresult;

	/*
	 * Extract out of the dictionary all of the things we need.
	 * Note that since we are following the "Get Rule" and this
	 * dictionary should be de-allocated soon, we need to CFRetain()
	 * everything we want for later.
	 *
	 * Key items:
	 *
	 * Attribute label (display string for the identity)
	 * SecIdentityRef (used by Security Framework)
	 * Various attribute flags (we use those for returning
	 * object information)
	 *
	 * To make things easier, we extract the private key object
	 * and the certificate from the identity.  Those are copies and
	 * we don't need to retain those objects.
	 */

	if (CFDictionaryGetValueIfPresent(dict, kSecAttrLabel,
					  (const void **) &label)) {
		id_list[i].label = getstrcopy(label);
		os_log_debug(logsys, "Identity label: %{public}@", label);
	} else {
		id_list[i].label = strdup("Hardware token");
		os_log_debug(logsys, "No label, using default");
	}
	
#if 0
	if (! CFDictionaryGetValueIfPresent(dict, kSecValueRef,
					    (const void **)&id_list[i].ident)) {
		os_log_debug(logsys, "Identity reference not found");
		return -1;
	}

	CFRetain(id_list[i].ident);
#endif

#if 0
	if (! CFDictionaryGetValueIfPresent(dict, kSecAttrAccessControl,
				    (const void **) &id_list[i].secaccess)) {
		os_log_debug(logsys, "Access Control object not found");
		return -1;
	}

	CFRetain(id_list[i].secaccess);
#endif

	if (! CFDictionaryGetValueIfPresent(dict, kSecAttrKeyType,
					    (const void **) &keytype)) {
		os_log_debug(logsys, "Key type not found");
		return -1;
	}

	id_list[i].keytype = convert_keytype(keytype);

	id_list[i].privcansign = boolfromdict("Can-Sign", dict,
					      kSecAttrCanSign);
	id_list[i].privcandecrypt = boolfromdict("Can-Decrypt", dict,
						 kSecAttrCanDecrypt);

	ret = SecIdentityCopyCertificate(id_list[i].ident, &id_list[i].cert);

	if (ret)
		LOG_SEC_ERR("CopyCertificate failed: %@", ret);

	if (! ret) {
		ret = SecIdentityCopyPrivateKey(id_list[i].ident,
						&id_list[i].privkey);
		if (ret)
			LOG_SEC_ERR("CopyPrivateKey failed: %@", ret);
		else {
			if (! (id_list[i].secaccess =
					getaccesscontrol(dict)))
				return -1;
		}
	}

	if ( !ret) {
		ret = SecCertificateCopyPublicKey(id_list[i].cert,
						  &id_list[i].pubkey);
		if (ret)
			LOG_SEC_ERR("CopyPublicKey failed: %@", ret);
	}

	/*
	 * Get our public key attributes
	 */

	if (! ret) {
		keydict = SecKeyCopyAttributes(id_list[i].pubkey);

		id_list[i].pubcanverify = boolfromdict("Can-Verify", keydict,
						        kSecAttrCanVerify);
		id_list[i].pubcanencrypt = boolfromdict("Can-Encrypt", keydict,
							kSecAttrCanEncrypt);
		CFRelease(keydict);
	}

	if (ret)
		return -1;

	return 0;
}

/*
 * Get the SecAccessControl object from the identity.
 *
 * This is a little subtle; we don't actually want the SecAccessControl
 * object for the IDENTITY, we want it for the private key (as it turns
 * out, they are different).  So what we need to do is get the attributes
 * for the key using SecItemCopyMatching(); the SecAccessControl object
 * will be in there.
 */

static SecAccessControlRef
getaccesscontrol(CFDictionaryRef dict)
{
	SecAccessControlRef accret;
	CFDictionaryRef accquery, attrdict;
	CFDataRef label;
	OSStatus ret;

	/*
	 * Our keys for our query dictionary for SecItemCopyMaching().
	 *
	 * In order:
	 *
	 * kSecClass = kSecClassKey
	 *	This means we're searching for keys (instead of identities
	 *	or certificates)
	 * kSecAttrKeyClass = kSecAttrKeyClassPrivate
	 *	We want to match on the private key
	 * kSecAttrApplicationLabel
	 *	This is the "application label" of the key.  We get this
	 *	from the identity dictionary, and it makes sure we get the
	 *	private key associated with this identity.
	 * kSecMatchLimit = kSecMatchLimitOne
	 *	We only want one match (really, we should only have one
	 *	match, but let's be safe)
	 * kSecReturnAttributes = kCFBooleanTrue
	 *	We want to get all of the attributes so we can find the
	 *	SecAccessControlRef
	 */

	const void *keys[] = {
		kSecClass,
		kSecAttrKeyClass,
		kSecAttrApplicationLabel,
#define ATTR_LABEL_INDEX 2
		kSecMatchLimit,
		kSecReturnAttributes,
	};

	const void *values[] = {
		kSecClassKey,		/* kSecClass */
		kSecAttrKeyClassPrivate,/* kSecAttrKeyClass */
		NULL,			/* Application Label, fill in later */
		kSecMatchLimitOne,	/* kSecMatchLimit */
		kCFBooleanTrue,		/* kSecReturnAttributes */
	};

	/*
	 * Build our query dictionary to retrieve the key attributes.  We
	 * need the application label from the original identity (this is
	 * passed down in "dict")
	 */

	if (! CFDictionaryGetValueIfPresent(dict, kSecAttrApplicationLabel,
				    (const void **) &label)) {
		os_log_debug(logsys, "Application Label object not found");
		return NULL;
	}

	values[ATTR_LABEL_INDEX] = label;

	accquery = CFDictionaryCreate(NULL, keys, values,
				      sizeof(keys)/sizeof(keys[0]),
				      &kCFTypeDictionaryKeyCallBacks,
				      &kCFTypeDictionaryValueCallBacks);

	if (accquery == NULL) {
		os_log_debug(logsys, "Access control ref query dictionary "
			     "creation returned NULL");
		return NULL;
	}

	/*
	 * Perform the actual query
	 */

	ret = SecItemCopyMatching(accquery, (CFTypeRef *) &attrdict);

	CFRelease(accquery);

	if (ret) {
		LOG_SEC_ERR("Access control ref SecItemCopyMatching "
			    "failed: %@", ret);
		return NULL;
	}

	/*
	 * Just in case, make sure we got a CFDictionaryRef
	 */

	if (CFGetTypeID(attrdict) != CFDictionaryGetTypeID()) {
		logtype("Was expecting a CFDictionary, but got: ", attrdict);
		CFRelease(attrdict);
		return NULL;
	}

	if (! CFDictionaryGetValueIfPresent(attrdict, kSecAttrAccessControl,
					    (const void **) &accret)) {
		os_log_debug(logsys, "Access Control object not found");
		CFRelease(attrdict);
		return NULL;
	}

	CFRetain(accret);
	CFRelease(attrdict);

	return accret;
}

/*
 * Make sure the our custom logging system is enabled
 */

static void
log_init(void *context)
{
	logsys = os_log_create(APP_DOMAIN, "general");
}

/*
 * Free our identity list
 */

static void
id_list_free(void)
{
	int i;

	for (i = 0; i < id_list_count; i++) {
		if (id_list[i].label)
			free(id_list[i].label);
		if (id_list[i].ident)
			CFRelease(id_list[i].ident);
		if (id_list[i].privkey)
			CFRelease(id_list[i].privkey);
		if (id_list[i].pubkey)
			CFRelease(id_list[i].pubkey);
		if (id_list[i].cert)
			CFRelease(id_list[i].cert);
		if (id_list[i].secaccess)
			CFRelease(id_list[i].secaccess);
	}

	if (id_list)
		free(id_list);

	id_list = NULL;
	id_list_count = id_list_size = 0;
	id_list_init = false;
}

/*
 * A version of snprintf() which does space-padding
 */

static void
sprintfpad(unsigned char *dest, size_t destsize, const char *fmt, ...)
{
	char *s;
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = vasprintf(&s, fmt, ap);
	va_end(ap);

	if (rc < 1) {
		memset(dest, ' ', destsize);
	} else {
		/* We are relying on strncpy not doing \0 at end for trunc */
		strncpy((char *) dest, s, destsize);
		if (rc < destsize)
			memset(dest + rc, ' ', destsize - rc);
		free(s);
	}
}

/*
 * Return a boolean value based on a dictionary key.  If the key is not
 * set then return false.
 */

bool
boolfromdict(const char *keyname, CFDictionaryRef dict, CFTypeRef key)
{
	CFTypeRef val;

	if (! CFDictionaryGetValueIfPresent(dict, key, &val)) {
		os_log_debug(logsys, "No value for %s in dictionary, "
			     "returning FALSE", keyname);
		return false;
	}

	if (CFGetTypeID(val) != CFBooleanGetTypeID() &&
	    CFGetTypeID(val) != CFNumberGetTypeID()) {
		os_log_debug(logsys, "%s was not a boolean, but exists, so "
			     "returning TRUE", keyname);
		return true;
	}

	os_log_debug(logsys, "%s is set to %{bool}d", keyname,
		     CFBooleanGetValue(val));

	return CFBooleanGetValue(val);
}

/*
 * Get a C string from a CFStringRef (assumes UTF-8 encoding).
 * Allocates memory that must be free()d.
 */

static char *
getstrcopy(CFStringRef string)
{
	const char *s = CFStringGetCStringPtr(string, kCFStringEncodingUTF8);

	if (! s) {
		CFIndex len = CFStringGetLength(string);
		CFIndex size = CFStringGetMaximumSizeForEncoding(len,
						 kCFStringEncodingUTF8) + 1;
		char *p = malloc(size);

		if (! CFStringGetCString(string, p, size,
					 kCFStringEncodingUTF8)) {
			free(p);
			return strdup("Unknown string");
		}

		return p;
	} else {
		return strdup(s);
	}
}

/*
 * Log this object's type
 */

static void
logtype(const char *string, CFTypeRef ref)
{
	CFTypeID id = CFGetTypeID(ref);
	CFStringRef str = CFCopyTypeIDDescription(id);

	os_log_debug(logsys, "%s: %{public}@", string, str);

	CFRelease(str);
}

#if defined(KEYCHAIN_DEBUG)
/*
 * Dump the contents of a dictionary
 */

void
dumpdict(const char *string, CFDictionaryRef dict)
{
	unsigned int i, count = CFDictionaryGetCount(dict);
	const void **keys, **values;

	os_log_debug(logsys, "Dumping dictionary for %s", string);
	os_log_debug(logsys, "Dictionary contains %u key/value pairs", count);

	keys = malloc(sizeof(void *) * count);
	values = malloc(sizeof(void *) * count);

	CFDictionaryGetKeysAndValues(dict, keys, values);

	for (i = 0; i < count; i++) {
		os_log_debug(logsys, "Dictionary entry %d", (int) i);
		os_log_debug(logsys, "Key value: %{public}@", keys[i]);
		logtype("Value type", values[i]);
		os_log_debug(logsys, "Value value: %{public}@", values[i]);
	}

	free(keys);
	free(values);
}
#endif /* KEYCHAIN_DEBUG */

/*
 * Convert Security framework key types to PKCS#11 key types.
 *
 * Sigh.  This is a lot harder than I would like.  The Apple API is in flux;
 * what the attribute dictionary returns is a CFNumber, but the constants
 * you use are actually CFStrings which happen to have string values which
 * correspond to the CFNumbers.  The numbers correspond to the values of
 * CSSM_ALGORITHMS in cssmtype.h.  So that means a RSA key, for example,
 * shows up in the attribute dictionary as a CFNumber with a value of 42,
 * but the constant kSecAttrKeyTypeRSA is a CFString with the value of "42".
 * (There is magic in the Security framework that lets you use things like
 * kSecAttrKeyTypeRSA as an input key for kSecAttrKeyType).
 *
 * I am hesitant to include cssmtype.h, so what I have decided to do is
 * convert the dictionary number we are given to a string and compare it
 * against the relevant "new" API constants.  Hopefully we don't have that
 * many.
 */

static CK_KEY_TYPE
convert_keytype(CFNumberRef type)
{
	int i;
	CFStringRef str = CFStringCreateWithFormat(NULL, NULL, CFSTR("%@"),
						   type);

	for (i = 0; keytype_map[i].keyname; i++) {
		if (CFEqual(str, *keytype_map[i].sec_keytype)) {
			os_log_debug(logsys, "This is a %s",
				     keytype_map[i].keyname);
			CFRelease(str);
			return keytype_map[i].pkcs11_keytype;
		}
	}

	CFRelease(str);

	os_log_debug(logsys, "Keytype is unknown, returning VENDOR_DEFINED");

	return CKK_VENDOR_DEFINED;
}

/*
 * Build our list of objects based on our identities
 */

#define ADD_ATTR_SIZE(attribute, var, size) \
do { \
	void *p = malloc(size); \
	memcpy(p, var, size); \
	if (id_obj_list[id_obj_count].attr_count >= \
	    id_obj_list[id_obj_count].attr_size) { \
		id_obj_list[id_obj_count].attr_size += 5; \
		id_obj_list[id_obj_count].attrs = realloc(id_obj_list[id_obj_count].attrs, \
			id_obj_list[id_obj_count].attr_size * sizeof(CK_ATTRIBUTE)); \
	} \
	id_obj_list[id_obj_count].attrs[id_obj_list[id_obj_count].attr_count].type = attribute; \
	id_obj_list[id_obj_count].attrs[id_obj_list[id_obj_count].attr_count].pValue = p; \
	id_obj_list[id_obj_count].attrs[id_obj_list[id_obj_count].attr_count].ulValueLen = size; \
	id_obj_list[id_obj_count].attr_count++; \
} while (0)

#define ADD_ATTR(attr, var) ADD_ATTR_SIZE(attr, &var, sizeof(var))

#define NEW_OBJECT() \
do { \
	if (++id_obj_count >= id_obj_size) { \
		id_obj_size += 5; \
		id_obj_list = realloc(id_obj_list, id_obj_size * sizeof(*id_obj_list)); \
	} \
} while (0)

/*
 * Build up a list of objects based on our identity list
 */

static void
build_objects(int lock)
{
	int i;
	CK_OBJECT_CLASS cl;
	CK_CERTIFICATE_TYPE ct = CKC_X_509;	/* Only this for now */
	CK_ULONG t;
	CK_BBOOL b;
	CFDataRef d;

	if (lock)
		LOCK_MUTEX(id_mutex);

	if (id_list_count > 0) {
		/* Prime the pump */
		NEW_OBJECT();
		id_obj_count--;
	}

	for (i = 0; i < id_list_count; i++) {
		SecCertificateRef cert = id_list[i].cert;
		CFDataRef subject = NULL, issuer = NULL;

#define OBJINIT() \
do { \
	id_obj_list[id_obj_count].id_index = i; \
	id_obj_list[id_obj_count].attrs = NULL; \
	id_obj_list[id_obj_count].attr_count = 0; \
	id_obj_list[id_obj_count].attr_size = 0; \
} while (0)

		OBJINIT();

		/*
		 * Add in the object for each identity; cert, public key,
		 * private key.  Add in attributes we need.
		 */

		t = i;
		cl = CKO_CERTIFICATE;
		id_obj_list[id_obj_count].class = cl;
		ADD_ATTR(CKA_CLASS, cl);
		ADD_ATTR(CKA_ID, t);
		ADD_ATTR(CKA_CERTIFICATE_TYPE, ct);
		b = CK_TRUE;
		ADD_ATTR(CKA_TOKEN, b);
		ADD_ATTR_SIZE(CKA_LABEL, id_list[i].label,
			      strlen(id_list[i].label));
		d = SecCertificateCopySerialNumberData(cert, NULL);
		ADD_ATTR_SIZE(CKA_SERIAL_NUMBER, CFDataGetBytePtr(d),
			      CFDataGetLength(d));
		CFRelease(d);
		d = SecCertificateCopyData(cert);
		ADD_ATTR_SIZE(CKA_VALUE, CFDataGetBytePtr(d),
			      CFDataGetLength(d));
		get_certificate_info(d, &issuer, &subject);
		CFRelease(d);

		if (subject)
			ADD_ATTR_SIZE(CKA_SUBJECT, CFDataGetBytePtr(subject),
				      CFDataGetLength(subject));
		if (issuer)
			ADD_ATTR_SIZE(CKA_ISSUER, CFDataGetBytePtr(issuer),
				      CFDataGetLength(issuer));

		NEW_OBJECT();
		OBJINIT();

		cl = CKO_PUBLIC_KEY;
		id_obj_list[id_obj_count].class = cl;
		ADD_ATTR(CKA_CLASS, cl);
		ADD_ATTR(CKA_ID, t);
		ADD_ATTR(CKA_KEY_TYPE, id_list[i].keytype);
		b = CK_TRUE;
		ADD_ATTR(CKA_TOKEN, b);
		b = id_list[i].pubcanencrypt;
		ADD_ATTR(CKA_ENCRYPT, b);
		b = id_list[i].pubcanverify;
		ADD_ATTR(CKA_VERIFY, b);
		if (subject)
			ADD_ATTR_SIZE(CKA_SUBJECT, CFDataGetBytePtr(subject),
				      CFDataGetLength(subject));

		NEW_OBJECT();
		OBJINIT();

		cl = CKO_PRIVATE_KEY;
		id_obj_list[id_obj_count].class = cl;
		ADD_ATTR(CKA_CLASS, cl);
		ADD_ATTR(CKA_ID, t);
		ADD_ATTR(CKA_KEY_TYPE, id_list[i].keytype);
		b = CK_TRUE;
		ADD_ATTR(CKA_TOKEN, b);
		ADD_ATTR(CKA_PRIVATE, b);
		b = id_list[i].privcandecrypt;
		ADD_ATTR(CKA_DECRYPT, b);
		b = id_list[i].privcansign;
		ADD_ATTR(CKA_SIGN, b);
		if (subject)
			ADD_ATTR_SIZE(CKA_SUBJECT, CFDataGetBytePtr(subject),
				      CFDataGetLength(subject));

		NEW_OBJECT();

		if (subject)
			CFRelease(subject);
		if (issuer)
			CFRelease(issuer);
	}

	if (lock)
		UNLOCK_MUTEX(id_mutex);
}

/*
 * Free our object list and all associated data
 */

static void
obj_free(struct obj_info **obj, unsigned int *count, unsigned int *size)
{
	int i, j;

	for (i = 0; i < *count; i++) {
		for (j = 0; j < (*obj)[i].attr_count; j++)
			free((*obj)[i].attrs[j].pValue);
		free((*obj)[i].attrs);
	}

	free(*obj);

	*obj = NULL;
	*count = *size = 0;
}

/*
 * Search an object to see if our attributes match.  If we have no
 * attributes then that counts as a match.
 */

static bool
search_object(struct obj_info *obj, CK_ATTRIBUTE_PTR attrs,
	      unsigned int attrcount)
{
	int i, j;

	/*
	 * If we get a valid "hit", then goto next to continue the
	 * attrs loop; if we make to the end of the attrs loop then
	 * we can return 'true'
	 */

	for (i = 0; i < attrcount; i++) {
		for (j = 0; j < obj->attr_count; j++)
			/*
			 * For a match, the type has to be the same, both
			 * have to have the same length, and either both
			 * are NULL pointers or both have the same contents
			 */
			if (obj->attrs[j].type == attrs[i].type &&
			    obj->attrs[j].ulValueLen == attrs[i].ulValueLen) {
			    	/*
				 * We are assuming that we only have one
				 * copy of an attribute in an object.  So
				 * if the attribute doesn't match then
				 * we can short-circuit the match now
				 */
				if ((obj->attrs[j].pValue == NULL ||
				     attrs[i].pValue == NULL) &&
				    (obj->attrs[j].pValue != attrs[i].pValue))
					return false;

				/*
				 * Both are valid pointers and have the same
				 * length, so do a memcmp().  But again, if
				 * doesn't match than return false.
				 */
				if (memcmp(obj->attrs[j].pValue,
					   attrs[i].pValue,
					   attrs[i].ulValueLen) == 0)
					goto next;
				else
					return false;
			}

		/*
		 * If we made it here then that means we went through
		 * every attribute in this object and didn't find a match
		 * so we can return false now.
		 */

		return false;
next:	;
	}

	return true;
}

/*
 * Search an object for a particular attribute; return NULL if not found
 */

static CK_ATTRIBUTE_PTR
find_attribute(struct obj_info *obj, CK_ATTRIBUTE_TYPE type)
{
	int i;

	for (i = 0; i < obj->attr_count; i++)
		if (obj->attrs[i].type == type)
			return &obj->attrs[i];

	return NULL;
}

/*
 * Output information about an attribute
 */

static void
dump_attribute(const char *str, CK_ATTRIBUTE_PTR attr)
{
	if (!os_log_debug_enabled(logsys))
		return;

	switch (attr->type) {
	case CKA_CLASS:
		os_log_debug(logsys, "%s: CKA_CLASS: %s", str,
			     getCKOName(*((CK_OBJECT_CLASS *) attr->pValue)));
		break;
	default:
		os_log_debug(logsys, "%s: %s, len = %lu, val = %p", str,
			     getCKAName(attr->type), attr->ulValueLen,
					attr->pValue);
	}
}

/*
 * See if a particular key is set in our preferences dictionary.
 *
 * It may be a single string, or an array (that's all we support right now).
 * Return true if it matches (or was found in the array).
 */

static bool
prefkey_found(const char *key, const char *value)
{
	CFTypeID id;
	CFPropertyListRef propref;
	CFStringRef keyref, valref;
	bool ret = false;

	keyref = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);

	propref = CFPreferencesCopyAppValue(keyref, CFSTR(APP_DOMAIN));
	CFRelease(keyref);

	if (! propref)
		return false;

	valref = CFStringCreateWithCString(NULL, value, kCFStringEncodingUTF8);

	id = CFGetTypeID(propref);

	if (id == CFStringGetTypeID()) {
		/*
		 * If this is a string, then it's a single application
		 * name.  See if it is equal.
		 */
		ret = CFEqual(valref, propref);
	} else if (id == CFArrayGetTypeID()) {
		/*
		 * This should be a list of application names, so
		 * search the array to see if our key is in there.
		 * They should be a series of CFStrings.
		 */
		ret = CFArrayContainsValue(propref,
				     CFRangeMake(0, CFArrayGetCount(propref)),
				     valref);
	} else {
		logtype("Unknown preference return type", propref);
		ret = false;
	}

	CFRelease(valref);
	CFRelease(propref);

	return ret;
}

/*
 * Free a session
 */

static void
sess_free(struct session *se)
{
	int i;

	LOCK_MUTEX(se->mutex);

	for (i = 0; i < se->search_attrs_count; i++)
		free(se->search_attrs[i].pValue);

	free(se->search_attrs);

	if (se->sig_key)
		CFRelease(se->sig_key);

	if (se->ver_key)
		CFRelease(se->ver_key);

	UNLOCK_MUTEX(se->mutex);
	DESTROY_MUTEX(se->mutex);
	free(se);
}

/*
 * Free all sessions; call with sess_mutex locked.
 */

static void
sess_list_free(void)
{
	int i;

	for (i = 0; i < sess_list_count; i++)
		if (sess_list[i])
			sess_free(sess_list[i]);

	sess_list_count = sess_list_size = 0;

	free(sess_list);

	sess_list = NULL;
}

/*
 * Logout from our token
 */

static void
token_logout(void)
{
	/*
	 * Log out from all identities; since we now share a lacontext
	 * across identities, we only need to do this once.
	 */

	lacontext_logout(lacontext);

	logged_in = false;
}
