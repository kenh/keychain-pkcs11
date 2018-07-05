/*
 * Our main driver for the keychain_pkcs11 module
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <stdio.h>
#include <string.h>

#include "mypkcs11.h"

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
	return CKR_FUNCTION_NOT_SUPPORTED; \
}

/*
 * Our implementation of C_GetFunctionList(), which just returns a pointer
 * to our function list
 */

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR pPtr)
{
	if (! pPtr)
		return CKR_ARGUMENTS_BAD;

	*pPtr = &function_list;
	return CKR_OK;
}

/*
 * These are in PKCS11 order, to make searching easier
 */

NOTSUPPORTED(C_Initialize, (CK_VOID_PTR p))
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
NOTSUPPORTED(CK_VerifyFinal, (CK_SESSION_HANDLE session, CK_BYTE_PTR sig, CK_ULONG siglen))
