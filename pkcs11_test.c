/*
 *  pkcs11_test.c
 *  KeychainToken
 *
 *  Created by Jay Kline on 6/24/09.
 *  Copyright 2009,2016
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "pkcs11_test.h"
#include "config.h"

#include <stdarg.h>

/*
 * Dump one or more attributes of an object
 */

static CK_RV dump_attrs(CK_FUNCTION_LIST_PTR, CK_SESSION_HANDLE,
		  CK_OBJECT_HANDLE, CK_ULONG *, ...);

/*
 * Our routines to output attribute information
 */

struct attr_handler {
    CK_ATTRIBUTE_TYPE attr;	/* Attribute */
    const char *label;	/* Attribute printed label */
    void (*dumper)(unsigned char *, unsigned int);	/* dumper function */
};

static void hexify_dump(unsigned char *, unsigned int);
static void string_dump(unsigned char *, unsigned int);
static void certtype_dump(unsigned char *, unsigned int);
static void length_dump(unsigned char *, unsigned int);
static void class_dump(unsigned char *, unsigned int);
static void mech_dump(unsigned char *, unsigned int);
static void mechlist_dump(unsigned char *, unsigned int);
static void keytype_dump(unsigned char *, unsigned int);

static struct attr_handler id_attr = {
    CKA_ID, "Key Identifier", hexify_dump
};

static struct attr_handler ctype_attr = {
    CKA_CERTIFICATE_TYPE, "Certificate Type", certtype_dump
};

static struct attr_handler value_attr = {
    CKA_VALUE, "Object value", length_dump
};

static struct attr_handler class_attr = {
    CKA_CLASS, "Object class", class_dump
};

static struct attr_handler app_attr = {
    CKA_APPLICATION, "Application Description", string_dump
};

static struct attr_handler objid_attr = {
    CKA_OBJECT_ID, "Object ID", hexify_dump
};

static struct attr_handler genmech_attr = {
    CKA_KEY_GEN_MECHANISM, "Key Generation Mechanism", mech_dump
};

static struct attr_handler allowedmech_attr = {
    CKA_ALLOWED_MECHANISMS, "Allowed Mechanisms", mechlist_dump
};

static struct attr_handler subject_attr = {
    CKA_SUBJECT, "Subject name", hexify_dump
};

static struct attr_handler keytype_attr = {
    CKA_KEY_TYPE, "Key type", keytype_dump
};

#if 0
static struct attr_handler value_attr = {
    CKA_VALUE, "Object value", hexify_dump
};
#endif

int main(int argc, char *argv[]) {
    CK_RV rv;
    CK_FUNCTION_LIST_PTR p11p;
    CK_SLOT_ID slot = -1;
    CK_SESSION_HANDLE hSession;
    /* CK_UTF8CHAR pin[64]; */
    /* CK_ULONG pinLen = sizeof(pin) - 1; */
    /* CK_BYTE label[32]; */

    CK_INFO info;
    CK_SLOT_INFO sInfo;
    CK_TOKEN_INFO tInfo;
    CK_SESSION_INFO sessionInfo;

    CK_OBJECT_HANDLE_PTR phObject;
    CK_ULONG maxSize;
    CK_ULONG count;

    CK_OBJECT_CLASS cls;
    CK_CERTIFICATE_TYPE certtype;
    CK_ATTRIBUTE attrs[10];
    CK_ULONG ulValue;

    CK_ULONG numSlots = 0;
    CK_SLOT_ID_PTR slotList = NULL;
    CK_SLOT_ID validSlot = -1;
    CK_SLOT_INFO slotInfo;


    int i;

    while ((i = getopt(argc, argv, "n:s:")) != -1) {
	switch (i) {
	case 'n':
#ifdef HAVE_SETPROGNAME
	    setprogname(optarg);
#endif /* HAVE_SETPROGNAME */
	    break;
	case 's':
	    slot = atoi(optarg);
	    break;
	case '?':
	default:
	    fprintf(stderr, "Usage: %s [-s slotnumber] [-n progname] "
		    "[pkcs11_library]\n", argv[0]);
	    exit(1);
	}
    }

    argc -= optind - 1;
    argv += optind - 1;

    if(argc == 1) {
        rv = load_library("keychain_pkcs11.dylib", &p11p);
    } else {
        rv = load_library(argv[1], &p11p);
    }
    if (rv != CKR_OK) {
        fprintf(stderr, "Error loading library (rv = %X)\n", (unsigned int) rv);
        return(1);
    }

    rv = p11p->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error initalizing library (rv = %X)\n", (unsigned int) rv);
        return(2);
    }

    memset(&info, 0, sizeof(info));
    rv = p11p->C_GetInfo(&info);
    if (rv == CKR_OK) {
        printf("PKCS#11 Version: %d.%d\n",info.cryptokiVersion.major, info.cryptokiVersion.minor);
        printf("Lib manufacturer: %s\n", stringify(info.manufacturerID, 32));
        printf("Lib description: %s\n", stringify(info.libraryDescription,32));
        printf("Lib version: %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);
        printf("Lib flags: %d\n", (int) info.flags);
    } else {
        fprintf(stderr, "Unable to get info (rv = %X)\n", (unsigned int) rv);
    }


    rv = p11p->C_GetSlotList(TRUE, NULL, &numSlots);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error getting Slot List\n");
        return(rv);
    }
    printf("Found %d slots\n", (int) numSlots);

    slotList = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * (numSlots + 1));
    if (!slotList) return(-1);

    rv = p11p->C_GetSlotList(TRUE, slotList, &numSlots);
    if (rv != CKR_OK) {
        free(slotList);
        fprintf(stderr, "Error getting Slot List\n");
        return(rv);
    }

    for (i=0; i < numSlots; i++) {
        memset(&slotInfo, 0, sizeof(slotInfo));
	if (! p11p->C_GetSlotInfo) {
	    fprintf(stderr, "C_GetSlotInfo is NULL, continuing ...\n");
	    continue;
	}
        rv = p11p->C_GetSlotInfo(slotList[i], &slotInfo);
        if (rv != CKR_OK) continue;
        if (!(slotInfo.flags & CKF_TOKEN_PRESENT)) {
            fprintf(stderr,"Slot %d has no token present\n", (int) slotList[i]);
            continue;
        } else {
            printf("Slot %d description: %s\n", (int) slotList[i],  stringify(slotInfo.slotDescription, 64));
        }
        validSlot = slotList[i];
    }

    if (! p11p->C_GetSlotInfo && numSlots > 0) {
	fprintf(stderr, "C_GetSlotInfo is NULL, assuming first slot "
		"is valid\n");
	validSlot = 0;
    }

    if (slotList) free(slotList);
    if (validSlot == -1)
        fprintf(stderr, "No slots with tokens!\n");



    if (slot == -1)
	slot = validSlot;












    memset(&sInfo, 0, sizeof(sInfo));
    if (p11p->C_GetSlotInfo) {
	rv = p11p->C_GetSlotInfo(slot, &sInfo);
    } else {
	rv = CKR_FUNCTION_NOT_SUPPORTED;
    }
    if (rv == CKR_OK) {
        printf("Slot Description: %s\n", stringify(sInfo.slotDescription, 64));
        printf("Slot Manufacturer: %s\n", stringify(sInfo.manufacturerID, 32));
        printf("Slot HW version: %d.%d\n", sInfo.hardwareVersion.major, sInfo.hardwareVersion.minor);
        printf("Slot FW version: %d.%d\n", sInfo.firmwareVersion.major, sInfo.firmwareVersion.minor);
        printf("Slot has token: %s\n", (sInfo.flags & CKF_TOKEN_PRESENT ? "yes" : "no"));
        printf("Slot supports removeable tokens: %s\n", (sInfo.flags & CKF_REMOVABLE_DEVICE ? "yes" : "no"));
        printf("Slot is a hardware slot: %s\n", (sInfo.flags & CKF_HW_SLOT ? "yes" : "no"));
    } else {
        fprintf(stderr, "Error getting slot info (rv = %X)\n", (unsigned int) rv);
    }

    memset(&tInfo, 0, sizeof(tInfo));
    rv = p11p->C_GetTokenInfo(slot, &tInfo);
    if (rv == CKR_OK) {
        printf("Token label: %s\n", stringify(tInfo.label, 32));
        printf("Token Manufacturer: %s\n", stringify(tInfo.manufacturerID, 32));
        printf("Token Model: %s\n", stringify(tInfo.model,16));
        printf("Token Serial: %s\n", stringify(tInfo.serialNumber,16));
        printf("Token flags = 0x%x (%d)\n", (unsigned int) tInfo.flags, (int) tInfo.flags);
        printf("Token MaxSessionCount = %d\n", (int) tInfo.ulMaxSessionCount);
        printf("Token SessionCount = %d\n", (int) tInfo.ulSessionCount);
        printf("Token MaxRwSessionCount = %d\n", (int) tInfo.ulMaxRwSessionCount);
        printf("Token RwSessionCount = %d\n", (int) tInfo.ulRwSessionCount);
        printf("Token Max PIN len = %d\n", (int) tInfo.ulMaxPinLen);
        printf("Token Min PIN len = %d\n", (int) tInfo.ulMinPinLen);
        printf("Token total public mem = %d\n", (int) tInfo.ulTotalPublicMemory);
        printf("Token free public mem = %d\n", (int) tInfo.ulFreePublicMemory);
        printf("Token total private mem = %d\n", (int) tInfo.ulTotalPrivateMemory);
        printf("Token free private mem = %d\n", (int) tInfo.ulFreePrivateMemory);
        printf("Token hardware version = %d.%d\n", tInfo.hardwareVersion.major,
               tInfo.hardwareVersion.minor);
        printf("Token firmware version = %d.%d\n", tInfo.firmwareVersion.major,
               tInfo.firmwareVersion.minor);
        printf("Token utcTime = %s\n", stringify(tInfo.utcTime, 16));

    } else {
        fprintf(stderr, "Error getting token info (rv = %X)\n", (unsigned int) rv);
    }

    rv = p11p->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error opening session (rv = %X)\n", (unsigned int) rv);
        goto cleanup;
    }

    memset(&sessionInfo, 0, sizeof(sessionInfo));
    if (p11p->C_GetSessionInfo)
	rv = p11p->C_GetSessionInfo(hSession, &sessionInfo);
    else
	rv = CKR_FUNCTION_NOT_SUPPORTED;

    if (rv == CKR_OK) {
        printf("Session slot: %d\n", (int) sessionInfo.slotID);
        printf("Session state: %d\n", (int) sessionInfo.state);
        printf("Session flags: %d\n", (int) sessionInfo.flags);
        printf("Session device errors: %d\n", (int) sessionInfo.ulDeviceError);
    } else {
        fprintf(stderr, "Unable to get session info (rv = %X)\n", (unsigned int) rv);
    }


    rv = login(p11p, &tInfo, hSession, 0, NULL, 0);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error logging into token (rv = %X)\n", (unsigned int) rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }




    rv = p11p->C_FindObjectsInit(hSession, NULL, 0);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error initializing Find Objects (rv = %X)\n", (unsigned int) rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }

    maxSize = 10;
    phObject = malloc(maxSize * sizeof(CK_OBJECT_HANDLE_PTR));


    do {
	rv = p11p->C_FindObjects(hSession, phObject, maxSize, &count);
	    if (rv != CKR_OK) {
		fprintf(stderr, "Error Finding Objects (rv = %X)\n",
			(unsigned int) rv);
		(void)p11p->C_CloseSession(hSession);
		goto cleanup;
	    }

	fprintf(stderr, "Found %d objects\n", (int) count);

	for(i = 0; i < count; i++) {
	    printf("Object[%d] handle: %u\n", i, (unsigned int) phObject[i]);

	    rv = dump_attrs(p11p, hSession, phObject[i], &ulValue, &class_attr,
			    (void *) NULL);

	    if (rv != CKR_OK)
		continue;

	    switch(ulValue) {
            case CKO_DATA:
		dump_attrs(p11p, hSession, phObject[i], NULL, &app_attr,
			   &objid_attr, &value_attr, (void *) NULL);
                break;
            case CKO_CERTIFICATE:
		dump_attrs(p11p, hSession, phObject[i], NULL, &ctype_attr,
			   &id_attr, &value_attr, (void *) NULL);
                break;
	    case CKO_PUBLIC_KEY:
	    case CKO_PRIVATE_KEY:
		dump_attrs(p11p, hSession, phObject[i], NULL, &id_attr,
			   &keytype_attr, &genmech_attr, &allowedmech_attr,
			   &subject_attr, (void *) NULL);
		break;
	    }
	}
    } while (count > 0);

    rv = p11p->C_FindObjectsFinal(hSession);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error finalizing Finding Objects (rv = %X)\n", (unsigned int) rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }


    cls = CKO_CERTIFICATE; //type CK_OBJECT_CLASS
    attrs[0].type = CKA_CLASS;
    attrs[0].pValue = &cls;
    attrs[0].ulValueLen = sizeof cls;

    certtype = CKC_X_509; //type CK_CERTIFICATE_TYPE
    attrs[1].type = CKA_CERTIFICATE_TYPE;
    attrs[1].pValue = &certtype;
    attrs[1].ulValueLen = sizeof certtype;


    rv = p11p->C_FindObjectsInit(hSession, attrs, 2);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error initializing Find Objects (rv = %X)\n", (unsigned int) rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }

    do {
	rv = p11p->C_FindObjects(hSession, phObject, maxSize, &count);
	if (rv != CKR_OK) {
	    fprintf(stderr, "Error Finding Objects (rv = %X)\n", (unsigned int) rv);
	    (void)p11p->C_CloseSession(hSession);
	    goto cleanup;
	}

	fprintf(stderr, "Found %d objects\n", (int) count);

	for(i = 0; i < count; i++) {
	    rv = dump_attrs(p11p, hSession, phObject[i], &ulValue, &class_attr,
			    (void *) NULL);

	    if (rv != CKR_OK)
		continue;

	    switch(ulValue) {
            case CKO_CERTIFICATE:
		dump_attrs(p11p, hSession, phObject[i], NULL, &ctype_attr,
			   &id_attr, &value_attr, (void *) NULL);
                break;
	    }
	}
    } while (count > 0);

    rv = p11p->C_FindObjectsFinal(hSession);



    cls = CKA_VENDOR_DEFINED; //type CK_OBJECT_CLASS
    attrs[0].type = CKA_CLASS;
    attrs[0].pValue = &cls;
    attrs[0].ulValueLen = sizeof cls;

    rv = p11p->C_FindObjectsInit(hSession, attrs, 1);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error initializing Find Objects (rv = %X)\n", (unsigned int) rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }

    do {
	rv = p11p->C_FindObjects(hSession, phObject, maxSize, &count);
	if (rv != CKR_OK) {
		fprintf(stderr, "Error Finding Objects (rv = %X)\n",
			(unsigned int) rv);
		(void)p11p->C_CloseSession(hSession);
		goto cleanup;
	}
	fprintf(stderr, "Found %d objects\n", (int) count);

	for(i = 0; i < count; i++) {
	    printf("Object[%d] handle: %u\n", i, (unsigned int) phObject[i]);
	    rv = dump_attrs(p11p, hSession, phObject[i], &ulValue, &class_attr,
			    (void *) NULL);

	    if (rv != CKR_OK)
		continue;
	    switch(ulValue) {
            case CKO_DATA:
		dump_attrs(p11p, hSession, phObject[i], NULL, &app_attr,
			   &objid_attr, &value_attr, (void *) NULL);
		break;
	    }
        }

    } while (count > 0);

    rv = p11p->C_FindObjectsFinal(hSession);



#if 0

    rv = login(p11p, &tInfo, hSession, 0, NULL, 0);
     if (rv != CKR_OK) {
         fprintf(stderr, "Error logging into token (rv = %X)\n", (unsigned int) rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
     }
#endif

    if (p11p->C_Logout)
	p11p->C_Logout(hSession);
    (void)p11p->C_CloseSession(hSession);
cleanup:
    if (p11p) p11p->C_Finalize(0);


    return 0;
}

CK_RV login(CK_FUNCTION_LIST_PTR p11p, CK_TOKEN_INFO_PTR tInfo, CK_SESSION_HANDLE hSession, int admin, CK_UTF8CHAR *password, CK_ULONG passwordLen) {
    CK_UTF8CHAR pin[64];
    CK_ULONG pinLen = sizeof(pin) - 1;
    CK_RV rv;

    if (tInfo->flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
	printf("Protected authentication path found, not prompting PIN\n");
	return p11p->C_Login(hSession, admin == 1 ? CKU_SO : CKU_USER, NULL, 0);
    }

    if (passwordLen > 0 && password != NULL && passwordLen <= pinLen) {
        memcpy(pin, password, passwordLen);
        pinLen = passwordLen;
    } else {
        printf("Enter %sPIN: ", (admin == 1) ? "admin " : "");
        rv = getPassword(pin, &pinLen);
        if (rv!= 0)
            return(-1);
    }

    if (admin == 1)
        rv = p11p->C_Login(hSession, CKU_SO, pin, pinLen);
    else
        rv = p11p->C_Login(hSession, CKU_USER, pin, pinLen);

    memset(pin, 0, sizeof(pin));
    return(rv);
}


CK_RV load_library(char *library, CK_FUNCTION_LIST_PTR *p11p) {
    CK_RV rv;
    LpHandleType p11lib_handle = NULL;
    CK_RV (*getflist)(CK_FUNCTION_LIST_PTR_PTR);

    if (!library) {
        *p11p = NULL;
        return(-1);
    }
#ifdef _WIN32
    p11lib_handle = LoadLibrary(library);
#else
    p11lib_handle = dlopen(library, RTLD_NOW);
#endif
    if (p11lib_handle == NULL) {
#ifdef _WIN32
        printf("Error loading PKCS11 library: %s\n", (char *)GetLastError);
#else
        printf("Error loading PKCS11 library: %s\n", dlerror());
#endif
        return(EXIT_FAILURE);
    }

    getflist = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
    GetFuncFromMod(p11lib_handle,
                   "C_GetFunctionList");
    if (getflist == NULL) {
#ifdef _WIN32
        printf("Error finding \"C_GetFunctionList\" symbol: %s\n",
               (char *)GetLastError);
#else
        printf("Error finding \"C_GetFunctionList\" symbol: %s\n", dlerror());
#endif
        return(EXIT_FAILURE);
    }

    rv = (*getflist)(p11p);
    if (rv != CKR_OK) {
        printf("Error calling \"C_GetFunctionList\" (rv = %d)\n", (int) rv);
        return(rv);
    }
    return(CKR_OK);
}

CK_RV getPassword(CK_UTF8CHAR *pass, CK_ULONG *length) {
#ifndef _WIN32
    struct termios t, save;
    int ret;
#else
    HANDLE handle;
    DWORD old_mode, new_mode;
#endif
    char *cp;

    if (pass == NULL || length == NULL)
        return(-1);

#ifndef _WIN32
    memset(&t, 0, sizeof(t));
    ret = tcgetattr(fileno(stdin), &t);
    if (ret) return(CKR_GENERAL_ERROR);

    save = t;
    t.c_lflag &= ~ECHO;

    ret = tcsetattr(fileno(stdin), TCSANOW, &t);
    if (ret) return(CKR_GENERAL_ERROR);
#else
    handle = GetStdHandle(STD_INPUT_HANDLE);
    if (handle == INVALID_HANDLE_VALUE)
        return ENOTTY;
    if (!GetConsoleMode(handle, &old_mode))
        return ENOTTY;

    new_mode = old_mode;
    new_mode |= ( ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT );
    new_mode &= ~( ENABLE_ECHO_INPUT );

    if (!SetConsoleMode(handle, new_mode))
        return ENOTTY;
    if (!SetConsoleMode(handle, old_mode))
        return ENOTTY;
    if (!SetConsoleMode(handle, new_mode))
        return ENOTTY;
#endif

    (void)fgets((char *)pass, (int)*length, stdin);
    cp = strchr((char *)pass, '\n');
    if (cp) *cp = (char)NULL;
    else pass[*length - 1] = (char)NULL;

    *length = (CK_ULONG)strlen((char *)pass);

#ifndef _WIN32
    ret = tcsetattr(fileno(stdin), TCSANOW, &save);
    if (ret) return(CKR_GENERAL_ERROR);
#else
    if (!SetConsoleMode(handle, old_mode))
        return ENOTTY;
#endif
    printf("\n");
    return(0);

}

/*
 * Dump out attributes for a specific object.  Argument list should end
 * with a NULL.
 */

static CK_RV
dump_attrs(CK_FUNCTION_LIST_PTR p11p, CK_SESSION_HANDLE session,
	   CK_OBJECT_HANDLE obj, CK_ULONG *retval, ...)
{
    va_list ap;
    struct attr_handler *ah;
    CK_ATTRIBUTE template;
    CK_RV rv, rvret = CKR_OK;
    bool valret = false;

    va_start(ap, retval);

    while ((ah = va_arg(ap, struct attr_handler *))) {
	template.type = ah->attr;
	template.pValue = NULL;
	template.ulValueLen = 0;
	rv = p11p->C_GetAttributeValue(session, obj, &template, 1);
	if (rv != CKR_OK) {
	    printf("%s: C_GetAttributeValue returned %lu\n", ah->label, rv);
	    rvret = rv;
	    continue;
	}
	if (template.ulValueLen == CK_UNAVAILABLE_INFORMATION) {
	    printf("%s: Information Unavailable\n", ah->label);
	    continue;
	}
	template.pValue = malloc(template.ulValueLen);
	rv = p11p->C_GetAttributeValue(session, obj, &template, 1);
	if (rv != CKR_OK) {
	    printf("%s: Second call to C_GetAttributeValue failed: %lu\n",
		   ah->label, rv);
	    free(template.pValue);
	    rvret = rv;
	    continue;
	}
	printf("%s: ", ah->label);
	(*ah->dumper)(template.pValue, template.ulValueLen);
	printf("\n");

	/*
	 * If we were passed in a value to return, then return the first
	 * item that was the correct size (sizeof(CK_ULONG))
	 */

	if (retval && !valret) {
	    *retval = *((CK_ULONG *) template.pValue);
	    valret = true;
	}

	free(template.pValue);
    }

    va_end(ap);

    return rvret;
}

/*
 * Dump attribute information, using hexify()
 */

static void
hexify_dump(unsigned char *data, unsigned int len)
{
    char *s = hexify(data, (int) len);

    printf("%s", s);
    free(s);
}

/*
 * Dump certificate type information
 */

static void
certtype_dump(unsigned char *data, unsigned int len)
{
    CK_CERTIFICATE_TYPE *type = (CK_CERTIFICATE_TYPE *) data;

    if (len != sizeof(CK_CERTIFICATE_TYPE)) {
    	printf("Unexpected length (got %d, expected %d)", (int) len,
	       (int) sizeof(CK_CERTIFICATE_TYPE));
	return;
    }

    switch (*type) {
    case CKC_X_509:
	printf("X.509 Certificate");
	break;
    case CKC_WTLS:
	printf("WTLS Certificate");
	break;
    case CKC_X_509_ATTR_CERT:
	printf("X.509 Attribute Certificate");
	break;
    default:
	printf("Unknown certificate type: %#lx", *type);
    }
}

/*
 * Dump class information
 */

static void
class_dump(unsigned char *data, unsigned int len)
{
    CK_OBJECT_CLASS *class = (CK_OBJECT_CLASS *) data;

    if (len != sizeof(CK_OBJECT_CLASS)) {
    	printf("Unexpected length (got %d, expected %d)", (int) len,
	       (int) sizeof(CK_OBJECT_CLASS));
	return;
    }

    printf("%s", getCKOName(*class));
}

/*
 * Just dump length
 */

static void 
length_dump(unsigned char *data, unsigned int len)
{
    printf("%u bytes", len);
}

/*
 * Dump this as a string
 */

static void
string_dump(unsigned char *data, unsigned int len)
{
    printf("%s", stringify(data, len));
}

/*
 * Dump this as a single mechanism
 */

static void
mech_dump(unsigned char *data, unsigned int len)
{
    CK_MECHANISM_TYPE *mech = (CK_MECHANISM_TYPE *) data;

    if (len != sizeof(CK_MECHANISM_TYPE)) {
    	printf("Unexpected length (got %d, expected %d)", (int) len,
	       (int) sizeof(CK_MECHANISM_TYPE));
	return;
    }

    printf("%s", getCKMName(*mech));
}

/*
 * Dump a list of mechanisms
 */

static void
mechlist_dump(unsigned char *data, unsigned int len)
{
    CK_MECHANISM_TYPE_PTR mechlist = (CK_MECHANISM_TYPE_PTR) data;
    unsigned int count = len / sizeof(CK_MECHANISM_TYPE);
    unsigned int i;

    for (i = 0; i < count; i++)
	printf("%s%s", i > 0 ? ", " : "", getCKMName(mechlist[i]));

}

/*
 * Dump a key type
 */

static void
keytype_dump(unsigned char *data, unsigned int len)
{
    CK_KEY_TYPE *keytype = (CK_KEY_TYPE *) data;

    if (len != sizeof(CK_KEY_TYPE)) {
    	printf("Unexpected length (got %d, expected %d)", (int) len,
	       (int) sizeof(CK_KEY_TYPE));
	return;
    }

    switch (*keytype) {
    case CKK_RSA:
    	printf("RSA Key");
	break;
    case CKK_DSA:
    	printf("DSA Key");
	break;
    default:
	printf("Unknown key type: %#lx", *keytype);
    }
}
