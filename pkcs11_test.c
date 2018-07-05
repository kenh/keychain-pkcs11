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



int main(int argc, char *argv[]) {
    CK_RV rv;
    CK_FUNCTION_LIST_PTR p11p;
    CK_SLOT_ID slot;
    CK_SESSION_HANDLE hSession;
    CK_UTF8CHAR pin[64];
    CK_ULONG pinLen = sizeof(pin) - 1;
    CK_BYTE label[32];

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
    if(argc == 1) {
        rv = load_library("keychain_pkcs11.dylib", &p11p);
    } else {
        rv = load_library(argv[1], &p11p);
    }
    if (rv != CKR_OK) {
        fprintf(stderr, "Error loading library (rv = %X)\n", rv);
        return(1);
    }

    rv = p11p->C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error initalizing library (rv = %X)\n", rv);
        return(2);
    }

    memset(&info, 0, sizeof(info));
    rv = p11p->C_GetInfo(&info);
    if (rv == CKR_OK) {
        printf("PKCS#11 Version: %d.%d\n",info.cryptokiVersion.major, info.cryptokiVersion.minor);
        printf("Lib manufacturer: %s\n", stringify(info.manufacturerID, 32));
        printf("Lib description: %s\n", stringify(info.libraryDescription,32));
        printf("Lib version: %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);
        printf("Lib flags: %d\n", info.flags);
    } else {
        fprintf(stderr, "Unable to get info (rv = %X)\n", rv);
    }


    rv = p11p->C_GetSlotList(TRUE, NULL, &numSlots);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error getting Slot List\n");
        return(rv);
    }
    printf("Found %d slots\n", numSlots);

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
        rv = p11p->C_GetSlotInfo(slotList[i], &slotInfo);
        if (rv != CKR_OK) continue;
        if (!(slotInfo.flags & CKF_TOKEN_PRESENT)) {
            fprintf(stderr,"Slot %d has no token present\n", slotList[i]);
            continue;
        } else {
            printf("Slot %d description: %s\n", slotList[i],  stringify(slotInfo.slotDescription, 64));
        }
        validSlot = slotList[i];
    }

    if (slotList) free(slotList);
    if (validSlot == -1)
        fprintf(stderr, "No slots with tokens!\n");



    slot = validSlot;












    memset(&sInfo, 0, sizeof(sInfo));
    rv = p11p->C_GetSlotInfo(slot, &sInfo);
    if (rv == CKR_OK) {
        printf("Slot Description: %s\n", stringify(sInfo.slotDescription, 64));
        printf("Slot Manufacturer: %s\n", stringify(sInfo.manufacturerID, 32));
        printf("Slot HW version: %d.%d\n", sInfo.hardwareVersion.major, sInfo.hardwareVersion.minor);
        printf("Slot FW version: %d.%d\n", sInfo.firmwareVersion.major, sInfo.firmwareVersion.minor);
        printf("Slot has token: %s\n", (sInfo.flags & CKF_TOKEN_PRESENT ? "yes" : "no"));
        printf("Slot supports removeable tokens: %s\n", (sInfo.flags & CKF_REMOVABLE_DEVICE ? "yes" : "no"));
        printf("Slot is a hardware slot: %s\n", (sInfo.flags & CKF_HW_SLOT ? "yes" : "no"));
    } else {
        fprintf(stderr, "Error getting slot info (rv = %X)\n", rv);
    }

    memset(&tInfo, 0, sizeof(tInfo));
    rv = p11p->C_GetTokenInfo(slot, &tInfo);
    if (rv == CKR_OK) {
        printf("Token label: %s\n", stringify(tInfo.label, 32));
        printf("Token Manufacturer: %s\n", stringify(tInfo.manufacturerID, 32));
        printf("Token Model: %s\n", stringify(tInfo.model,16));
        printf("Token Serial: %s\n", stringify(tInfo.serialNumber,16));
        printf("Token flags = 0x%x (%d)\n", tInfo.flags, tInfo.flags);
        printf("Token MaxSessionCount = %d\n", tInfo.ulMaxSessionCount);
        printf("Token SessionCount = %d\n", tInfo.ulSessionCount);
        printf("Token MaxRwSessionCount = %d\n", tInfo.ulMaxRwSessionCount);
        printf("Token RwSessionCount = %d\n", tInfo.ulRwSessionCount);
        printf("Token Max PIN len = %d\n", tInfo.ulMaxPinLen);
        printf("Token Min PIN len = %d\n", tInfo.ulMinPinLen);
        printf("Token total public mem = %d\n", tInfo.ulTotalPublicMemory);
        printf("Token free public mem = %d\n", tInfo.ulFreePublicMemory);
        printf("Token total private mem = %d\n", tInfo.ulTotalPrivateMemory);
        printf("Token free private mem = %d\n", tInfo.ulFreePrivateMemory);
        printf("Token hardware version = %d.%d\n", tInfo.hardwareVersion.major,
               tInfo.hardwareVersion.minor);
        printf("Token firmware version = %d.%d\n", tInfo.firmwareVersion.major,
               tInfo.firmwareVersion.minor);
        printf("Token utcTime = %s\n", stringify(tInfo.utcTime, 16));

    } else {
        fprintf(stderr, "Error getting token info (rv = %X)\n", rv);
    }

    rv = p11p->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error opening session (rv = %X)\n", rv);
        goto cleanup;
    }

    memset(&sessionInfo, 0, sizeof(sessionInfo));
    rv = p11p->C_GetSessionInfo(hSession, &sessionInfo);
    if (rv == CKR_OK) {
        printf("Session slot: %d\n", sessionInfo.slotID);
        printf("Session state: %d\n", sessionInfo.state);
        printf("Session flags: %d\n", sessionInfo.flags);
        printf("Session device errors: %d\n", sessionInfo.ulDeviceError);
    } else {
        fprintf(stderr, "Unable to get session info (rv = %X)\n", rv);
    }


    rv = login(p11p, hSession, 0, NULL, 0);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error logging into token (rv = %X)\n", rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }




    rv = p11p->C_FindObjectsInit(hSession, NULL, 0);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error initializing Find Objects (rv = %X)\n", rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }

    maxSize = 10;
    phObject = malloc(maxSize * sizeof(CK_OBJECT_HANDLE_PTR));


    rv = p11p->C_FindObjects(hSession, phObject, maxSize, &count);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error Finding Objects (rv = %X)\n", rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }
    fprintf(stderr, "Found %d objects\n", count);

    for(i = 0; i < count; i++) {
        printf("Object[%d] handle: %u\n", i, phObject[i]);

        attrs[0].type = CKA_CLASS;
        attrs[0].pValue = &ulValue;
        attrs[0].ulValueLen = sizeof(CK_ULONG);

        rv = p11p->C_GetAttributeValue(hSession, phObject[i], attrs, 1);
        if(rv != CKR_OK) {
            fprintf(stderr, "Error getting object attributes (rv = %X)\n", rv);
            (void)p11p->C_CloseSession(hSession);
            goto cleanup;
        }


        fprintf(stderr, "  Class: 0x%X ", ulValue);
        switch(ulValue) {
            case CKO_DATA:
                {
                    fprintf(stderr, "CKO_DATA\n");

                }



                break;
            case CKO_CERTIFICATE:
            {
                CK_CERTIFICATE_TYPE certType;
                CK_BYTE certData[2048];
                unsigned char keyId[20];
                int j;

                memset(&certType,0,sizeof(certType));
                memset(certData,0,sizeof(certData));
                memset(keyId,0,sizeof(keyId));

                fprintf(stderr, "CKO_CERTIFICATE\n");

                attrs[0].type = CKA_CERTIFICATE_TYPE;
                attrs[0].pValue = &certType;
                attrs[0].ulValueLen = sizeof(certType);

                attrs[1].type = CKA_ID;
                attrs[1].pValue = &keyId;
                attrs[1].ulValueLen = sizeof(keyId);

                attrs[2].type = CKA_VALUE;
                attrs[2].pValue = &certData;
                attrs[2].ulValueLen = sizeof(certData);



                for(j=0;j<4;j++) {
                    rv = p11p->C_GetAttributeValue(hSession, phObject[i], &(attrs[j]), 1);
                    if(rv != CKR_OK) {
                        fprintf(stderr, "Error getting object attributes for %d (rv = 0x%X)\n",j, rv);

                    }
                }


                fprintf(stderr, "    type: %d\n", certType);
                //fwrite(certData, attrs[3].ulValueLen, 1, stdout);
                fprintf(stderr,"     keyId: %s\n", hexify(keyId,attrs[1].ulValueLen));


            }
                break;
            case CKO_PUBLIC_KEY:
                fprintf(stderr, "CKO_PUBLIC_KEY\n"); break;
            case CKO_PRIVATE_KEY:
                fprintf(stderr, "CKO_PRIVATE_KEY\n"); break;
            case CKO_SECRET_KEY:
                fprintf(stderr, "CKO_SECRET_KEY\n"); break;
            case CKO_HW_FEATURE:
                fprintf(stderr, "CKO_HW_FEATURE\n"); break;
            case CKO_DOMAIN_PARAMETERS:
                fprintf(stderr, "CKO_DOMAIN_PARAMETERS\n"); break;
            case CKO_MECHANISM:
                fprintf(stderr, "CKO_MECHANISM\n"); break;
            case CKO_OTP_KEY:
                fprintf(stderr, "CKO_OTP_KEY\n"); break;
            default:
                fprintf(stderr,"\n");
        }


    }

    rv = p11p->C_FindObjectsFinal(hSession);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error finalizing Finding Objects (rv = %X)\n", rv);
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
        fprintf(stderr, "Error initializing Find Objects (rv = %X)\n", rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }

    rv = p11p->C_FindObjects(hSession, phObject, maxSize, &count);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error Finding Objects (rv = %X)\n", rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }
    fprintf(stderr, "Found %d objects\n", count);

    for(i = 0; i < count; i++) {
        printf("Object[%d] handle: %u\n", i, phObject[i]);
        attrs[0].type = CKA_CLASS;
        attrs[0].pValue = &ulValue;
        attrs[0].ulValueLen = sizeof(CK_ULONG);

        rv = p11p->C_GetAttributeValue(hSession, phObject[i], attrs, 1);
        if(rv != CKR_OK) {
            fprintf(stderr, "Error getting object attributes (rv = %X)\n", rv);
            (void)p11p->C_CloseSession(hSession);
            goto cleanup;
        }


        fprintf(stderr, "  Class: 0x%X ", ulValue);
        switch(ulValue) {
            case CKA_TOKEN: fprintf(stderr, "CKA_TOKEN\n");
                break;
            case CKA_PRIVATE: fprintf(stderr, "CKA_PRIVATE\n");
                break;
            case CKA_LABEL: fprintf(stderr, "CKA_LABEL\n");
                break;
            case CKA_APPLICATION: fprintf(stderr, "CKA_APPLICATION\n");
                break;
            case CKA_VALUE: fprintf(stderr, "CKA_VALUE\n");
                break;
            default:
                fprintf(stderr,"\n");
        }

    }

    rv = p11p->C_FindObjectsFinal(hSession);



    cls = CKA_VENDOR_DEFINED; //type CK_OBJECT_CLASS
    attrs[0].type = CKA_CLASS;
    attrs[0].pValue = &cls;
    attrs[0].ulValueLen = sizeof cls;

    rv = p11p->C_FindObjectsInit(hSession, attrs, 1);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error initializing Find Objects (rv = %X)\n", rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }

    rv = p11p->C_FindObjects(hSession, phObject, maxSize, &count);
    if (rv != CKR_OK) {
        fprintf(stderr, "Error Finding Objects (rv = %X)\n", rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
    }
    fprintf(stderr, "Found %d objects\n", count);

    for(i = 0; i < count; i++) {
        printf("Object[%d] handle: %u\n", i, phObject[i]);
        attrs[0].type = CKA_CLASS;
        attrs[0].pValue = &ulValue;
        attrs[0].ulValueLen = sizeof(CK_ULONG);

        rv = p11p->C_GetAttributeValue(hSession, phObject[i], attrs, 1);
        if(rv != CKR_OK) {
            fprintf(stderr, "Error getting object attributes (rv = %X)\n", rv);
            (void)p11p->C_CloseSession(hSession);
            goto cleanup;
        }


        fprintf(stderr, "  Class: 0x%X ", ulValue);
        switch(ulValue) {
            case CKA_TOKEN: fprintf(stderr, "CKA_TOKEN\n");
                break;
            case CKA_PRIVATE: fprintf(stderr, "CKA_PRIVATE\n");
                break;
            case CKA_LABEL: fprintf(stderr, "CKA_LABEL\n");
                break;
            case CKA_APPLICATION: fprintf(stderr, "CKA_APPLICATION\n");
                break;
            case CKA_VALUE: fprintf(stderr, "CKA_VALUE\n");
                break;
            default:
                fprintf(stderr,"\n");
        }

    }

    rv = p11p->C_FindObjectsFinal(hSession);




    rv = login(p11p, hSession, 0, NULL, 0);
     if (rv != CKR_OK) {
         fprintf(stderr, "Error logging into token (rv = %X)\n", rv);
        (void)p11p->C_CloseSession(hSession);
        goto cleanup;
     }


    p11p->C_Logout(hSession);
    (void)p11p->C_CloseSession(hSession);
cleanup:
    if (p11p) p11p->C_Finalize(0);


    return 0;
}

CK_RV login(CK_FUNCTION_LIST_PTR p11p, CK_SESSION_HANDLE hSession, int admin, CK_UTF8CHAR *password, CK_ULONG passwordLen) {
    CK_UTF8CHAR pin[64];
    CK_ULONG pinLen = sizeof(pin) - 1;
    CK_RV rv;

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
        printf("Error calling \"C_GetFunctionList\" (rv = %d)\n", rv);
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
