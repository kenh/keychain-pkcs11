/*
 *  pkcs11_test.h
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

#ifndef _PKCS11_TEST_H_
#define _PKCS11_TEST_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mypkcs11.h"
#include "debug.h"

#ifndef _WIN32
#include <termios.h>
#include <dlfcn.h>
#define GetFuncFromMod dlsym
#define CloseMod dlclose
typedef void *LpHandleType;
#else
#include <io.h>
#define GetFuncFromMod GetProcAddress
#define CloseMod FreeLibrary
typedef HINSTANCE LpHandleType;
#endif


void hexdump(unsigned char *, int);
CK_RV get_slot(CK_FUNCTION_LIST_PTR, CK_SLOT_ID_PTR);
CK_RV login(CK_FUNCTION_LIST_PTR, CK_SESSION_HANDLE, int, CK_UTF8CHAR *, CK_ULONG);
CK_RV load_library(char *, CK_FUNCTION_LIST_PTR *);
char *unhex(char *input, CK_ULONG *length);
CK_RV getPassword(CK_UTF8CHAR *pass, CK_ULONG *length);


#endif
