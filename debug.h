/*
 *  debug.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 7/1/09.
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

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdlib.h>
#include <string.h>

#include "mypkcs11.h"



#define DEBUG_CRITICAL  1
#define DEBUG_WARNING   2
#define DEBUG_IMPORTANT 3
#define DEBUG_INFO      4
#define DEBUG_VERBOSE   5

#ifndef DEBUG_LEVEL
#define DEBUG_LEVEL DEBUG_CRITICAL
#endif



void debug(int level, const char* format, ...);

const char * getCKRName(CK_RV rv);
const char * getCKAName(CK_ATTRIBUTE_TYPE attrib);
const char * getCKOName(CK_OBJECT_CLASS class);
const char * getCKMName(CK_MECHANISM_TYPE mech);
const char * getCKCName(CK_CERTIFICATE_TYPE ctype);
const char * getCKSName(CK_STATE state);
#if 0
const char * getSecErrorName(int status);
#endif
char *hexify(unsigned char *data, int len);
char *stringify(unsigned char *str, int length);

#endif
