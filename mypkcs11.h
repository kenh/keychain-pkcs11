/*
 *  mypkcs11.h
 *  KeychainToken
 *
 *  Created by Jay Kline on 6/23/09.
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

#ifndef MYPKCS11_H
#define MYPKCS11_H

#define CK_PTR *
#define CK_DECLARE_FUNCTION(rv,func) rv func
#define CK_DECLARE_FUNCTION_POINTER(rv,func) rv (* func)
#define CK_CALLBACK_FUNCTION(rv,func) rv (* func)
#define CK_NULL_PTR 0

#include "pkcs11.h"
#include "pkcs11n.h"

#endif
