/** @file
  Internal include file for cryptlib.

Copyright (c) 2010 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __INTERNAL_CRYPT_LIB_H__
#define __INTERNAL_CRYPT_LIB_H__

#undef _WIN32
#undef _WIN64

#include <base.h>
#include <library/memlib.h>
#include <library/malloclib.h>
#include <library/debuglib.h>
#include <library/cryptlib.h>

#include "crt_support.h"

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OBJ_get0_data(o) ((o)->data)
#define OBJ_length(o) ((o)->length)
#endif

#endif
