/** @file
  Internal include file for BaseCryptLib.

Copyright (c) 2010 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __INTERNAL_CRYPT_LIB_H__
#define __INTERNAL_CRYPT_LIB_H__

#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseCryptLib.h>
#include <stdio.h>

//
// We should alwasy add mbedtls/config.h here
// to ensure the config override takes effect.
//
#include <mbedtls/config.h>

int myrand( void *rng_state, unsigned char *output, size_t len );

#endif
