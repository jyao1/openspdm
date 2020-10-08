/** @file

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _TOOLCHAIN_HARNESS_LIB_
#define _TOOLCHAIN_HARNESS_LIB_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

VOID
EFIAPI
RunTestHarness (
  IN VOID  *TestBuffer,
  IN UINTN TestBufferSize
  );

UINTN
EFIAPI
GetMaxBufferSize (
  VOID
  );

#endif