/** @file

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

VOID *
EFIAPI
AllocatePool (
  IN UINTN  AllocationSize
  )
{
  return malloc (AllocationSize);
}

VOID *
EFIAPI
AllocateZeroPool (
  IN UINTN  AllocationSize
  )
{
  VOID *Buffer;
  Buffer = malloc (AllocationSize);
  if (Buffer == NULL) {
    return NULL;
  }
  memset (Buffer, 0, AllocationSize);
  return Buffer;
}

VOID
EFIAPI
FreePool (
  IN VOID   *Buffer
  )
{
  free (Buffer);
}
