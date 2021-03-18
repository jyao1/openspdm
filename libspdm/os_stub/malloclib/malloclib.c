/** @file

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <base.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void *
allocate_pool (
  IN uintn  AllocationSize
  )
{
  return malloc (AllocationSize);
}

void *
allocate_zero_pool (
  IN uintn  AllocationSize
  )
{
  void *buffer;
  buffer = malloc (AllocationSize);
  if (buffer == NULL) {
    return NULL;
  }
  memset (buffer, 0, AllocationSize);
  return buffer;
}

void
free_pool (
  IN void   *buffer
  )
{
  free (buffer);
}
