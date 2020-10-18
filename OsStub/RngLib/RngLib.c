/** @file

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

/**
  Generates a 64-bit random number.

  if Rand is NULL, then ASSERT().

  @param[out] Rand     Buffer pointer to store the 64-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.

**/
BOOLEAN
EFIAPI
GetRandomNumber64 (
  OUT     UINT64                    *Rand
  )
{
  UINT8  *Ptr;

  srand ((unsigned int)time (NULL));

  Ptr = (UINT8 *)Rand;
  Ptr[0] = (UINT8)rand();
  Ptr[1] = (UINT8)rand();
  Ptr[2] = (UINT8)rand();
  Ptr[3] = (UINT8)rand();

  return TRUE;
}
