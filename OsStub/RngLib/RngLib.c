/** @file

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>
#include <stdlib.h>

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

  Ptr = (UINT8 *)Rand;
  Ptr[0] = (UINT8)rand();
  Ptr[1] = (UINT8)rand();
  Ptr[2] = (UINT8)rand();
  Ptr[3] = (UINT8)rand();
  Ptr[4] = (UINT8)rand();
  Ptr[5] = (UINT8)rand();
  Ptr[6] = (UINT8)rand();
  Ptr[7] = (UINT8)rand();

  return TRUE;
}
