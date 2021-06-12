/** @file
  Pseudorandom Number Generator Wrapper Implementation over mbedTLS.

Copyright (c) 2010 - 2013, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <Library/RngLib.h>

/**
  Sets up the seed value for the pseudorandom number generator.

  This function sets up the seed value for the pseudorandom number generator.
  If Seed is not NULL, then the seed passed in is used.
  If Seed is NULL, then default seed is used.

  @param[in]  Seed      Pointer to seed value.
                        If NULL, default seed is used.
  @param[in]  SeedSize  Size of seed value.
                        If Seed is NULL, this parameter is ignored.

  @retval TRUE   Pseudorandom number generator has enough entropy for random generation.
  @retval FALSE  Pseudorandom number generator does not have enough entropy for random generation.

**/
BOOLEAN
EFIAPI
RandomSeed (
  IN  CONST  UINT8  *Seed  OPTIONAL,
  IN  UINTN         SeedSize
  )
{
  // TBD
  return TRUE;
}

/**
  Generates a pseudorandom byte stream of the specified size.

  If Output is NULL, then return FALSE.

  @param[out]  Output  Pointer to buffer to receive random value.
  @param[in]   Size    Size of random bytes to generate.

  @retval TRUE   Pseudorandom byte stream generated successfully.
  @retval FALSE  Pseudorandom number generator fails to generate due to lack of entropy.

**/
BOOLEAN
EFIAPI
RandomBytes (
  OUT  UINT8  *Output,
  IN   UINTN  Size
  )
{
  BOOLEAN     Ret;
  UINT64      TempRand;

  Ret = FALSE;

  while (Size > 0) {
    // Use RngLib to get random number
    Ret = GetRandomNumber64 (&TempRand);

    if (!Ret) {
      return Ret;
    }
    if (Size >= sizeof (TempRand)) {
      *((UINT64*) Output) = TempRand;
      Output += sizeof (UINT64);
      Size -= sizeof (TempRand);
    }
    else {
      CopyMem (Output, &TempRand, Size);
      Size = 0;
    }
  }

  return Ret;
}

int myrand( void *rng_state, unsigned char *output, size_t len )
{
  RandomBytes (output, len);

  return 0;
}
