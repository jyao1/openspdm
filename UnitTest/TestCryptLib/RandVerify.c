/** @file  
  Application for Pseudorandom Number Generator Validation.

Copyright (c) 2010, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

#define  RANDOM_NUMBER_SIZE  256

CONST  UINT8  SeedString[] = "This is the random seed for PRNG verification.";

UINT8  PreviousRandomBuffer[RANDOM_NUMBER_SIZE] = { 0x0 };

UINT8  RandomBuffer[RANDOM_NUMBER_SIZE] = { 0x0 };

/**
  Validate UEFI-OpenSSL pseudorandom number generator interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptPrng (
  VOID
  )
{
  UINTN    Index;
  BOOLEAN  Status;

  Print (" \nUEFI-OpenSSL PRNG Engine Testing:\n");

  Print ("- Random Generation...");

  Status = RandomSeed (SeedString, sizeof (SeedString));
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  for (Index = 0; Index < 10; Index ++) {
    Status = RandomBytes (RandomBuffer, RANDOM_NUMBER_SIZE);
    if (!Status) {
      Print ("[Fail]");
      return EFI_ABORTED;
    }

    if (CompareMem (PreviousRandomBuffer, RandomBuffer, RANDOM_NUMBER_SIZE) == 0) {
      Print ("[Fail]");
      return EFI_ABORTED;
    }

    CopyMem (PreviousRandomBuffer, RandomBuffer, RANDOM_NUMBER_SIZE);
  }

  Print ("[Pass]\n");

  return EFI_SUCCESS;

}
