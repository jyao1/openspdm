/** @file
  Application for Cryptographic Primitives Validation.

Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

/**
  Entry Point of Cryptographic Validation Utility.

  @param  ImageHandle  The image handle of the UEFI Application.
  @param  SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
CryptestMain (
  IN     EFI_HANDLE                 ImageHandle,
  IN     EFI_SYSTEM_TABLE           *SystemTable
  )
{
  EFI_STATUS  Status;

  Print (L"\nUEFI-OpenSSL Wrapper Cryptosystem Testing: \n");
  Print (L"-------------------------------------------- \n");

  RandomSeed (NULL, 0);

  Status = ValidateCryptDigest ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ValidateCryptHmac ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Status = ValidateCryptBlockCipher ();
  // if (EFI_ERROR (Status)) {
  //   return Status;
  // }

  // Status = ValidateCryptMac ();
  // if (EFI_ERROR (Status)) {
  //   return Status;
  // }

  Status = ValidateCryptAeadCipher ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ValidateCryptRsa ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ValidateCryptRsa2 ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ValidateCryptX509 ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Status = ValidateCryptPkcs5Pbkdf2 ();
  // if (EFI_ERROR (Status)) {
  //   return Status;
  // }

  Status = ValidateCryptPkcs7 ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Status = ValidateAuthenticode ();
  // if (EFI_ERROR (Status)) {
  //   return Status;
  // }

  // Status = ValidateTSCounterSignature ();
  // if (EFI_ERROR (Status)) {
  //   return Status;
  // }

  Status = ValidateCryptDh ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ValidateCryptEc ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ValidateCryptEc2 ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ValidateCryptPkcs7Ec ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ValidateCryptPrng ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

int main(void)
{
  CryptestMain(NULL, NULL);
  return 0;
}