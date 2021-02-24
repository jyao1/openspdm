/** @file
  Application for Edwards-Curve Primitives Validation.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

/**
  Validate UEFI-OpenSSL Ed Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptEd (
  VOID
  )
{
  VOID    *Ed1;
  VOID    *Ed2;
  UINT8   Message[] = "EdDsaTest";
  UINT8   Signature1[32 * 2];
  UINT8   Signature2[57 * 2];
  UINTN   Sig1Size;
  UINTN   Sig2Size;
  BOOLEAN Status;

  Print ("\nUEFI-OpenSSL Ed-DSA Signing Verification Testing:\n");

  Print ("- Context1 ... ");
  Ed1 = EdNewByNid (CRYPTO_NID_EDDSA_ED25519);
  if (Ed1 == NULL) {
    Print ("[Fail]");
    goto Exit;
  }

  //
  // Verify Ed-DSA
  //
  Sig1Size = sizeof(Signature1);
  Print ("\n- Ed-DSA Signing ... ");
  Status  = EdDsaSign (Ed1, CRYPTO_NID_NULL, Message, sizeof(Message), Signature1, &Sig1Size);
  if (!Status) {
    Print ("[Fail]");
    EdFree (Ed1);
    goto Exit;
  }

  Print ("Ed-DSA Verification ... ");
  Status = EdDsaVerify (Ed1, CRYPTO_NID_NULL, Message, sizeof(Message), Signature1, Sig1Size);
  if (!Status) {
    Print ("[Fail]");
    EdFree (Ed1);
    goto Exit;
  } else {
    Print ("[Pass]\n");
  }
  EdFree (Ed1);

  Print ("Context2 ... ");
  Ed2 = EdNewByNid (CRYPTO_NID_EDDSA_ED448);
  if (Ed2 == NULL) {
    Print ("[Fail]");
    goto Exit;
  }

  Sig2Size = sizeof(Signature2);
  Print ("\n- Ed-DSA Signing ... ");
  Status  = EdDsaSign (Ed2, CRYPTO_NID_NULL, Message, sizeof(Message), Signature2, &Sig2Size);
  if (!Status) {
    Print ("[Fail]");
    EdFree (Ed2);
    goto Exit;
  }

  Print ("Ed-DSA Verification ... ");
  Status = EdDsaVerify (Ed2, CRYPTO_NID_NULL, Message, sizeof(Message), Signature2, Sig2Size);
  if (!Status) {
    Print ("[Fail]");
    EdFree (Ed2);
    goto Exit;
  } else {
    Print ("[Pass]\n");
  }

  EdFree (Ed2);

Exit:
  return EFI_SUCCESS;
}