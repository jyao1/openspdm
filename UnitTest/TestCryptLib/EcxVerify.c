/** @file
  Application for Montgomery-Curve Primitives Validation.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

/**
  Validate UEFI-OpenSSL MontgomeryCurve Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptEcx (
  VOID
  )
{
  VOID    *Ecx1;
  VOID    *Ecx2;
  UINT8   Public1[56];
  UINTN   Public1Length;
  UINT8   Public2[56];
  UINTN   Public2Length;
  UINT8   Key1[56];
  UINTN   Key1Length;
  UINT8   Key2[56];
  UINTN   Key2Length;
  BOOLEAN Status;

  Print ("\nUEFI-OpenSSL Montgomery Curve Key Exchange Testing:\n");

  //
  // Initialize Key Length
  //
  Public1Length  = sizeof (Public1);
  Public2Length  = sizeof (Public2);
  Key1Length     = sizeof (Key1);
  Key2Length     = sizeof (Key2);

  //
  // Generate & Initialize EC Context
  //
  Print ("- Context1 ... ");
  Ecx1 = EcxNewByNid (CRYPTO_NID_CURVE_X25519);
  if (Ecx1 == NULL) {
    Print ("[Fail]");
    goto Exit;
  }

  Print ("Context2 ... ");
  Ecx2 = EcxNewByNid (CRYPTO_NID_CURVE_X25519);
  if (Ecx2 == NULL) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    goto Exit;
  }

  //
  // Verify EC-DH x25519/x448
  //
  Print ("Generate key1 ... ");
  Status = EcxGenerateKey (Ecx1, Public1, &Public1Length);
  if (!Status) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  }

  Print ("Generate key2 ... ");
  Status = EcxGenerateKey (Ecx2, Public2, &Public2Length);
  if (!Status) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  }

  Print ("Compute key1 ... ");
  Status = EcxComputeKey (Ecx1, Public2, Public2Length, Key1, &Key1Length);
  if (!Status) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  }

  Print ("Compute key2 ... ");
  Status = EcxComputeKey (Ecx2, Public1, Public1Length, Key2, &Key2Length);
  if (!Status) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  }

  Print ("Compare Keys ... ");
  if (Key1Length != Key2Length) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  }

  if (CompareMem (Key1, Key2, Key1Length) != 0) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  } else {
    Print ("[Pass]\n");
  }

  EcxFree (Ecx1);
  EcxFree (Ecx2);

  //
  // Initialize Key Length
  //
  Public1Length  = sizeof (Public1);
  Public2Length  = sizeof (Public2);
  Key1Length     = sizeof (Key1);
  Key2Length     = sizeof (Key2);

  //
  // Generate & Initialize EC Context
  //
  Print ("- Context1 ... ");
  Ecx1 = EcxNewByNid (CRYPTO_NID_CURVE_X448);
  if (Ecx1 == NULL) {
    Print ("[Fail]");
    goto Exit;
  }

  Print ("Context2 ... ");
  Ecx2 = EcxNewByNid (CRYPTO_NID_CURVE_X448);
  if (Ecx2 == NULL) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    goto Exit;
  }

  //
  // Verify EC-DH x25519/x448
  //
  Print ("Generate key1 ... ");
  Status = EcxGenerateKey (Ecx1, Public1, &Public1Length);
  if (!Status) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  }

  Print ("Generate key2 ... ");
  Status = EcxGenerateKey (Ecx2, Public2, &Public2Length);
  if (!Status) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  }

  Print ("Compute key1 ... ");
  Status = EcxComputeKey (Ecx1, Public2, Public2Length, Key1, &Key1Length);
  if (!Status) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  }

  Print ("Compute key2 ... ");
  Status = EcxComputeKey (Ecx2, Public1, Public1Length, Key2, &Key2Length);
  if (!Status) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  }

  Print ("Compare Keys ... ");
  if (Key1Length != Key2Length) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  }

  if (CompareMem (Key1, Key2, Key1Length) != 0) {
    Print ("[Fail]");
    EcxFree (Ecx1);
    EcxFree (Ecx2);
    goto Exit;
  } else {
    Print ("[Pass]\n");
  }

  EcxFree (Ecx1);
  EcxFree (Ecx2);

Exit:
  return EFI_SUCCESS;
}