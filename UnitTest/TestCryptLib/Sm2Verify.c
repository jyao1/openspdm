/** @file
  Application for Shang-Mi2 Primitives Validation.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

/**
  Validate UEFI-OpenSSL Sm2 Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptSm2 (
  VOID
  )
{
  VOID    *Sm2_1;
  VOID    *Sm2_2;
  UINT8   Public1[66 * 2];
  UINTN   Public1Length;
  UINT8   Public2[66 * 2];
  UINTN   Public2Length;
  UINT8   Key1[32];
  UINTN   Key1Length;
  UINT8   Key2[32];
  UINTN   Key2Length;
  UINT8   Message[] = "Sm2Test";
  UINT8   Signature[32 * 2];
  UINTN   SigSize;
  BOOLEAN Status;

  Print ("\nUEFI-OpenSSL SM2 Key Exchange Testing:\n");

  //
  // Initialize Key Length
  //
  Public1Length  = sizeof (Public1);
  Public2Length  = sizeof (Public2);
  Key1Length     = sizeof (Key1);
  Key2Length     = sizeof (Key2);

  //
  // Generate & Initialize SM2 Context
  //
  Print ("- Context1 ... ");
  Sm2_1 = Sm2New ();
  if (Sm2_1 == NULL) {
    Print ("[Fail]");
    goto Exit;
  }

  Print ("Context2 ... ");
  Sm2_2 = Sm2New ();
  if (Sm2_2 == NULL) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    goto Exit;
  }

  //
  // Verify SM2-DH
  //
  Print ("Generate key1 ... ");
  Status = Sm2GenerateKey (Sm2_1, Public1, &Public1Length);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  }

  Print ("Generate key2 ... ");
  Status = Sm2GenerateKey (Sm2_2, Public2, &Public2Length);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  }

  Print ("Compute key1 ... ");
  Status = Sm2ComputeKey (Sm2_1, Public2, Public2Length, Key1, &Key1Length);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  }

  Print ("Compute key2 ... ");
  Status = Sm2ComputeKey (Sm2_2, Public1, Public1Length, Key2, &Key2Length);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  }

  Print ("Compare Keys ... ");
  if (Key1Length != Key2Length) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  }

  if (CompareMem (Key1, Key2, Key1Length) != 0) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  } else {
    Print ("[Pass]\n");
  }

  Sm2Free (Sm2_1);
  Sm2Free (Sm2_2);

  Print ("\nUEFI-OpenSSL Sm2 Signing Verification Testing:\n");

  Public1Length  = sizeof (Public1);

  Print ("- Context1 ... ");
  Sm2_1 = Sm2New ();
  if (Sm2_1 == NULL) {
    Print ("[Fail]");
    goto Exit;
  }

  Print ("Compute key1 ... ");
  Status = Sm2GenerateKey (Sm2_1, Public1, &Public1Length);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    goto Exit;
  }

  //
  // Verify SM2 signing/verification
  //
  SigSize = sizeof(Signature);
  Print ("\n- SM2 Signing ... ");
  Status  = Sm2Sign (Sm2_1, CRYPTO_NID_SM3_256, Message, sizeof(Message), Signature, &SigSize);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    goto Exit;
  }

  Print ("SM2 Verification ... ");
  Status = Sm2Verify (Sm2_1, CRYPTO_NID_SM3_256, Message, sizeof(Message), Signature, SigSize);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    goto Exit;
  } else {
    Print ("[Pass]\n");
  }
  Sm2Free (Sm2_1);


  Print ("\nUEFI-OpenSSL Sm2 Signing Verification Testing with SetPubKey:\n");

  Public1Length  = sizeof (Public1);
  Public2Length  = sizeof (Public2);

  Print ("- Context1 ... ");
  Sm2_1 = Sm2New ();
  if (Sm2_1 == NULL) {
    Print ("[Fail]");
    goto Exit;
  }

  Print ("Context2 ... ");
  Sm2_2 = Sm2New ();
  if (Sm2_2 == NULL) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    goto Exit;
  }

  Print ("Compute key in Context1 ... ");
  Status = Sm2GenerateKey (Sm2_1, Public1, &Public1Length);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  }

  Print ("Export key in Context1 ... ");
  Status = Sm2GetPubKey (Sm2_1, Public2, &Public2Length);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  }

  Print ("Import key in Context2 ... ");
  Status = Sm2SetPubKey (Sm2_2, Public2, Public2Length);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  }

  //
  // Verify EC-DSA
  //
  SigSize = sizeof(Signature);
  Print ("\n- Sm2 Signing in Context1 ... ");
  Status  = Sm2Sign (Sm2_1, CRYPTO_NID_SM3_256, Message, sizeof(Message), Signature, &SigSize);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  }

  Print ("Sm2 Verification in Context2 ... ");
  Status = Sm2Verify (Sm2_2, CRYPTO_NID_SM3_256, Message, sizeof(Message), Signature, SigSize);
  if (!Status) {
    Print ("[Fail]");
    Sm2Free (Sm2_1);
    Sm2Free (Sm2_2);
    goto Exit;
  } else {
    Print ("[Pass]\n");
  }

  Sm2Free (Sm2_1);
  Sm2Free (Sm2_2);

Exit:
  return EFI_SUCCESS;
}