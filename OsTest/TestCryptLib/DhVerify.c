/** @file
  Application for Diffie-Hellman Primitives Validation.

Copyright (c) 2010 - 2014, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

/**
  Validate UEFI-OpenSSL DH Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptDh (
  VOID
  )
{
  VOID    *Dh1;
  VOID    *Dh2;
  UINT8   Prime[64];
  UINT8   PublicKey1[64];
  UINTN   PublicKey1Length;
  UINT8   PublicKey2[64];
  UINTN   PublicKey2Length;
  UINT8   Key1[64];
  UINTN   Key1Length;
  UINT8   Key2[64];
  UINTN   Key2Length;
  BOOLEAN Status;
  UINT8   FFPublicKey1[256];
  UINTN   FFPublicKey1Length;
  UINT8   FFPublicKey2[256];
  UINTN   FFPublicKey2Length;
  UINT8   FFKey1[256];
  UINTN   FFKey1Length;
  UINT8   FFKey2[256];
  UINTN   FFKey2Length;

  Print ("\nUEFI-OpenSSL DH Engine Testing:\n");

if (0) {
  //
  // Initialize Key Length
  //
  PublicKey1Length = sizeof (PublicKey1);
  PublicKey2Length = sizeof (PublicKey2);
  Key1Length       = sizeof (Key1);
  Key2Length       = sizeof (Key2);

  //
  // Generate & Initialize DH Context
  //
  Print ("- Context1 ... ");
  Dh1 = DhNew ();
  if (Dh1 == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Context2 ... ");
  Dh2 = DhNew ();
  if (Dh2 == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Parameter1 ... ");
  Status = DhGenerateParameter (Dh1, 2, 64, Prime);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Parameter2 ... ");
  Status = DhSetParameter (Dh2, 2, 64, Prime);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Generate key1 ... ");
  Status = DhGenerateKey (Dh1, PublicKey1, &PublicKey1Length);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Generate key2 ... ");
  Status = DhGenerateKey (Dh2, PublicKey2, &PublicKey2Length);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Compute key1 ... ");
  Status = DhComputeKey (Dh1, PublicKey2, PublicKey2Length, Key1, &Key1Length);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Compute key2 ... ");
  Status = DhComputeKey (Dh2, PublicKey1, PublicKey1Length, Key2, &Key2Length);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Compare Keys ... ");
  if (Key1Length != Key2Length) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  if (CompareMem (Key1, Key2, Key1Length) != 0) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("[Pass]\n");
}

  //
  //
  //
  FFPublicKey1Length = sizeof (FFPublicKey1);
  FFPublicKey2Length = sizeof (FFPublicKey2);
  FFKey1Length       = sizeof (FFKey1);
  FFKey2Length       = sizeof (FFKey2);
  Print ("- Context1 ... ");
  Dh1 = DhNewByNid (CRYPTO_NID_FFDHE2048);
  if (Dh1 == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Context2 ... ");
  Dh2 = DhNewByNid (CRYPTO_NID_FFDHE2048);
  if (Dh2 == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Generate key1 ... ");
  Status = DhGenerateKey (Dh1, FFPublicKey1, &FFPublicKey1Length);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Generate key2 ... ");
  Status = DhGenerateKey (Dh2, FFPublicKey2, &FFPublicKey2Length);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Compute key1 ... ");
  Status = DhComputeKey (Dh1, FFPublicKey2, FFPublicKey2Length, FFKey1, &FFKey1Length);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Compute key2 ... ");
  Status = DhComputeKey (Dh2, FFPublicKey1, FFPublicKey1Length, FFKey2, &FFKey2Length);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Compare Keys ... ");
  if (FFKey1Length != FFKey2Length) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  if (CompareMem (FFKey1, FFKey2, FFKey1Length) != 0) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("[Pass]\n");

  return EFI_SUCCESS;
}