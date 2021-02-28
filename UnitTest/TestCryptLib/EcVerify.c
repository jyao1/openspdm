/** @file
  Application for Elliptic Curve Primitives Validation.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

/**
  Validate UEFI-OpenSSL EC Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptEc (
  VOID
  )
{
  VOID    *Ec1;
  VOID    *Ec2;
  UINT8   Public1[66 * 2];
  UINTN   Public1Length;
  UINT8   Public2[66 * 2];
  UINTN   Public2Length;
  UINT8   Key1[32];
  UINTN   Key1Length;
  UINT8   Key2[32];
  UINTN   Key2Length;
  UINT8   HashValue[SHA256_DIGEST_SIZE];
  UINTN   HashSize;
  UINT8   Signature[66 * 2];
  UINTN   SigSize;
  BOOLEAN Status;

  Print ("\nUEFI-OpenSSL EC-DH Key Exchange Testing:\n");

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
  Ec1 = EcNewByNid (CRYPTO_NID_SECP256R1);
  if (Ec1 == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Context2 ... ");
  Ec2 = EcNewByNid (CRYPTO_NID_SECP256R1);
  if (Ec2 == NULL) {
    Print ("[Fail]");
    EcFree (Ec1);
    return EFI_ABORTED;
  }

  //
  // Verify EC-DH
  //
  Print ("Generate key1 ... ");
  Status = EcGenerateKey (Ec1, Public1, &Public1Length);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  Print ("Generate key2 ... ");
  Status = EcGenerateKey (Ec2, Public2, &Public2Length);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  Print ("Compute key1 ... ");
  Status = EcComputeKey (Ec1, Public2, Public2Length, Key1, &Key1Length);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  Print ("Compute key2 ... ");
  Status = EcComputeKey (Ec2, Public1, Public1Length, Key2, &Key2Length);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  Print ("Compare Keys ... ");
  if (Key1Length != Key2Length) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  if (CompareMem (Key1, Key2, Key1Length) != 0) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  } else {
    Print ("[Pass]\n");
  }

  EcFree (Ec1);
  EcFree (Ec2);

  Print ("\nUEFI-OpenSSL EC-DSA Signing Verification Testing:\n");

  Public1Length  = sizeof (Public1);
  Public2Length  = sizeof (Public2);

  Print ("- Context1 ... ");
  Ec1 = EcNewByNid (CRYPTO_NID_SECP256R1);
  if (Ec1 == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Context2 ... ");
  Ec2 = EcNewByNid (CRYPTO_NID_SECP521R1);
  if (Ec2 == NULL) {
    Print ("[Fail]");
    EcFree (Ec1);
    return EFI_ABORTED;
  }

  Print ("Compute key1 ... ");
  Status = EcGenerateKey (Ec1, Public1, &Public1Length);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  Print ("Compute key2 ... ");
  Status = EcGenerateKey (Ec2, Public2, &Public2Length);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  //
  // Verify EC-DSA
  //
  HashSize = sizeof(HashValue);
  SigSize = sizeof(Signature);
  Print ("\n- EC-DSA Signing ... ");
  Status  = EcDsaSign (Ec1, CRYPTO_NID_SHA256, HashValue, HashSize, Signature, &SigSize);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  Print ("EC-DSA Verification ... ");
  Status = EcDsaVerify (Ec1, CRYPTO_NID_SHA256, HashValue, HashSize, Signature, SigSize);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  } else {
    Print ("[Pass]\n");
  }

  HashSize = sizeof(HashValue);
  SigSize = sizeof(Signature);
  Print ("- EC-DSA Signing ... ");
  Status  = EcDsaSign (Ec2, CRYPTO_NID_SHA256, HashValue, HashSize, Signature, &SigSize);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  Print ("EC-DSA Verification ... ");
  Status = EcDsaVerify (Ec2, CRYPTO_NID_SHA256, HashValue, HashSize, Signature, SigSize);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  } else {
    Print ("[Pass]\n");
  }

  EcFree (Ec1);
  EcFree (Ec2);

  Print ("\nUEFI-OpenSSL EC-DSA Signing Verification Testing with SetPubKey:\n");

  Public1Length  = sizeof (Public1);
  Public2Length  = sizeof (Public2);

  Print ("- Context1 ... ");
  Ec1 = EcNewByNid (CRYPTO_NID_SECP256R1);
  if (Ec1 == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Context2 ... ");
  Ec2 = EcNewByNid (CRYPTO_NID_SECP256R1);
  if (Ec2 == NULL) {
    Print ("[Fail]");
    EcFree (Ec1);
    return EFI_ABORTED;
  }

  Print ("Compute key in Context1 ... ");
  Status = EcGenerateKey (Ec1, Public1, &Public1Length);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  Print ("Export key in Context1 ... ");
  Status = EcGetPubKey (Ec1, Public2, &Public2Length);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  Print ("Import key in Context2 ... ");
  Status = EcSetPubKey (Ec2, Public2, Public2Length);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  //
  // Verify EC-DSA
  //
  HashSize = sizeof(HashValue);
  SigSize = sizeof(Signature);
  Print ("\n- EC-DSA Signing in Context1 ... ");
  Status  = EcDsaSign (Ec1, CRYPTO_NID_SHA256, HashValue, HashSize, Signature, &SigSize);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  }

  Print ("EC-DSA Verification in Context2 ... ");
  Status = EcDsaVerify (Ec2, CRYPTO_NID_SHA256, HashValue, HashSize, Signature, SigSize);
  if (!Status) {
    Print ("[Fail]");
    EcFree (Ec1);
    EcFree (Ec2);
    return EFI_ABORTED;
  } else {
    Print ("[Pass]\n");
  }

  EcFree (Ec1);
  EcFree (Ec2);

  return EFI_SUCCESS;
}