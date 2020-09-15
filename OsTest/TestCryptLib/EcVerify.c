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
  UINT8   Public1[64];
  UINTN   Public1Length;
  UINT8   Public2[64];
  UINTN   Public2Length;
  UINT8   Key1[32];
  UINTN   Key1Length;
  UINT8   Key2[32];
  UINTN   Key2Length;
  UINT8   HashValue[SHA256_DIGEST_SIZE];
  UINTN   HashSize;
  UINT8   Signature[512]; // 0x48/72, 0x68/104, 0x8A/138
  UINTN   SigSize;
  BOOLEAN Status;

  Print (L"\nUEFI-OpenSSL EC-DH Key Exchange Testing:\n");

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
  Print (L"- Context1 ... ");
  Ec1 = EcNewByNid (CRYPTO_NID_SECP256R1);
  if (Ec1 == NULL) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  Print (L"Context2 ... ");
  Ec2 = EcNewByNid (CRYPTO_NID_SECP256R1);
  if (Ec2 == NULL) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  //
  // Verify EC-DH
  //
  Print (L"Generate key1 ... ");
  Status = EcGenerateKey (Ec1);
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }
  Status = EcGetPublicKey (Ec1, Public1, &Public1Length);
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  Print (L"Generate key2 ... ");
  Status = EcGenerateKey (Ec2);
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }
  Status = EcGetPublicKey (Ec2, Public2, &Public2Length);
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  Print (L"Compute key1 ... ");
  Status = EcComputeKey (Ec1, Public2, Public2Length, Key1, &Key1Length);
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  Print (L"Compute key2 ... ");
  Status = EcComputeKey (Ec2, Public1, Public1Length, Key2, &Key2Length);
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  Print (L"Compare Keys ... ");
  if (Key1Length != Key2Length) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  if (CompareMem (Key1, Key2, Key1Length) != 0) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  } else {
    Print (L"[Pass]\n");
  }

  EcFree (Ec1);
  EcFree (Ec2);

  Print (L"\nUEFI-OpenSSL EC-DSA Signing Verification Testing:\n");

  Print (L"- Context1 ... ");
  Ec1 = EcNewByNid (CRYPTO_NID_SECP256R1);
  if (Ec1 == NULL) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  Print (L"Context2 ... ");
  Ec2 = EcNewByNid (CRYPTO_NID_SECP521R1);
  if (Ec2 == NULL) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  Print (L"Compute key1 ... ");
  Status = EcGenerateKey (Ec1);
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  Print (L"Compute key2 ... ");
  Status = EcGenerateKey (Ec2);
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  //
  // Verify EC-DSA
  //
  HashSize = sizeof(HashValue);
  SigSize = sizeof(Signature);
  Print (L"\n- EC-DSA Signing ... ");
  Status  = EcDsaSign (Ec1, HashValue, HashSize, Signature, &SigSize);
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  Print (L"EC-DSA Verification ... ");
  Status = EcDsaVerify (Ec1, HashValue, HashSize, Signature, SigSize);
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  } else {
    Print (L"[Pass]\n");
  }

  // HashSize = sizeof(HashValue);
  // SigSize = sizeof(Signature);
  // Print (L"- EC-DSA Signing ... ");
  // Status  = EcDsaSign (Ec2, HashValue, HashSize, Signature, &SigSize);
  // if (!Status) {
  //   Print (L"[Fail]");
  //   return EFI_ABORTED;
  // }

  // Print (L"EC-DSA Verification ... ");
  // Status = EcDsaVerify (Ec2, HashValue, HashSize, Signature, SigSize);
  // if (!Status) {
  //   Print (L"[Fail]");
  //   return EFI_ABORTED;
  // } else {
  //   Print (L"[Pass]\n");
  // }

  return EFI_SUCCESS;
}