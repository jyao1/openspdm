/** @file
  Application for HMAC Primitives Validation.

Copyright (c) 2010 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

//
// Max Known Digest Size is SHA512 Output (64 bytes) by far
//
#define MAX_DIGEST_SIZE    64

//
// Data string for HMAC validation
//
GLOBAL_REMOVE_IF_UNREFERENCED CONST CHAR8 *HmacData = "Hi There";

//
// Key value for HMAC-SHA-256 validation. (From "4. Test Vectors" of IETF RFC4231)
//
GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 HmacSha256Key[20] = {
  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
  0x0b, 0x0b, 0x0b, 0x0b
  };

//
// Result for HMAC-SHA-256 ("Hi There"). (From "4. Test Vectors" of IETF RFC4231)
//
GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 HmacSha256Digest[] = {
  0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
  0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
  };

/**
  Validate UEFI-OpenSSL Message Authentication Codes Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptHmac (
  VOID
  )
{
  VOID     *HmacCtx;
  UINT8    Digest[MAX_DIGEST_SIZE];
  BOOLEAN  Status;

  Print (" \nUEFI-OpenSSL HMAC Engine Testing:\n");

  Print ("- HMAC-SHA256: ");
  //
  // HMAC-SHA-256 Digest Validation
  //
  ZeroMem (Digest, MAX_DIGEST_SIZE);
  HmacCtx = HmacSha256New ();
  if (HmacCtx == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Status = HmacSha256SetKey (HmacCtx, HmacSha256Key, 20);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HmacCtx);
    return EFI_ABORTED;
  }

  Print ("Update... ");
  Status  = HmacSha256Update (HmacCtx, HmacData, 8);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HmacCtx);
    return EFI_ABORTED;
  }

  Print ("Finalize... ");
  Status  = HmacSha256Final (HmacCtx, Digest);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HmacCtx);
    return EFI_ABORTED;
  }

  FreePool (HmacCtx);

  Print ("Check Value... ");
  if (CompareMem (Digest, HmacSha256Digest, SHA256_DIGEST_SIZE) != 0) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("[Pass]\n");

  return EFI_SUCCESS;
}
