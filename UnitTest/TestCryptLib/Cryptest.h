/** @file
  Application for Cryptographic Primitives Validation.

Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __CRYPTEST_H__
#define __CRYPTEST_H__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#undef NULL

#include <Hal/Base.h>

#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseCryptLib.h>


#define IN
#define OUT
#define EFI_HANDLE VOID*
#define EFI_SYSTEM_TABLE VOID*
#define EFI_STATUS RETURN_STATUS
#define EFI_ERROR(StatusCode) (((INTN)(RETURN_STATUS)(StatusCode)) < 0)
#define EFI_SUCCESS 0
#define EFI_ABORTED RETURN_ABORTED


BOOLEAN
ReadInputFile (
  IN CHAR8    *FileName,
  OUT VOID    **FileData,
  OUT UINTN   *FileSize
  );

UINTN
EFIAPI
AsciiStrLen (
  IN      CONST CHAR8               *String
  );

VOID
Print (
  IN CHAR8 *Message
  );

// /**
//   Validate UEFI-OpenSSL Digest Interfaces.

//   @retval  EFI_SUCCESS  Validation succeeded.
//   @retval  EFI_ABORTED  Validation failed.

// **/
EFI_STATUS
ValidateCryptDigest (
  VOID
  );

/**
  Validate UEFI-OpenSSL Message Authentication Codes Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptHmac (
  VOID
  );

// /**
//   Validate UEFI-OpenSSL Block Ciphers (Symmetric Crypto) Interfaces.

//   @retval  EFI_SUCCESS  Validation succeeded.
//   @retval  EFI_ABORTED  Validation failed.

// **/
// EFI_STATUS
// ValidateCryptBlockCipher (
//   VOID
//   );

/**
  Validate UEFI-OpenSSL Message Authentication Codes Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptMac (
  VOID
  );

/**
  Validate UEFI-OpenSSL AEAD Ciphers Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptAeadCipher (
  VOID
  );

/**
  Validate UEFI-OpenSSL RSA Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptRsa (
  VOID
  );

/**
  Validate UEFI-OpenSSL RSA Key Retrieving (from PEM & X509) & Signature Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptRsa2 (
  VOID
  );

/**
  Validate UEFI-Crypto  X509 certificate Verify

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptX509 (
  CHAR8 *Path,
  UINTN Len
  );

// /**
//   Validate UEFI-OpenSSL PKCS#5 PBKDF2 Interface.

//   @retval  EFI_SUCCESS  Validation succeeded.
//   @retval  EFI_ABORTED  Validation failed.

// **/
// EFI_STATUS
// ValidateCryptPkcs5Pbkdf2 (
//   VOID
//   );

/**
  Validate UEFI-OpenSSL PKCS#7 Signing & Verification Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptPkcs7 (
  VOID
  );

// /**
//   Validate UEFI-OpenSSL Authenticode Verification Interfaces.

//   @retval  EFI_SUCCESS  Validation succeeded.
//   @retval  EFI_ABORTED  Validation failed.

// **/
// EFI_STATUS
// ValidateAuthenticode (
//   VOID
//   );

// /**
//   Validate UEFI-OpenSSL RFC3161 Timestamp CounterSignature Verification Interfaces.

//   @retval  EFI_SUCCESS  Validation succeeded.
//   @retval  EFI_ABORTED  Validation failed.

// **/
// EFI_STATUS
// ValidateTSCounterSignature (
//   VOID
//   );

/**
  Validate UEFI-OpenSSL DH Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptDh (
  VOID
  );

/**
  Validate UEFI-OpenSSL EC Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptEc (
  VOID
  );

/**
  Validate UEFI-OpenSSL EC Key Retrieving (from PEM & X509) & Signature Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptEc2 (
  VOID
  );

/**
  Validate UEFI-OpenSSL Ed Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptEd (
  VOID
  );

/**
  Validate UEFI-OpenSSL Ed Key Retrieving (from PEM & X509) & Signature Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptEd2 (
  VOID
  );

/**
  Validate UEFI-OpenSSL Sm2 Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptSm2 (
  VOID
  );

/**
  Validate UEFI-OpenSSL Sm2 Key Retrieving (from PEM & X509) & Signature Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptSm2_2 (
  VOID
  );

/**
  Validate UEFI-OpenSSL PKCS#7 Signing & Verification Interfaces for EC.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptPkcs7Ec (
  VOID
  );

/**
  Validate UEFI-OpenSSL pseudorandom number generator interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptPrng (
  VOID
  );

#endif
