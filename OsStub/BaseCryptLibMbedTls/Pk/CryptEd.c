/** @file
  Edwards-Curve Wrapper Implementation over OpenSSL.

  RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)
  FIPS 186-4 - Digital Signature Standard (DSS)

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

/**
  Allocates and Initializes one Edwards-Curve Context for subsequent use
  with the NID.

  The key is generated before the function returns.

  @param Nid cipher NID

  @return  Pointer to the Edwards-Curve Context that has been initialized.
           If the allocations fails, EdNewByNid() returns NULL.

**/
VOID *
EFIAPI
EdNewByNid (
  IN UINTN  Nid
  )
{
  return NULL;
}

/**
  Release the specified Ed context.
  
  @param[in]  EcContext  Pointer to the Ed context to be released.

**/
VOID
EFIAPI
EdFree (
  IN  VOID  *EdContext
  )
{
}

/**
  Carries out the Ed-DSA signature.

  This function carries out the Ed-DSA signature.
  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  If EdContext is NULL, then return FALSE.
  If Message is NULL, then return FALSE.
  If SigSize is large enough but Signature is NULL, then return FALSE.

  For Ed25519, the SigSize is 64. First 32-byte is R, Second 32-byte is S.
  For Ed448, the SigSize is 114. First 57-byte is R, Second 57-byte is S.

  @param[in]       EdContext    Pointer to Ed context for signature generation.
  @param[in]       Message      Pointer to octet message to be signed.
  @param[in]       Size         Size of the message in bytes.
  @param[out]      Signature    Pointer to buffer to receive Ed-DSA signature.
  @param[in, out]  SigSize      On input, the size of Signature buffer in bytes.
                                On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated in Ed-DSA.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.

**/
BOOLEAN
EFIAPI
EdDsaSign (
  IN      VOID         *EdContext,
  IN      CONST UINT8  *Message,
  IN      UINTN        Size,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  return FALSE;
}

/**
  Verifies the Ed-DSA signature.

  If EdContext is NULL, then return FALSE.
  If Message is NULL, then return FALSE.
  If Signature is NULL, then return FALSE.

  For Ed25519, the SigSize is 64. First 32-byte is R, Second 32-byte is S.
  For Ed448, the SigSize is 114. First 57-byte is R, Second 57-byte is S.

  @param[in]  EdContext    Pointer to Ed context for signature verification.
  @param[in]  Message      Pointer to octet message to be checked.
  @param[in]  Size         Size of the message in bytes.
  @param[in]  Signature    Pointer to Ed-DSA signature to be verified.
  @param[in]  SigSize      Size of signature in bytes.

  @retval  TRUE   Valid signature encoded in Ed-DSA.
  @retval  FALSE  Invalid signature or invalid Ed context.

**/
BOOLEAN
EFIAPI
EdDsaVerify (
  IN  VOID         *EdContext,
  IN  CONST UINT8  *Message,
  IN  UINTN        Size,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  )
{
  return FALSE;
}
