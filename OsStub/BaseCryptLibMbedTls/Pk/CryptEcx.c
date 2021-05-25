/** @file
  Montgomery-Curve Wrapper Implementation over mbedTLS.

  RFC 7748 - Elliptic Curves for Security (Curve25519/Curve448)
  NIST SP 800-186 - Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

/**
  Allocates and Initializes one Montgomery-Curve Context for subsequent use
  with the NID.

  @param Nid cipher NID

  @return  Pointer to the Montgomery-Curve Context that has been initialized.
           If the allocations fails, EcxNewByNid() returns NULL.

**/
VOID *
EFIAPI
EcxNewByNid (
  IN UINTN  Nid
  )
{
  return NULL;
}

/**
  Release the specified Ecx context.
  
  @param[in]  EcxContext  Pointer to the Ecx context to be released.

**/
VOID
EFIAPI
EcxFree (
  IN  VOID  *EcxContext
  )
{
}

/**
  Generates Ecx key and returns Ecx public key.

  This function generates random secret, and computes the public key, which is
  returned via parameter Public, PublicSize.
  Ecx context is updated accordingly.
  If the Public buffer is too small to hold the public key, FALSE is returned and
  PublicSize is set to the required buffer size to obtain the public key.

  For X25519, the PublicSize is 32.
  For X448, the PublicSize is 56.

  If EcxContext is NULL, then return FALSE.
  If PublicSize is NULL, then return FALSE.
  If PublicSize is large enough but Public is NULL, then return FALSE.

  @param[in, out]  EcxContext      Pointer to the Ecx context.
  @param[out]      Public         Pointer to the buffer to receive generated public key.
  @param[in, out]  PublicSize     On input, the size of Public buffer in bytes.
                                  On output, the size of data returned in Public buffer in bytes.

  @retval TRUE   Ecx public key generation succeeded.
  @retval FALSE  Ecx public key generation failed.
  @retval FALSE  PublicSize is not large enough.

**/
BOOLEAN
EFIAPI
EcxGenerateKey (
  IN OUT  VOID   *EcxContext,
  OUT     UINT8  *Public,
  IN OUT  UINTN  *PublicSize
  )
{
  return FALSE;
}

/**
  Computes exchanged common key.

  Given peer's public key, this function computes the exchanged common key,
  based on its own context including value of curve parameter and random secret.

  If EcxContext is NULL, then return FALSE.
  If PeerPublic is NULL, then return FALSE.
  If PeerPublicSize is 0, then return FALSE.
  If Key is NULL, then return FALSE.
  If KeySize is not large enough, then return FALSE.

  For X25519, the PublicSize is 32.
  For X448, the PublicSize is 56.

  @param[in, out]  EcxContext          Pointer to the Ecx context.
  @param[in]       PeerPublic         Pointer to the peer's public key.
  @param[in]       PeerPublicSize     Size of peer's public key in bytes.
  @param[out]      Key                Pointer to the buffer to receive generated key.
  @param[in, out]  KeySize            On input, the size of Key buffer in bytes.
                                      On output, the size of data returned in Key buffer in bytes.

  @retval TRUE   Ecx exchanged key generation succeeded.
  @retval FALSE  Ecx exchanged key generation failed.
  @retval FALSE  KeySize is not large enough.

**/
BOOLEAN
EFIAPI
EcxComputeKey (
  IN OUT  VOID         *EcxContext,
  IN      CONST UINT8  *PeerPublic,
  IN      UINTN        PeerPublicSize,
  OUT     UINT8        *Key,
  IN OUT  UINTN        *KeySize
  )
{
  return FALSE;
}
