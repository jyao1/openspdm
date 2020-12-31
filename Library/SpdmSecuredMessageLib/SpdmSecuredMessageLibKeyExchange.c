/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmSecuredMessageLibInternal.h"

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) Context for subsequent use,
  based upon negotiated DHE algorithm.
  
  @param  DHENamedGroup                SPDM DHENamedGroup

  @return  Pointer to the Diffie-Hellman Context that has been initialized.
**/
VOID *
EFIAPI
SpdmSecuredMessageDheNew (
  IN   UINT16                       DHENamedGroup
  )
{
  return SpdmDheNew (DHENamedGroup);
}

/**
  Release the specified DHE context,
  based upon negotiated DHE algorithm.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  DheContext                   Pointer to the DHE context to be released.
**/
VOID
EFIAPI
SpdmSecuredMessageDheFree (
  IN   UINT16                       DHENamedGroup,
  IN   VOID                         *DheContext
  )
{
  SpdmDheFree (DHENamedGroup, DheContext);
}

/**
  Generates DHE public key,
  based upon negotiated DHE algorithm.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter PublicKey and PublicKeySize. DH context is updated accordingly.
  If the PublicKey buffer is too small to hold the public key, FALSE is returned and
  PublicKeySize is set to the required buffer size to obtain the public key.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  DheContext                   Pointer to the DHE context.
  @param  PublicKey                    Pointer to the buffer to receive generated public key.
  @param  PublicKeySize                On input, the size of PublicKey buffer in bytes.
                                       On output, the size of data returned in PublicKey buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  PublicKeySize is not large enough.
**/
BOOLEAN
EFIAPI
SpdmSecuredMessageDheGenerateKey (
  IN      UINT16                       DHENamedGroup,
  IN OUT  VOID                         *DheContext,
  OUT     UINT8                        *PublicKey,
  IN OUT  UINTN                        *PublicKeySize
  )
{
  return SpdmDheGenerateKey (DHENamedGroup, DheContext, PublicKey, PublicKeySize);
}

/**
  Computes exchanged common key,
  based upon negotiated DHE algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  DheContext                   Pointer to the DHE context.
  @param  PeerPublicKey                Pointer to the peer's public key.
  @param  PeerPublicKeySize            Size of peer's public key in bytes.
  @param  Key                          Pointer to the buffer to receive generated key.
  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  KeySize is not large enough.
**/
BOOLEAN
EFIAPI
SpdmSecuredMessageDheComputeKey (
  IN      UINT16                       DHENamedGroup,
  IN OUT  VOID                         *DheContext,
  IN      CONST UINT8                  *PeerPublic,
  IN      UINTN                        PeerPublicSize,
  IN OUT  VOID                         *SpdmSecuredMessageContext
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;
  UINT8                                  FinalKey[MAX_DHE_KEY_SIZE];
  UINTN                                  FinalKeySize;
  BOOLEAN                                Ret;

  SecuredMessageContext = SpdmSecuredMessageContext;

  FinalKeySize = sizeof(FinalKey);
  Ret = SpdmDheComputeKey (DHENamedGroup, DheContext, PeerPublic, PeerPublicSize, FinalKey, &FinalKeySize);
  if (!Ret) {
    return Ret;
  }
  CopyMem (SecuredMessageContext->MasterSecret.DheSecret, FinalKey, FinalKeySize);
  SecuredMessageContext->DheKeySize = FinalKeySize;
  return TRUE;
}
