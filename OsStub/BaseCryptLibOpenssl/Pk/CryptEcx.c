/** @file
  Montgomery-Curve Wrapper Implementation over OpenSSL.

  RFC 7748 - Elliptic Curves for Security (Curve25519/Curve448)
  NIST SP 800-186 - Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <openssl/evp.h>

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
  EVP_PKEY_CTX  *Pctx;
  EVP_PKEY      *Pkey;
  INT32         Result;
  INT32         OpenSslPkeyType;

  switch (Nid) {
  case CRYPTO_NID_CURVE_X25519:
    OpenSslPkeyType = NID_X25519;
    break;
  case CRYPTO_NID_CURVE_X448:
    OpenSslPkeyType = NID_X448;
    break;
  default:
    return NULL;
  }

  Pctx = EVP_PKEY_CTX_new_id(OpenSslPkeyType, NULL);
  if (Pctx == NULL) {
    return NULL;
  }
  Result = EVP_PKEY_keygen_init(Pctx);
  if (Result <= 0) {
    EVP_PKEY_CTX_free(Pctx);
    return NULL;
  }
  Pkey = NULL;
  Result = EVP_PKEY_keygen(Pctx, &Pkey);
  if (Result <= 0) {
    EVP_PKEY_CTX_free(Pctx);
    return NULL;
  }
  EVP_PKEY_CTX_free(Pctx);

  return (VOID *)Pkey;
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
  EVP_PKEY_free ((EVP_PKEY *) EcxContext);
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
  EVP_PKEY *Pkey;
  INT32    Result;
  UINT32   FinalPubKeySize;

  if (EcxContext == NULL || Public == NULL || PublicSize == NULL) {
    return FALSE;
  }

  Pkey = (EVP_PKEY *) EcxContext;
  switch (EVP_PKEY_id(Pkey)) {
  case NID_X25519:
    FinalPubKeySize = 32;
    break;
  case NID_X448:
    FinalPubKeySize = 56;
    break;
  default:
    return FALSE;
  }
  if (*PublicSize < FinalPubKeySize) {
    *PublicSize = FinalPubKeySize;
    return FALSE;
  }
  *PublicSize = FinalPubKeySize;
  ZeroMem (Public, *PublicSize);
  Result = EVP_PKEY_get_raw_public_key (Pkey, Public, PublicSize);
  if (Result == 0) {
    return FALSE;
  }

  return TRUE;
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
  EVP_PKEY_CTX *Pctx;
  EVP_PKEY     *Pkey;
  EVP_PKEY     *PeerKey;
  INT32        Result;
  UINT32       FinalKeySize;
  INT32        OpenSslPkeyType;

  if (EcxContext == NULL || PeerPublic == NULL) {
    return FALSE;
  }

  Pkey = (EVP_PKEY *) EcxContext;
  switch (EVP_PKEY_id(Pkey)) {
  case NID_X25519:
    OpenSslPkeyType = NID_X25519;
    FinalKeySize = 32;
    break;
  case NID_X448:
    OpenSslPkeyType = NID_X448;
    FinalKeySize = 56;
    break;
  default:
    return FALSE;
  }
  if (*KeySize < FinalKeySize) {
    *KeySize = FinalKeySize;
    return FALSE;
  }
  *KeySize = FinalKeySize;
  ZeroMem (Key, *KeySize);

  // Derive Key
  Pctx = EVP_PKEY_CTX_new (Pkey, NULL);
  if (Pctx == NULL) {
    return FALSE;
  }
  Result = EVP_PKEY_derive_init(Pctx);
  if (Result <= 0) {
    EVP_PKEY_CTX_free(Pctx);
    return FALSE;
  }

  PeerKey = EVP_PKEY_new_raw_public_key (OpenSslPkeyType, NULL, PeerPublic, PeerPublicSize);
  if (PeerKey == NULL) {
    EVP_PKEY_CTX_free(Pctx);
    return FALSE;
  }
  Result = EVP_PKEY_derive_set_peer(Pctx, PeerKey);
  if (Result <= 0) {
    EVP_PKEY_free (PeerKey);
    EVP_PKEY_CTX_free(Pctx);
    return FALSE;
  }
  EVP_PKEY_free (PeerKey);

  Result = EVP_PKEY_derive(Pctx, Key, KeySize);
  if (Result <= 0) {
    EVP_PKEY_CTX_free(Pctx);
    return FALSE;
  }

  EVP_PKEY_CTX_free(Pctx);
  return TRUE;
}
