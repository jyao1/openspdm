/** @file
  Elliptic Curve Wrapper Implementation over OpenSSL.

  RFC 8422 - Elliptic Curve Cryptography (ECC) Cipher Suites
  FIPS 186-4 - Digital Signature Standard (DSS)

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

/**
  Allocates and Initializes one Elliptic Curve Context for subsequent use.

  @return  Pointer to the Elliptic Curve Context that has been initialized.
           If the allocations fails, EcNew() returns NULL.

**/
VOID *
EFIAPI
EcNew (
  VOID
  )
{
  return EC_KEY_new();
}

/**
  Allocates and Initializes one Elliptic Curve Context for subsequent use
  with the NID.
  
  @param Nid cipher NID

  @return  Pointer to the Elliptic Curve Context that has been initialized.
           If the allocations fails, EcNewByNid() returns NULL.

**/
VOID *
EFIAPI
EcNewByNid (
  IN UINTN  Nid
  )
{
  EC_KEY   *EcKey;
  EC_GROUP *Group;
  BOOLEAN  RetVal;
  INT32    OpenSslNid;

  EcKey = EC_KEY_new();
  if (EcKey == NULL) {
    return NULL;
  }
  switch (Nid) {
  case CRYPTO_NID_SECP256R1:
    OpenSslNid = NID_X9_62_prime256v1;
    break;
  case CRYPTO_NID_SECP384R1:
    OpenSslNid = NID_secp384r1;
    break;
  case CRYPTO_NID_SECP521R1:
    OpenSslNid = NID_secp521r1;
    break;
  default:
    return NULL;
  }
  
  Group = EC_GROUP_new_by_curve_name(OpenSslNid);
  if (Group == NULL) {
    return NULL;
  }
  RetVal = (BOOLEAN) EC_KEY_set_group(EcKey, Group);
  EC_GROUP_free(Group);
  if (!RetVal) {
    return NULL;
  }
  return (VOID *)EcKey;
}

/**
  Release the specified EC context.
  
  @param[in]  EcContext  Pointer to the EC context to be released.

**/
VOID
EFIAPI
EcFree (
  IN  VOID  *EcContext
  )
{
  EC_KEY_free ((EC_KEY *) EcContext);
}

/**
  Generates EC key.

  If EcContext is NULL, then return FALSE.

  @param[in, out]  EcContext      Pointer to the EC context.

  @retval TRUE   EC Key generation succeeded.
  @retval FALSE  EC Key generation failed.

**/
BOOLEAN
EFIAPI
EcGenerateKey (
  IN OUT  VOID   *EcContext
  )
{
  EC_KEY     *EcKey;
  BOOLEAN    RetVal;
  
  if (EcContext == NULL) {
    return FALSE;
  }

  EcKey = (EC_KEY *)EcContext;

  RetVal = (BOOLEAN) EC_KEY_generate_key (EcKey);
  if (!RetVal) {
    return FALSE;
  }
  
  return RetVal;
}

/**
  Validates key components of EC context.
  NOTE: This function performs integrity checks on all the EC key material, so
        the EC key structure must contain all the private key data.

  If EcContext is NULL, then return FALSE.

  @param[in]  EcContext  Pointer to EC context to check.

  @retval  TRUE   EC key components are valid.
  @retval  FALSE  EC key components are not valid.

**/
BOOLEAN
EFIAPI
EcCheckKey (
  IN  VOID  *EcContext
  )
{
  EC_KEY     *EcKey;
  BOOLEAN    RetVal;

  if (EcContext == NULL) {
    return FALSE;
  }
  
  EcKey = (EC_KEY *)EcContext;

  RetVal = (BOOLEAN) EC_KEY_check_key (EcKey);
  if (!RetVal) {
    return FALSE;
  }

  return TRUE;
}

/**
  Gets EC public key (X, Y).

  This function generates random secret, and computes the public key (X, Y), which is
  returned via parameter Public, PublicSize.
  X is the first half of Public with size being PublicSize / 2,
  Y is the second half of Public with size being PublicSize / 2.
  EC context is updated accordingly.
  If the Public buffer is too small to hold the public X, Y, FALSE is returned and
  PublicSize is set to the required buffer size to obtain the public X, Y.

  If EcContext is NULL, then return FALSE.
  If PublicSize is NULL, then return FALSE.
  If PublicSize is large enough but Public is NULL, then return FALSE.

  @param[in, out]  EcContext      Pointer to the EC context.
  @param[out]      Public         Pointer to the buffer to receive generated public X,Y.
  @param[in, out]  PublicSize     On input, the size of Public buffer in bytes.
                                  On output, the size of data returned in Public buffer in bytes.

  @retval TRUE   EC public X,Y generation succeeded.
  @retval FALSE  EC public X,Y generation failed.
  @retval FALSE  PublicSize is not large enough.

**/
BOOLEAN
EFIAPI
EcGetPublicKey (
  IN OUT  VOID   *EcContext,
  OUT     UINT8  *Public,
  IN OUT  UINTN  *PublicSize
  )
{
  EC_KEY     *EcKey;
  EC_GROUP   *Group;
  BOOLEAN    RetVal;
  EC_POINT   *EcPoint;
  BIGNUM     *BnX;
  BIGNUM     *BnY;
  INTN       XSize;
  INTN       YSize;

  if (EcContext == NULL || PublicSize == NULL) {
    return FALSE;
  }

  if (Public == NULL && *PublicSize != 0) {
    return FALSE;
  }
  
  EcKey = (EC_KEY *)EcContext;
  Group = EC_KEY_get0_group (EcKey);

  EcPoint = EC_KEY_get0_public_key (EcKey);
  if (EcPoint == NULL) {
    return FALSE;
  }
   
  BnX = BN_new();
  BnY = BN_new();
  if (BnX == NULL || BnY == NULL) {
    RetVal = FALSE;
    goto Done;
  }
 
  RetVal = (BOOLEAN) EC_POINT_get_affine_coordinates(Group, EcPoint, BnX, BnY, NULL);
  if (!RetVal) {
    goto Done;
  }

  XSize = BN_num_bytes (BnX);
  YSize = BN_num_bytes (BnY);
  if (XSize <= 0 || YSize <= 0) {
    RetVal = FALSE;
    goto Done;
  }
  if (*PublicSize < (UINTN) (XSize + YSize)) {
    *PublicSize = XSize + YSize;
    RetVal = TRUE;
    goto Done;
  }

  if (Public != NULL) {
    BN_bn2bin (BnX, Public);
    BN_bn2bin (BnY, Public + XSize);
  }
  *PublicSize = XSize + YSize;
  RetVal = TRUE;

Done:
  if (BnX != NULL) {
    BN_free (BnX);
  }
  if (BnY != NULL) {
    BN_free (BnY);
  }
  return RetVal;
}

/**
  Computes exchanged common key.

  Given peer's public key (X, Y), this function computes the exchanged common key,
  based on its own context including value of curve parameter and random secret.
  X is the first half of PeerPublic with size being PeerPublicSize / 2,
  Y is the second half of PeerPublic with size being PeerPublicSize / 2.

  If EcContext is NULL, then return FALSE.
  If PeerPublic is NULL, then return FALSE.
  If PeerPublicSize is 0, then return FALSE.
  If Key is NULL, then return FALSE.
  If KeySize is not large enough, then return FALSE.

  @param[in, out]  EcContext          Pointer to the EC context.
  @param[in]       PeerPublic         Pointer to the peer's public X,Y.
  @param[in]       PeerPublicSize     Size of peer's public X,Y in bytes.
  @param[out]      Key                Pointer to the buffer to receive generated key.
  @param[in, out]  KeySize            On input, the size of Key buffer in bytes.
                                      On output, the size of data returned in Key buffer in bytes.

  @retval TRUE   EC exchanged key generation succeeded.
  @retval FALSE  EC exchanged key generation failed.
  @retval FALSE  KeySize is not large enough.

**/
BOOLEAN
EFIAPI
EcComputeKey (
  IN OUT  VOID         *EcContext,
  IN      CONST UINT8  *PeerPublic,
  IN      UINTN        PeerPublicSize,
  OUT     UINT8        *Key,
  IN OUT  UINTN        *KeySize
  )
{
  EC_KEY     *EcKey;
  EC_GROUP   *Group;
  BOOLEAN    RetVal;
  BIGNUM     *BnX;
  BIGNUM     *BnY;
  EC_POINT   *Point;
  INTN       Size;

  if (EcContext == NULL || PeerPublic == NULL || KeySize == NULL || Key == NULL) {
    return FALSE;
  }

  if (PeerPublicSize > INT_MAX) {
    return FALSE;
  }
  
  EcKey = (EC_KEY *)EcContext;
  Group = EC_KEY_get0_group (EcKey);
  Point = NULL;

  BnX = BN_bin2bn (PeerPublic, (UINT32) PeerPublicSize / 2, NULL);
  BnY = BN_bin2bn (PeerPublic + PeerPublicSize / 2, (UINT32) PeerPublicSize / 2, NULL);
  if (BnX == NULL || BnY == NULL) {
    RetVal = FALSE;
    goto Done;
  }
  Point = EC_POINT_new(Group);
  if (Point == NULL) {
    goto Done;
  }

  RetVal = (BOOLEAN) EC_POINT_set_affine_coordinates(Group, Point, BnX, BnY, NULL);
  if (!RetVal) {
    goto Done;
  }

  Size = ECDH_compute_key (Key, *KeySize, Point, EcKey, NULL);
  if (Size < 0) {
    RetVal = FALSE;
    goto Done;
  }

  if (*KeySize < (UINTN) Size) {
    *KeySize = Size;
    RetVal = FALSE;
    goto Done;
  }

  *KeySize = Size;
  
  RetVal = TRUE;

Done:
  if (BnX != NULL) {
    BN_free (BnX);
  }
  if (BnY != NULL) {
    BN_free (BnY);
  }
  if (Point != NULL) {
    EC_POINT_free(Point);
  }
  return RetVal;
}

/**
  Carries out the EC-DSA signature.

  This function carries out the EC-DSA signature.
  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  If EcContext is NULL, then return FALSE.
  If MessageHash is NULL, then return FALSE.
  If HashSize is not equal to the size of SHA-1, SHA-256, SHA-384 or SHA-512 digest, then return FALSE.
  If SigSize is large enough but Signature is NULL, then return FALSE.

  @param[in]       EcContext    Pointer to EC context for signature generation.
  @param[in]       MessageHash  Pointer to octet message hash to be signed.
  @param[in]       HashSize     Size of the message hash in bytes.
  @param[out]      Signature    Pointer to buffer to receive EC-DSA signature.
  @param[in, out]  SigSize      On input, the size of Signature buffer in bytes.
                                On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated in EC-DSA.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.

**/
BOOLEAN
EFIAPI
EcDsaSign (
  IN      VOID         *EcContext,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  EC_KEY     *EcKey;
  UINTN      Size;
  INT32      DigestType;
  
  if (EcContext == NULL || MessageHash == NULL) {
    return FALSE;
  }
  
  EcKey = (EC_KEY *) EcContext;
  Size = ECDSA_size (EcKey);
  
  if (*SigSize < Size) {
    *SigSize = Size;
    return FALSE;
  }
  *SigSize = Size;

  if (Signature == NULL) {
    return FALSE;
  }

  //
  // Determine the message digest algorithm according to digest size.
  //
  switch (HashSize) {
  case SHA256_DIGEST_SIZE:
    DigestType = NID_sha256;
    break;
    
  case SHA384_DIGEST_SIZE:
    DigestType = NID_sha384;
    break;

  case SHA512_DIGEST_SIZE:
    DigestType = NID_sha512;
    break;

  default:
    return FALSE;
  }

  return (BOOLEAN) ECDSA_sign (
                     DigestType,
                     MessageHash,
                     (UINT32) HashSize,
                     Signature,
                     (UINT32 *) SigSize,
                     (EC_KEY *) EcContext
                     );
}

/**
  Verifies the EC-DSA signature.

  If EcContext is NULL, then return FALSE.
  If MessageHash is NULL, then return FALSE.
  If Signature is NULL, then return FALSE.
  If HashSize is not equal to the size of SHA-1, SHA-256, SHA-384 or SHA-512 digest, then return FALSE.

  @param[in]  EcContext    Pointer to EC context for signature verification.
  @param[in]  MessageHash  Pointer to octet message hash to be checked.
  @param[in]  HashSize     Size of the message hash in bytes.
  @param[in]  Signature    Pointer to EC-DSA signature to be verified.
  @param[in]  SigSize      Size of signature in bytes.

  @retval  TRUE   Valid signature encoded in EC-DSA.
  @retval  FALSE  Invalid signature or invalid EC context.

**/
BOOLEAN
EFIAPI
EcDsaVerify (
  IN  VOID         *EcContext,
  IN  CONST UINT8  *MessageHash,
  IN  UINTN        HashSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  )
{
  INT32    DigestType;
  UINT8    *SigBuf;

  if (EcContext == NULL || MessageHash == NULL || Signature == NULL) {
    return FALSE;
  }

  if (SigSize > INT_MAX || SigSize == 0) {
    return FALSE;
  }

  //
  // Determine the message digest algorithm according to digest size.
  //
  switch (HashSize) {
  case SHA256_DIGEST_SIZE:
    DigestType = NID_sha256;
    break;
    
  case SHA384_DIGEST_SIZE:
    DigestType = NID_sha384;
    break;

  case SHA512_DIGEST_SIZE:
    DigestType = NID_sha512;
    break;

  default:
    return FALSE;
  }

  SigBuf = (UINT8 *) Signature;
  return (BOOLEAN) ECDSA_verify (
                     DigestType,
                     MessageHash,
                     (UINT32) HashSize,
                     SigBuf,
                     (UINT32) SigSize,
                     (EC_KEY *) EcContext
                     );
}
