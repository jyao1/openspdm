/** @file
  RSA Asymmetric Cipher Wrapper Implementation over OpenSSL.

  This file implements following APIs which provide more capabilities for RSA:
  1) RsaGetKey
  2) RsaGenerateKey
  3) RsaCheckKey
  4) RsaPkcs1Sign

  RFC 8017 - PKCS #1: RSA Cryptography Specifications Version 2.2

Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <mbedtls/rsa.h>

/**
  Gets the tag-designated RSA key component from the established RSA context.

  This function retrieves the tag-designated RSA key component from the
  established RSA context as a non-negative integer (octet string format
  represented in RSA PKCS#1).
  If specified key component has not been set or has been cleared, then returned
  BnSize is set to 0.
  If the BigNumber buffer is too small to hold the contents of the key, FALSE
  is returned and BnSize is set to the required buffer size to obtain the key.

  If RsaContext is NULL, then return FALSE.
  If BnSize is NULL, then return FALSE.
  If BnSize is large enough but BigNumber is NULL, then return FALSE.

  @param[in, out]  RsaContext  Pointer to RSA context being set.
  @param[in]       KeyTag      Tag of RSA key component being set.
  @param[out]      BigNumber   Pointer to octet integer buffer.
  @param[in, out]  BnSize      On input, the size of big number buffer in bytes.
                               On output, the size of data returned in big number buffer in bytes.

  @retval  TRUE   RSA key component was retrieved successfully.
  @retval  FALSE  Invalid RSA key component tag.
  @retval  FALSE  BnSize is too small.

**/
BOOLEAN
EFIAPI
RsaGetKey (
  IN OUT  VOID         *RsaContext,
  IN      RSA_KEY_TAG  KeyTag,
  OUT     UINT8        *BigNumber,
  IN OUT  UINTN        *BnSize
  )
{
  mbedtls_rsa_context *RsaKey;
  INT32               Ret;
  mbedtls_mpi         Value;
  UINTN               Size;

  //
  // Check input parameters.
  //
  if (RsaContext == NULL || *BnSize > INT_MAX) {
    return FALSE;
  }
  //
  // Init mbedtls_mpi
  //
  mbedtls_mpi_init(&Value);
  Size = *BnSize;
  *BnSize = 0;

  RsaKey = (mbedtls_rsa_context *)RsaContext;

  switch (KeyTag) {
  case RsaKeyN:
    Ret = mbedtls_rsa_export(RsaKey, &Value, NULL, NULL, NULL, NULL);
    break;
  case RsaKeyE:
    Ret = mbedtls_rsa_export(RsaKey, NULL, NULL, NULL, NULL, &Value);
    break;
  case RsaKeyD:
    Ret = mbedtls_rsa_export(RsaKey, NULL, NULL, NULL, &Value, NULL);
    break;
  case RsaKeyQ:
    Ret = mbedtls_rsa_export(RsaKey, NULL, NULL, &Value, NULL, NULL);
    break;
  case RsaKeyP:
    Ret = mbedtls_rsa_export(RsaKey, NULL, &Value, NULL, NULL, NULL);
    break;
  case RsaKeyDp:
    break;
  }

  if (!mbedtls_mpi_size(&Value)) {
    Ret = 0;
    goto End;
  }

  *BnSize = Size;

  if (Ret == 0) {
     Size = mbedtls_mpi_size(&Value);
  }
  if (Size == 0) {
    Ret = 1;
    goto End;
  }

  if (*BnSize < Size) {
    Ret = 1;
    *BnSize = Size;
    goto End;
  }

  if (BigNumber == NULL) {
    Ret = 0;
    *BnSize = Size;
    goto End;
  }

  if (BigNumber != NULL && Ret == 0) {
    Ret = mbedtls_mpi_write_binary(&Value, BigNumber, Size);
    *BnSize = Size;
  }
End:
  mbedtls_mpi_free(&Value);
  return Ret == 0;
}

/**
  Generates RSA key components.

  This function generates RSA key components. It takes RSA public exponent E and
  length in bits of RSA modulus N as input, and generates all key components.
  If PublicExponent is NULL, the default RSA public exponent (0x10001) will be used.

  Before this function can be invoked, pseudorandom number generator must be correctly
  initialized by RandomSeed().

  If RsaContext is NULL, then return FALSE.

  @param[in, out]  RsaContext           Pointer to RSA context being set.
  @param[in]       ModulusLength        Length of RSA modulus N in bits.
  @param[in]       PublicExponent       Pointer to RSA public exponent.
  @param[in]       PublicExponentSize   Size of RSA public exponent buffer in bytes.

  @retval  TRUE   RSA key component was generated successfully.
  @retval  FALSE  Invalid RSA key component tag.

**/
BOOLEAN
EFIAPI
RsaGenerateKey (
  IN OUT  VOID         *RsaContext,
  IN      UINTN        ModulusLength,
  IN      CONST UINT8  *PublicExponent,
  IN      UINTN        PublicExponentSize
  )
{

  INT32 Ret = 0;
  mbedtls_rsa_context *Rsa;
  INT32 PE;
  mbedtls_mpi E;

  //
  // Check input parameters.
  //
  if (RsaContext == NULL || ModulusLength > INT_MAX || PublicExponentSize > INT_MAX) {
    return FALSE;
  }

  Rsa = (mbedtls_rsa_context*)RsaContext;

  mbedtls_mpi_init(&E);

  if(PublicExponent == NULL) {
    PE = 0x10001;
  } else {
    // TBD
    Ret = mbedtls_mpi_read_binary(&E, PublicExponent, PublicExponentSize);
    PE = 0x10001;
  }

  if(Ret == 0) {
    Ret = mbedtls_rsa_gen_key(
      Rsa,
      myrand,
      NULL,
      (UINT32)ModulusLength,
      PE
    );
  }

  return Ret == 0;
}

/**
  Validates key components of RSA context.
  NOTE: This function performs integrity checks on all the RSA key material, so
        the RSA key structure must contain all the private key data.

  This function validates key components of RSA context in following aspects:
  - Whether p is a prime
  - Whether q is a prime
  - Whether n = p * q
  - Whether d*e = 1  mod lcm(p-1,q-1)

  If RsaContext is NULL, then return FALSE.

  @param[in]  RsaContext  Pointer to RSA context to check.

  @retval  TRUE   RSA key components are valid.
  @retval  FALSE  RSA key components are not valid.

**/
BOOLEAN
EFIAPI
RsaCheckKey (
  IN  VOID  *RsaContext
  )
{

  if (RsaContext == NULL) {
    return FALSE;
  }

  UINT32 Ret;

  Ret = mbedtls_rsa_complete(RsaContext);
  if (Ret == 0) {
    Ret = mbedtls_rsa_check_privkey(RsaContext);
  }
  return Ret == 0;
}

/**
  Carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme.

  This function carries out the RSA-SSA signature generation with EMSA-PKCS1-v1_5 encoding scheme defined in
  RSA PKCS#1.
  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  If RsaContext is NULL, then return FALSE.
  If MessageHash is NULL, then return FALSE.
  If HashSize is not equal to the size of MD5, SHA-1, SHA-256, SHA-384 or SHA-512 digest, then return FALSE.
  If SigSize is large enough but Signature is NULL, then return FALSE.

  @param[in]       RsaContext   Pointer to RSA context for signature generation.
  @param[in]       MessageHash  Pointer to octet message hash to be signed.
  @param[in]       HashSize     Size of the message hash in bytes.
  @param[out]      Signature    Pointer to buffer to receive RSA PKCS1-v1_5 signature.
  @param[in, out]  SigSize      On input, the size of Signature buffer in bytes.
                                On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated in PKCS1-v1_5.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.

**/
BOOLEAN
EFIAPI
RsaPkcs1Sign (
  IN      VOID         *RsaContext,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  INT32             Ret;
  mbedtls_md_type_t md_alg;


  if (RsaContext == NULL || MessageHash == NULL) {
    return FALSE;
  }

  switch (HashSize) {
  case SHA256_DIGEST_SIZE:
    md_alg = MBEDTLS_MD_SHA256;
    break;

  case SHA384_DIGEST_SIZE:
    md_alg = MBEDTLS_MD_SHA384;
    break;

  case SHA512_DIGEST_SIZE:
    md_alg = MBEDTLS_MD_SHA512;
    break;

  default:
    return FALSE;
  }

  if (mbedtls_rsa_get_len (RsaContext) > *SigSize) {
    *SigSize = mbedtls_rsa_get_len(RsaContext);
    return FALSE;
  }

  mbedtls_rsa_set_padding (RsaContext, MBEDTLS_RSA_PKCS_V15, md_alg);

  Ret = mbedtls_rsa_pkcs1_sign (
          RsaContext,
          myrand,
          NULL,
          MBEDTLS_RSA_PRIVATE,
          md_alg,
          (UINT32)HashSize,
          MessageHash,
          Signature
          );
  if (Ret != 0) {
    return FALSE;
  }
  *SigSize = mbedtls_rsa_get_len (RsaContext);
  return TRUE;
}

/**
  Carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme.

  This function carries out the RSA-SSA signature generation with EMSA-PSS encoding scheme defined in
  RSA PKCS#1 v2.2.
  The salt length is same as digest length.
  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  If RsaContext is NULL, then return FALSE.
  If MessageHash is NULL, then return FALSE.
  If HashSize is not equal to the size of SHA-1, SHA-256, SHA-384 or SHA-512 digest, then return FALSE.
  If SigSize is large enough but Signature is NULL, then return FALSE.

  @param[in]       RsaContext   Pointer to RSA context for signature generation.
  @param[in]       MessageHash  Pointer to octet message hash to be signed.
  @param[in]       HashSize     Size of the message hash in bytes.
  @param[out]      Signature    Pointer to buffer to receive RSA-SSA PSS signature.
  @param[in, out]  SigSize      On input, the size of Signature buffer in bytes.
                                On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated in RSA-SSA PSS.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.

**/
BOOLEAN
EFIAPI
RsaPssSign (
  IN      VOID         *RsaContext,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  INT32             Ret;
  mbedtls_md_type_t md_alg;


  if (RsaContext == NULL || MessageHash == NULL) {
    return FALSE;
  }

  switch (HashSize) {
  case SHA256_DIGEST_SIZE:
    md_alg = MBEDTLS_MD_SHA256;
    break;

  case SHA384_DIGEST_SIZE:
    md_alg = MBEDTLS_MD_SHA384;
    break;

  case SHA512_DIGEST_SIZE:
    md_alg = MBEDTLS_MD_SHA512;
    break;

  default:
    return FALSE;
  }

  if (Signature == NULL) {
    //
    // If Signature is NULL, return safe SignatureSize
    //
    *SigSize = MBEDTLS_MPI_MAX_SIZE;
    return FALSE;
  }

  mbedtls_rsa_set_padding (RsaContext, MBEDTLS_RSA_PKCS_V21, md_alg);

  Ret = mbedtls_rsa_rsassa_pss_sign (
          RsaContext,
          myrand,
          NULL,
          MBEDTLS_RSA_PRIVATE,
          md_alg,
          (UINT32)HashSize,
          MessageHash,
          Signature
          );
  if (Ret != 0) {
    return FALSE;
  }
  *SigSize = ((mbedtls_rsa_context*)RsaContext)->len;
  return TRUE;
}
