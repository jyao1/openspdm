/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

typedef
BOOLEAN
(EFIAPI *HASH_ALL) (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  );

typedef
BOOLEAN
(EFIAPI *HMAC_ALL) (
  IN   CONST VOID   *Data,
  IN   UINTN        DataSize,
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize,
  OUT  UINT8        *HmacValue
  );

typedef
BOOLEAN
(EFIAPI *HKDF_EXPAND) (
  IN   CONST UINT8  *Prk,
  IN   UINTN        PrkSize,
  IN   CONST UINT8  *Info,
  IN   UINTN        InfoSize,
  OUT  UINT8        *Out,
  IN   UINTN        OutSize
  );

typedef
BOOLEAN
(EFIAPI *AEAD_ENCRYPT) (
  IN   CONST UINT8* Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8* Iv,
  IN   UINTN        IvSize,
  IN   CONST UINT8* AData,
  IN   UINTN        ADataSize,
  IN   CONST UINT8* DataIn,
  IN   UINTN        DataInSize,
  OUT  UINT8*       TagOut,
  IN   UINTN        TagSize,
  OUT  UINT8*       DataOut,
  OUT  UINTN*       DataOutSize
  );

typedef
BOOLEAN
(EFIAPI *AEAD_DECRYPT) (
  IN   CONST UINT8* Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8* Iv,
  IN   UINTN        IvSize,
  IN   CONST UINT8* AData,
  IN   UINTN        ADataSize,
  IN   CONST UINT8* DataIn,
  IN   UINTN        DataInSize,
  IN   CONST UINT8* Tag,
  IN   UINTN        TagSize,
  OUT  UINT8*       DataOut,
  OUT  UINTN*       DataOutSize
  );

typedef
BOOLEAN
(EFIAPI *ASYM_GET_PUBLIC_KEY_FROM_X509) (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize,
  OUT  VOID         **Context
  );

typedef
VOID
(EFIAPI *ASYM_FREE) (
  IN  VOID         *Context
  );

typedef
BOOLEAN
(EFIAPI *ASYM_VERIFY) (
  IN  VOID         *Context,
  IN  CONST UINT8  *MessageHash,
  IN  UINTN        HashSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  );

typedef
VOID *
(EFIAPI *DHE_NEW_BY_NID) (
  IN UINTN  Nid
  );

typedef
BOOLEAN
(EFIAPI *DHE_GENERATE_KEY) (
  IN OUT  VOID   *Context,
  OUT     UINT8  *PublicKey,
  IN OUT  UINTN  *PublicKeySize
  );

typedef
BOOLEAN
(EFIAPI *DHE_COMPUTE_KEY) (
  IN OUT  VOID         *Context,
  IN      CONST UINT8  *PeerPublic,
  IN      UINTN        PeerPublicSize,
  OUT     UINT8        *Key,
  IN OUT  UINTN        *KeySize
  );

typedef
VOID
(EFIAPI *DHE_FREE) (
  IN  VOID  *Context
  );

/**
  This function returns the SPDM hash size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM hash size
**/
UINT32
GetSpdmHashSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
    return 32;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
    return 48;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
    return 64;
  }
  return 0;
}

HASH_ALL
GetSpdmHashFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if OPENSPDM_SHA256_SUPPORT == 1
    return Sha256HashAll;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if OPENSPDM_SHA384_SUPPORT == 1
    return Sha384HashAll;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if OPENSPDM_SHA512_SUPPORT == 1
    return Sha512HashAll;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
    ASSERT (FALSE);
    break;
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmHashAll (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  )
{
  HASH_ALL   HashFunction;
  HashFunction = GetSpdmHashFunc (SpdmContext);
  if (HashFunction == NULL) {
    return FALSE;
  }
  return HashFunction (Data, DataSize, HashValue);
}

HASH_ALL
GetSpdmMeasurementHashFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo) {
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
#if OPENSPDM_SHA256_SUPPORT == 1
    return Sha256HashAll;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
#if OPENSPDM_SHA384_SUPPORT == 1
    return Sha384HashAll;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
#if OPENSPDM_SHA512_SUPPORT == 1
    return Sha512HashAll;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
    ASSERT (FALSE);
    break;
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmMeasurementHashAll (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  )
{
  HASH_ALL   HashFunction;
  HashFunction = GetSpdmMeasurementHashFunc (SpdmContext);
  if (HashFunction == NULL) {
    return FALSE;
  }
  return HashFunction (Data, DataSize, HashValue);
}

HMAC_ALL
GetSpdmHmacFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if OPENSPDM_HMAC_SHA256_SUPPORT == 1
    return HmacSha256All;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
    ASSERT (FALSE);
    break;
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmHmacAll (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  IN   CONST UINT8                  *Key,
  IN   UINTN                        KeySize,
  OUT  UINT8                        *HmacValue
  )
{
  HMAC_ALL   HmacFunction;
  HmacFunction = GetSpdmHmacFunc (SpdmContext);
  if (HmacFunction == NULL) {
    return FALSE;
  }
  return HmacFunction (Data, DataSize, Key, KeySize, HmacValue);
}

HKDF_EXPAND
GetSpdmHkdfExpandFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if OPENSPDM_HKDF_SHA256_SUPPORT == 1
    return HkdfSha256Expand;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
    ASSERT (FALSE);
    break;
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmHkdfExpand (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8                  *Prk,
  IN   UINTN                        PrkSize,
  IN   CONST UINT8                  *Info,
  IN   UINTN                        InfoSize,
  OUT  UINT8                        *Out,
  IN   UINTN                        OutSize
  )
{
  HKDF_EXPAND   HkdfExpandFunction;
  HkdfExpandFunction = GetSpdmHkdfExpandFunc (SpdmContext);
  if (HkdfExpandFunction == NULL) {
    return FALSE;
  }
  return HkdfExpandFunction (Prk, PrkSize, Info, InfoSize, Out, OutSize);
}

/**
  This function returns the SPDM asym size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM hash size
**/
UINT32
GetSpdmAsymSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    return 256;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    return 384;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
    return 512;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    return 32 * 2;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    return 48 * 2;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
    return 66 * 2;
  }
  return 0;
}

/**
  This function returns the SPDM Request asym size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM hash size
**/
UINT32
GetSpdmReqAsymSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    return 256;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    return 384;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
    return 512;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    return 32 * 2;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    return 48 * 2;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
    return 66 * 2;
  }
  return 0;
}

/**
  This function returns the SPDM measurement hash size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM measurement hash size
**/
UINT32
GetSpdmMeasurementHashSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo) {
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
    return 32;
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
    return 48;
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
    return 64;
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY:
    return 0;
  }
  return 0;
}

/**
  This function returns the SPDM DheKey size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM DheKey size
**/
UINT32
GetSpdmDheKeySize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
    return 256;
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
    return 384;
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
    return 512;
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
    return 32 * 2;
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
    return 48 * 2;
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
    return 66 * 2;
  }
  return 0;
}

UINTN
GetSpdmDheNid (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
    return CRYPTO_NID_FFDHE2048;
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
    return CRYPTO_NID_FFDHE3072;
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
    return CRYPTO_NID_FFDHE4096;
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
    return CRYPTO_NID_SECP256R1;
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
    return CRYPTO_NID_SECP384R1;
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
    return CRYPTO_NID_SECP521R1;
  }
  return 0;
}

/**
  This function returns the SPDM AEAD key size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM AEAD key size
**/
UINT32
GetSpdmAeadKeySize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
    return 16;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
    return 32;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
    return 32;
  }
  return 0;
}

/**
  This function returns the SPDM AEAD iv size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM AEAD iv size
**/
UINT32
GetSpdmAeadIvSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
    return 12;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
    return 12;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
    return 12;
  }
  return 0;
}

/**
  This function returns the SPDM AEAD tag size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM AEAD iv size
**/
UINT32
GetSpdmAeadTagSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
    return 16;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
    return 16;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
    return 16;
  }
  return 0;
}

/**
  This function returns the SPDM AEAD block size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM AEAD iv size
**/
UINT32
GetSpdmAeadBlockSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
    return 16;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
    return 16;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
    return 16;
  }
  return 0;
}

AEAD_ENCRYPT
GetSpdmAeadEncFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
    return AeadAesGcmEncrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
    return AeadAesGcmEncrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
#if OPENSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
    return AeadChaCha20Poly1305Encrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmAeadEncryption (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8*                 Key,
  IN   UINTN                        KeySize,
  IN   CONST UINT8*                 Iv,
  IN   UINTN                        IvSize,
  IN   CONST UINT8*                 AData,
  IN   UINTN                        ADataSize,
  IN   CONST UINT8*                 DataIn,
  IN   UINTN                        DataInSize,
  OUT  UINT8*                       TagOut,
  IN   UINTN                        TagSize,
  OUT  UINT8*                       DataOut,
  OUT  UINTN*                       DataOutSize
  )
{
  AEAD_ENCRYPT   AeadEncFunction;
  AeadEncFunction = GetSpdmAeadEncFunc (SpdmContext);
  if (AeadEncFunction == NULL) {
    return FALSE;
  }
  return AeadEncFunction (Key, KeySize, Iv, IvSize, AData, ADataSize, DataIn, DataInSize, TagOut, TagSize, DataOut, DataOutSize);
}

AEAD_DECRYPT
GetSpdmAeadDecFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
    return AeadAesGcmDecrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
    return AeadAesGcmDecrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
#if OPENSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
    return AeadChaCha20Poly1305Decrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmAeadDecryption (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8*                 Key,
  IN   UINTN                        KeySize,
  IN   CONST UINT8*                 Iv,
  IN   UINTN                        IvSize,
  IN   CONST UINT8*                 AData,
  IN   UINTN                        ADataSize,
  IN   CONST UINT8*                 DataIn,
  IN   UINTN                        DataInSize,
  IN   CONST UINT8*                 Tag,
  IN   UINTN                        TagSize,
  OUT  UINT8*                       DataOut,
  OUT  UINTN*                       DataOutSize
  )
{
  AEAD_DECRYPT   AeadDecFunction;
  AeadDecFunction = GetSpdmAeadDecFunc (SpdmContext);
  if (AeadDecFunction == NULL) {
    return FALSE;
  }
  return AeadDecFunction (Key, KeySize, Iv, IvSize, AData, ADataSize, DataIn, DataInSize, Tag, TagSize, DataOut, DataOutSize);
}

ASYM_GET_PUBLIC_KEY_FROM_X509
GetSpdmAsymGetPublicKeyFromX509 (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (OPENSPDM_RSA_SSA_SUPPORT == 1) || (OPENSPDM_RSA_PSS_SUPPORT == 1)
    return RsaGetPublicKeyFromX509;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
    return EcGetPublicKeyFromX509;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmAsymGetPublicKeyFromX509 (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8                  *Cert,
  IN   UINTN                        CertSize,
  OUT  VOID                         **Context
  )
{
  ASYM_GET_PUBLIC_KEY_FROM_X509   GetPublicKeyFromX509Function;
  GetPublicKeyFromX509Function = GetSpdmAsymGetPublicKeyFromX509 (SpdmContext);
  if (GetPublicKeyFromX509Function == NULL) {
    return FALSE;
  }
  return GetPublicKeyFromX509Function (Cert, CertSize, Context);
}

ASYM_FREE
GetSpdmAsymFree (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (OPENSPDM_RSA_SSA_SUPPORT == 1) || (OPENSPDM_RSA_PSS_SUPPORT == 1)
    return RsaFree;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
    return EcFree;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

VOID
SpdmAsymFree (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context
  )
{
  ASYM_FREE   FreeFunction;
  FreeFunction = GetSpdmAsymFree (SpdmContext);
  if (FreeFunction == NULL) {
    return ;
  }
  FreeFunction (Context);
}

ASYM_VERIFY
GetSpdmAsymVerify (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if OPENSPDM_RSA_SSA_SUPPORT == 1
    return RsaPkcs1Verify;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if OPENSPDM_RSA_PSS_SUPPORT == 1
    return RsaPssVerify;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
    return EcDsaVerify;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmAsymVerify (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context,
  IN   CONST UINT8                  *MessageHash,
  IN   UINTN                        HashSize,
  IN   CONST UINT8                  *Signature,
  IN   UINTN                        SigSize
  )
{
  ASYM_VERIFY   VerifyFunction;
  VerifyFunction = GetSpdmAsymVerify (SpdmContext);
  if (VerifyFunction == NULL) {
    return FALSE;
  }
  return VerifyFunction (Context, MessageHash, HashSize, Signature, SigSize);
}

ASYM_GET_PUBLIC_KEY_FROM_X509
GetSpdmReqAsymGetPublicKeyFromX509 (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (OPENSPDM_RSA_SSA_SUPPORT == 1) || (OPENSPDM_RSA_PSS_SUPPORT == 1)
    return RsaGetPublicKeyFromX509;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
    return EcGetPublicKeyFromX509;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmReqAsymGetPublicKeyFromX509 (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8                  *Cert,
  IN   UINTN                        CertSize,
  OUT  VOID                         **Context
  )
{
  ASYM_GET_PUBLIC_KEY_FROM_X509   GetPublicKeyFromX509Function;
  GetPublicKeyFromX509Function = GetSpdmReqAsymGetPublicKeyFromX509 (SpdmContext);
  if (GetPublicKeyFromX509Function == NULL) {
    return FALSE;
  }
  return GetPublicKeyFromX509Function (Cert, CertSize, Context);
}

ASYM_FREE
GetSpdmReqAsymFree (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (OPENSPDM_RSA_SSA_SUPPORT == 1) || (OPENSPDM_RSA_PSS_SUPPORT == 1)
    return RsaFree;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
    return EcFree;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

VOID
SpdmReqAsymFree (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context
  )
{
  ASYM_FREE   FreeFunction;
  FreeFunction = GetSpdmReqAsymFree (SpdmContext);
  if (FreeFunction == NULL) {
    return ;
  }
  FreeFunction (Context);
}

ASYM_VERIFY
GetSpdmReqAsymVerify (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if OPENSPDM_RSA_SSA_SUPPORT == 1
    return RsaPkcs1Verify;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if OPENSPDM_RSA_PSS_SUPPORT == 1
    return RsaPssVerify;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
    return EcDsaVerify;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmReqAsymVerify (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context,
  IN   CONST UINT8                  *MessageHash,
  IN   UINTN                        HashSize,
  IN   CONST UINT8                  *Signature,
  IN   UINTN                        SigSize
  )
{
  ASYM_VERIFY   VerifyFunction;
  VerifyFunction = GetSpdmReqAsymVerify (SpdmContext);
  if (VerifyFunction == NULL) {
    return FALSE;
  }
  return VerifyFunction (Context, MessageHash, HashSize, Signature, SigSize);
}

DHE_NEW_BY_NID
GetSpdmDheNew (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_DHE_SUPPORT == 1
    return DhNewByNid;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if OPENSPDM_ECDHE_SUPPORT == 1
    return EcNewByNid;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

VOID *
SpdmDheNew (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  DHE_NEW_BY_NID   NewFunction;
  UINTN            Nid;

  NewFunction = GetSpdmDheNew (SpdmContext);
  if (NewFunction == NULL) {
    return NULL;
  }
  Nid = GetSpdmDheNid (SpdmContext);
  if (Nid == 0) {
    return NULL;
  }
  return NewFunction (Nid);
}

DHE_FREE
GetSpdmDheFree (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_DHE_SUPPORT == 1
    return DhFree;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if OPENSPDM_ECDHE_SUPPORT == 1
    return EcFree;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

VOID
SpdmDheFree (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context
  )
{
  DHE_FREE   FreeFunction;
  FreeFunction = GetSpdmDheFree (SpdmContext);
  if (FreeFunction == NULL) {
    return ;
  }
  FreeFunction (Context);
}

DHE_GENERATE_KEY
GetSpdmDheGenerateKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_DHE_SUPPORT == 1
    return DhGenerateKey;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if OPENSPDM_ECDHE_SUPPORT == 1
    return EcGenerateKey;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmDheGenerateKey (
  IN      SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN OUT  VOID                         *Context,
  OUT     UINT8                        *PublicKey,
  IN OUT  UINTN                        *PublicKeySize
  )
{
  DHE_GENERATE_KEY   GenerateKeyFunction;
  GenerateKeyFunction = GetSpdmDheGenerateKey (SpdmContext);
  if (GenerateKeyFunction == NULL) {
    return FALSE;
  }
  return GenerateKeyFunction (Context, PublicKey, PublicKeySize);
}

DHE_COMPUTE_KEY
GetSpdmDheComputeKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_DHE_SUPPORT == 1
    return DhComputeKey;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1:
#if OPENSPDM_ECDHE_SUPPORT == 1
    return EcComputeKey;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

BOOLEAN
SpdmDheComputeKey (
  IN      SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN OUT  VOID                         *Context,
  IN      CONST UINT8                  *PeerPublic,
  IN      UINTN                        PeerPublicSize,
  OUT     UINT8                        *Key,
  IN OUT  UINTN                        *KeySize
  )
{
  DHE_COMPUTE_KEY   ComputeKeyFunction;
  ComputeKeyFunction = GetSpdmDheComputeKey (SpdmContext);
  if (ComputeKeyFunction == NULL) {
    return FALSE;
  }
  return ComputeKeyFunction (Context, PeerPublic, PeerPublicSize, Key, KeySize);
}

VOID
SpdmGetRandomNumber (
  IN  UINTN                     Size,
  OUT UINT8                     *Rand
  )
{
  RandomBytes (Rand, Size);

  return ;
}

STATIC
BOOLEAN InternalSpdmX509DateTimeCheck(
  IN UINT8 *From,
  IN OUT UINTN FromSize,
  IN OUT UINT8 *To,
  IN OUT UINTN ToSize)
{
  INTN Ret;
  RETURN_STATUS ReturnStatus;
  UINT8 F0[64];
  UINT8 T0[64];
  UINTN F0Size;
  UINTN T0Size;
  F0Size = 64;
  T0Size = 64;

  ReturnStatus = X509SetDateTime ("19700101000000Z", F0, &F0Size);
  if (ReturnStatus == RETURN_SUCCESS) {
    ReturnStatus = X509SetDateTime ("99991231235959Z", T0, &T0Size);
  }

  if (ReturnStatus != RETURN_SUCCESS) {
    return FALSE;
  }

  // From >= F0
  Ret = X509CompareDateTime(From, F0);
  if (Ret < 0) {
    return FALSE;
  }

  // To <= T0
  Ret = X509CompareDateTime(T0, To);
  if (Ret < 0) {
    return FALSE;
  }

  return TRUE;
}

/**
  Certificate Check for SPDM leaf cert.

  @param[in]  Cert            Pointer to the DER-encoded certificate data.
  @param[in]  CertSize        The size of certificate data in bytes.

  @retval  TRUE   Success.
  @retval  FALSE  Certificate is not valid
**/
BOOLEAN
EFIAPI
SpdmX509CertificateCheck(
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize
)
{
  UINT8         EndCertFrom[64];
  UINTN         EndCertFromLen;
  UINT8         EndCertTo[64];
  UINTN         EndCertToLen;
  UINTN         Asn1BufferLen;
  BOOLEAN       Status;
  UINTN         CertVersion;
  RETURN_STATUS Ret;
  UINTN         Value;
  VOID          *RsaContext;
  VOID          *EcContext;

  if (Cert == NULL || CertSize == 0) {
    return FALSE;
  }

  Status = TRUE;
  RsaContext = NULL;
  EcContext = NULL;
  EndCertFromLen = 64;
  EndCertToLen = 64;

  // 1. Version
  CertVersion = 0;
  Ret = X509GetVersion (Cert, CertSize, &CertVersion);
  if (RETURN_ERROR (Ret)) {
    Status = FALSE;
    goto Cleanup;
  }
  if (CertVersion != 2) {
    Status = FALSE;
    goto Cleanup;
  }

  // 2. SerialNumber
  Asn1BufferLen = 0;
  Ret = X509GetSerialNumber(Cert, CertSize, NULL, &Asn1BufferLen);
  if (Ret != RETURN_BUFFER_TOO_SMALL) {
    Status = FALSE;
    goto Cleanup;
  }

  // 3. SinatureAlgorithem
  Value = 0;
  Ret = X509GetSignatureAlgorithm (Cert, CertSize, NULL, &Value);
  if (Ret != RETURN_BUFFER_TOO_SMALL || Value == 0) {
    Status = FALSE;
    goto Cleanup;
  }

  // 4. Issuer
  Asn1BufferLen = 0;
  Status  = X509GetIssuerName (Cert, CertSize, NULL, &Asn1BufferLen);
  if (Status && Asn1BufferLen == 0) {
    goto Cleanup;
  }
  if (Asn1BufferLen <= 0) {
    Status = FALSE;
    goto Cleanup;
  }

  // 5. SubjectName
  Asn1BufferLen = 0;
  Status  = X509GetSubjectName (Cert, CertSize, NULL, &Asn1BufferLen);
  if (Status && Asn1BufferLen == 0) {
    goto Cleanup;
  }
  if (Asn1BufferLen <= 0) {
    Status = FALSE;
    goto Cleanup;
  }

  // 6. Validaity
  Status = X509GetValidity (Cert, CertSize, EndCertFrom, &EndCertFromLen, EndCertTo, &EndCertToLen);
  if (!Status) {
    goto Cleanup;
  }

  Status = InternalSpdmX509DateTimeCheck(EndCertFrom, EndCertFromLen, EndCertTo, EndCertToLen);
  if (!Status) {
    goto Cleanup;
  }

  // 7. SubjectPublic KeyInfo
  Status = RsaGetPublicKeyFromX509(Cert, CertSize, &RsaContext);
  if (!Status) {
    Status = EcGetPublicKeyFromX509(Cert, CertSize, &EcContext);
  }
  if (!Status) {
    goto Cleanup;
  }

  // 8. Extended Key Usage
  Value = 0;
  Ret = X509GetExtendedKeyUsage (Cert, CertSize, NULL, &Value);
  if (Ret != RETURN_BUFFER_TOO_SMALL || Value == 0) {
    goto Cleanup;
  }

  // 9. Key Usage
  Status = X509GetKeyUsage (Cert, CertSize, &Value);
  if (!Status) {
    goto Cleanup;
  }
  if (CRYPTO_X509_KU_DIGITAL_SIGNATURE & Value) {
    Status = TRUE;
  } else {
    Status = FALSE;
  }

Cleanup:
  if (RsaContext != NULL) {
    RsaFree(RsaContext);
  }
  if (EcContext != NULL) {
    EcFree(EcContext);
  }
  return Status;
}

STATIC CONST UINT8 OID_subjectAltName[] = {
  0x55, 0x1D, 0x11
};

RETURN_STATUS
EFIAPI
SpdmGetDMTFSubjectAltNameFromBytes (
  IN      CONST UINT8   *Buffer,
  IN      INTN          Len,
  OUT     CHAR8         *NameBuffer,  OPTIONAL
  IN OUT  UINTN         *NameBufferSize,
  OUT     UINT8         *Oid,         OPTIONAL
  IN OUT  UINTN         *OidSize
)
{
  UINT8       *Ptr;
  int         Length;
  UINTN       ObjLen;
  int         Ret;

  Length = (int)Len;
  Ptr = (UINT8 *)Buffer;
  ObjLen = 0;

  // Sequence
  Ret = Asn1GetTag (
    &Ptr, Ptr + Length, &ObjLen,
    CRYPTO_ASN1_SEQUENCE | CRYPTO_ASN1_CONSTRUCTED);
  if (!Ret) {
    return RETURN_NOT_FOUND;
  }

  Ret = Asn1GetTag (
    &Ptr, Ptr + ObjLen, &ObjLen,
    CRYPTO_ASN1_CONTEXT_SPECIFIC | CRYPTO_ASN1_CONSTRUCTED);

  Ret = Asn1GetTag (&Ptr, Ptr + ObjLen, &ObjLen, CRYPTO_ASN1_OID);
  if (!Ret) {
    return RETURN_NOT_FOUND;
  }
  // CopyData to OID
  if (*OidSize < (UINTN)ObjLen) {
    *OidSize = (UINTN)ObjLen;
    return RETURN_BUFFER_TOO_SMALL;

  }
  if (Oid != NULL) {
    CopyMem (Oid, Ptr, ObjLen);
    *OidSize = ObjLen;
  }

  // Move to next element
  Ptr += ObjLen;

  Ret = Asn1GetTag (
    &Ptr, (UINT8 *)(Buffer + Length),
    &ObjLen,
    CRYPTO_ASN1_CONTEXT_SPECIFIC | CRYPTO_ASN1_CONSTRUCTED
    );
  Ret = Asn1GetTag (
    &Ptr, (UINT8 *)(Buffer + Length),
    &ObjLen,
    CRYPTO_ASN1_UTF8_STRING);
  if (!Ret) {
    return RETURN_NOT_FOUND;
  }

  if (*NameBufferSize < (UINTN)ObjLen + 1) {
    *NameBufferSize = (UINTN)ObjLen + 1;
    return RETURN_BUFFER_TOO_SMALL;
  }

  if (NameBuffer != NULL) {
    CopyMem (NameBuffer, Ptr, ObjLen);
    *NameBufferSize = ObjLen + 1;
    NameBuffer[ObjLen] = 0;
  }
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmGetDMTFSubjectAltName (
  IN      CONST UINT8   *Cert,
  IN      INTN          CertSize,
  OUT     CHAR8         *NameBuffer,  OPTIONAL
  IN OUT  UINTN         *NameBufferSize,
  OUT     UINT8         *Oid,         OPTIONAL
  IN OUT  UINTN         *OidSize
  )
{
  RETURN_STATUS ReturnStatus;
  UINTN ExtensionDataSize;
  ExtensionDataSize = 0;
  ReturnStatus = X509GetExtensionData(Cert, CertSize, (UINT8 *)OID_subjectAltName, sizeof (OID_subjectAltName), NULL, &ExtensionDataSize);
  if (ReturnStatus != RETURN_BUFFER_TOO_SMALL) {
    return RETURN_NOT_FOUND;
  }
  if (ExtensionDataSize > *NameBufferSize) {
    *NameBufferSize = ExtensionDataSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  ReturnStatus = X509GetExtensionData(Cert, CertSize, (UINT8 *)OID_subjectAltName, sizeof (OID_subjectAltName), (UINT8 *)NameBuffer, NameBufferSize);
  if (RETURN_ERROR(ReturnStatus)) {
    return ReturnStatus;
  }

  return SpdmGetDMTFSubjectAltNameFromBytes((CONST UINT8 *)NameBuffer, *NameBufferSize, NameBuffer, NameBufferSize, Oid, OidSize);
}
