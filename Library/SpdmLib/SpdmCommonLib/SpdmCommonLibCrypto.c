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
    return EcDsaFree;
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
    return EcDsaFree;
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
