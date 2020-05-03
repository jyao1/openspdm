/** @file
  EDKII Device Security library for SPDM device.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

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
  return 0xFFFFFFFF;
}

HASH_ALL
GetSpdmHashFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    return Sha256HashAll;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
    return Sha384HashAll;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
    return Sha512HashAll;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
    ASSERT (FALSE);
    break;
  }
  return NULL;
}

HASH_ALL
GetSpdmMeasurementHashFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo) {
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
    return Sha256HashAll;
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
    return Sha384HashAll;
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
    return Sha512HashAll;
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256:
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384:
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512:
    ASSERT (FALSE);
    break;
  }
  return NULL;
}

HMAC_ALL
GetSpdmHmacFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    return HmacSha256All;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
    ASSERT (FALSE);
    break;
  }
  return NULL;
}

HKDF_EXPAND
GetSpdmHkdfExpandFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    return HkdfSha256Expand;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
    ASSERT (FALSE);
    break;
  }
  return NULL;
}

/**
  This function returns the SPDM hash size.

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
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    return 256;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    return 384;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
    return 512;
  }
  return 0xFFFFFFFF;
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
  return 0xFFFFFFFF;
}

/**
  This function returns the SPDM DHEKey size.

  @param[in]  SpdmContext             The SPDM context for the device.
  
  @return TCG SPDM DHEKey size
**/
UINT32
GetSpdmDHEKeySize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE2048:
    return 256;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE3072:
    return 384;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE4096:
    return 512;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP256R1:
    return 32 * 2;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP384R1:
    return 48 * 2;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP521R1:
    return 66 * 2;
  }
  return 0xFFFFFFFF;
}

UINTN
GetSpdmDHENid (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE2048:
    return CRYPTO_NID_FFDHE2048;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE3072:
    return CRYPTO_NID_FFDHE3072;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE4096:
    return CRYPTO_NID_FFDHE4096;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP256R1:
    return CRYPTO_NID_SECP256R1;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP384R1:
    return CRYPTO_NID_SECP384R1;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP521R1:
    return CRYPTO_NID_SECP521R1;
  }
  return 0xFFFFFFFF;
}

BOOLEAN
IsSpdmECDHE (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE2048:
    return FALSE;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE3072:
    return FALSE;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE4096:
    return FALSE;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP256R1:
    return TRUE;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP384R1:
    return TRUE;
  case SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP521R1:
    return TRUE;
  }
  return FALSE;
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
  return 0xFFFFFFFF;
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
  return 0xFFFFFFFF;
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
  return 0xFFFFFFFF;
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
  return 0xFFFFFFFF;
}

AEAD_ENCRYPT
GetSpdmAeadEncFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
    return AeadAesGcmEncrypt;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
    return AeadAesGcmEncrypt;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
    return AeadChaCha20Poly1305Encrypt;
  }
  return NULL;
}

AEAD_DECRYPT
GetSpdmAeadDecFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
    return AeadAesGcmDecrypt;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
    return AeadAesGcmDecrypt;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
    return AeadChaCha20Poly1305Decrypt;
  }
  return NULL;
}

VOID
GenerateDHESelfKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINTN                        SelfKeySize,
  OUT VOID                        *SelfPubKey,
  OUT VOID                        **Context
  )
{
  UINTN   Nid;
  BOOLEAN Result;
  BOOLEAN IsEcDhe;
  UINTN   OutKeySize;

  IsEcDhe = FALSE;
  Nid = GetSpdmDHENid (SpdmContext);
  IsEcDhe = IsSpdmECDHE (SpdmContext);

  if (!IsEcDhe) {
    *Context = DhNewByNid (Nid);
    ASSERT (*Context != NULL);

    OutKeySize = SelfKeySize;
    Result = DhGenerateKey (*Context, SelfPubKey, &OutKeySize);
    ASSERT (Result);
    ASSERT (OutKeySize == SelfKeySize);
  } else {
    *Context = EcNewByNid (Nid);
    ASSERT (*Context != NULL);

    Result = EcGenerateKey (*Context);
    ASSERT (Result);

    OutKeySize = SelfKeySize;
    Result = EcGetPublicKey (*Context, SelfPubKey, &OutKeySize);
    ASSERT (Result);
    ASSERT (OutKeySize == SelfKeySize);
  }
}

VOID
ComputeDHEFinalKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *Context,
  IN UINTN                        PeerKeySize,
  IN VOID                         *PeerPubKey,
  IN OUT UINTN                    *FinalKeySize,
  OUT VOID                        *FinalKey
  )
{
  BOOLEAN Result;
  BOOLEAN IsEcDhe;
  
  IsEcDhe = IsSpdmECDHE (SpdmContext);

  if (!IsEcDhe) {
    Result = DhComputeKey (Context, PeerPubKey, PeerKeySize, FinalKey, FinalKeySize);
    ASSERT (Result);

    DhFree (Context);
  } else {
    Result = EcComputeKey (Context, PeerPubKey, PeerKeySize, FinalKey, FinalKeySize);
    ASSERT (Result);

    EcFree (Context);
  }
}

VOID
GetRandomNumber (
  IN  UINTN                     Size,
  OUT UINT8                     *Rand
  )
{
  RandomBytes (Rand, Size);
  
  return ;
}