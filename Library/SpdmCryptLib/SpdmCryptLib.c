/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmCryptLib.h>

/**
  This function returns the SPDM hash algorithm size.

  @param  BaseHashAlgo                  SPDM BaseHashAlgo

  @return SPDM hash algorithm size.
**/
UINT32
EFIAPI
GetSpdmHashSize (
  IN      UINT32       BaseHashAlgo
  )
{
  switch (BaseHashAlgo) {
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

/**
  Return cipher ID, based upon the negotiated Hash algorithm.

  @param  BaseHashAlgo                  SPDM BaseHashAlgo

  @return Hash cipher ID
**/
UINTN
GetSpdmHashNid (
  IN      UINT32       BaseHashAlgo
  )
{
  switch (BaseHashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    return CRYPTO_NID_SHA256;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
    return CRYPTO_NID_SHA384;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
    return CRYPTO_NID_SHA512;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256:
    return CRYPTO_NID_SHA3_256;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384:
    return CRYPTO_NID_SHA3_384;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512:
    return CRYPTO_NID_SHA3_512;
  }
  return CRYPTO_NID_NULL;
}

/**
  Return hash function, based upon the negotiated hash algorithm.

  @param  BaseHashAlgo                  SPDM BaseHashAlgo

  @return hash function
**/
HASH_ALL
GetSpdmHashFunc (
  IN      UINT32       BaseHashAlgo
  )
{
  switch (BaseHashAlgo) {
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

/**
  Computes the hash of a input data buffer, based upon the negotiated hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
BOOLEAN
EFIAPI
SpdmHashAll (
  IN   UINT32                       BaseHashAlgo,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  )
{
  HASH_ALL   HashFunction;
  HashFunction = GetSpdmHashFunc (BaseHashAlgo);
  if (HashFunction == NULL) {
    return FALSE;
  }
  return HashFunction (Data, DataSize, HashValue);
}

/**
  This function returns the SPDM measurement hash algorithm size.

  @param  MeasurementHashAlgo          SPDM MeasurementHashAlgo

  @return SPDM measurement hash algorithm size.
  @return 0xFFFFFFFF for RAW_BIT_STREAM_ONLY.
**/
UINT32
EFIAPI
GetSpdmMeasurementHashSize (
  IN   UINT32                       MeasurementHashAlgo
  )
{
  switch (MeasurementHashAlgo) {
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
    return 0xFFFFFFFF;
  }
  return 0;
}

/**
  Return hash function, based upon the negotiated measurement hash algorithm.

  @param  MeasurementHashAlgo          SPDM MeasurementHashAlgo

  @return hash function
**/
HASH_ALL
GetSpdmMeasurementHashFunc (
  IN   UINT32                       MeasurementHashAlgo
  )
{
  switch (MeasurementHashAlgo) {
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

/**
  Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  MeasurementHashAlgo          SPDM MeasurementHashAlgo
  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
BOOLEAN
EFIAPI
SpdmMeasurementHashAll (
  IN   UINT32                       MeasurementHashAlgo,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  )
{
  HASH_ALL   HashFunction;
  HashFunction = GetSpdmMeasurementHashFunc (MeasurementHashAlgo);
  if (HashFunction == NULL) {
    return FALSE;
  }
  return HashFunction (Data, DataSize, HashValue);
}

/**
  Return HMAC function, based upon the negotiated HMAC algorithm.

  @param  BaseHashAlgo                 SPDM BaseHashAlgo

  @return HMAC function
**/
HMAC_ALL
GetSpdmHmacFunc (
  IN   UINT32                       BaseHashAlgo
  )
{
  switch (BaseHashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if OPENSPDM_SHA256_SUPPORT == 1
    return HmacSha256All;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if OPENSPDM_SHA384_SUPPORT == 1
    return HmacSha384All;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if OPENSPDM_SHA512_SUPPORT == 1
    return HmacSha512All;
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

/**
  Computes the HMAC of a input data buffer, based upon the negotiated HMAC algorithm.

  This function performs the HMAC of a given data buffer, and return the hash value.

  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Data                         Pointer to the buffer containing the data to be HMACed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  Key                          Pointer to the user-supplied key.
  @param  KeySize                      Key size in bytes.
  @param  HashValue                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
BOOLEAN
EFIAPI
SpdmHmacAll (
  IN   UINT32                       BaseHashAlgo,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  IN   CONST UINT8                  *Key,
  IN   UINTN                        KeySize,
  OUT  UINT8                        *HmacValue
  )
{
  HMAC_ALL   HmacFunction;
  HmacFunction = GetSpdmHmacFunc (BaseHashAlgo);
  if (HmacFunction == NULL) {
    return FALSE;
  }
  return HmacFunction (Data, DataSize, Key, KeySize, HmacValue);
}

/**
  Return HKDF expand function, based upon the negotiated HKDF algorithm.

  @param  BaseHashAlgo                 SPDM BaseHashAlgo

  @return HKDF expand function
**/
HKDF_EXPAND
GetSpdmHkdfExpandFunc (
  IN   UINT32                       BaseHashAlgo
  )
{
  switch (BaseHashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
#if OPENSPDM_SHA256_SUPPORT == 1
    return HkdfSha256Expand;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
#if OPENSPDM_SHA384_SUPPORT == 1
    return HkdfSha384Expand;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
#if OPENSPDM_SHA512_SUPPORT == 1
    return HkdfSha512Expand;
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

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Prk                          Pointer to the user-supplied key.
  @param  PrkSize                      Key size in bytes.
  @param  Info                         Pointer to the application specific info.
  @param  InfoSize                     Info size in bytes.
  @param  Out                          Pointer to buffer to receive hkdf value.
  @param  OutSize                      Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
BOOLEAN
EFIAPI
SpdmHkdfExpand (
  IN   UINT32                       BaseHashAlgo,
  IN   CONST UINT8                  *Prk,
  IN   UINTN                        PrkSize,
  IN   CONST UINT8                  *Info,
  IN   UINTN                        InfoSize,
  OUT  UINT8                        *Out,
  IN   UINTN                        OutSize
  )
{
  HKDF_EXPAND   HkdfExpandFunction;
  HkdfExpandFunction = GetSpdmHkdfExpandFunc (BaseHashAlgo);
  if (HkdfExpandFunction == NULL) {
    return FALSE;
  }
  return HkdfExpandFunction (Prk, PrkSize, Info, InfoSize, Out, OutSize);
}

/**
  This function returns the SPDM asymmetric algorithm size.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo

  @return SPDM asymmetric algorithm size.
**/
UINT32
EFIAPI
GetSpdmAsymSignatureSize (
  IN   UINT32                       BaseAsymAlgo
  )
{
  switch (BaseAsymAlgo) {
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
  Return asymmetric GET_PUBLIC_KEY_FROM_X509 function, based upon the negotiated asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo

  @return asymmetric GET_PUBLIC_KEY_FROM_X509 function
**/
ASYM_GET_PUBLIC_KEY_FROM_X509
GetSpdmAsymGetPublicKeyFromX509 (
  IN   UINT32                       BaseAsymAlgo
  )
{
  switch (BaseAsymAlgo) {
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

/**
  Retrieve the asymmetric Public Key from one DER-encoded X509 certificate,
  based upon negotiated asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo
  @param  Cert                         Pointer to the DER-encoded X509 certificate.
  @param  CertSize                     Size of the X509 certificate in bytes.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
BOOLEAN
EFIAPI
SpdmAsymGetPublicKeyFromX509 (
  IN   UINT32                       BaseAsymAlgo,
  IN   CONST UINT8                  *Cert,
  IN   UINTN                        CertSize,
  OUT  VOID                         **Context
  )
{
  ASYM_GET_PUBLIC_KEY_FROM_X509   GetPublicKeyFromX509Function;
  GetPublicKeyFromX509Function = GetSpdmAsymGetPublicKeyFromX509 (BaseAsymAlgo);
  if (GetPublicKeyFromX509Function == NULL) {
    return FALSE;
  }
  return GetPublicKeyFromX509Function (Cert, CertSize, Context);
}

/**
  Return asymmetric free function, based upon the negotiated asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo

  @return asymmetric free function
**/
ASYM_FREE
GetSpdmAsymFree (
  IN   UINT32                       BaseAsymAlgo
  )
{
  switch (BaseAsymAlgo) {
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

/**
  Release the specified asymmetric context,
  based upon negotiated asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo
  @param  Context                      Pointer to the asymmetric context to be released.
**/
VOID
EFIAPI
SpdmAsymFree (
  IN   UINT32                       BaseAsymAlgo,
  IN   VOID                         *Context
  )
{
  ASYM_FREE   FreeFunction;
  FreeFunction = GetSpdmAsymFree (BaseAsymAlgo);
  if (FreeFunction == NULL) {
    return ;
  }
  FreeFunction (Context);
}

/**
  Return if asymmetric function need message hash.

  @param  BaseAsymAlgo               SPDM BaseAsymAlgo

  @retval TRUE  asymmetric function need message hash
  @retval FALSE asymmetric function need raw message
**/
BOOLEAN
SpdmAsymFuncNeedHash (
  IN   UINT32                       BaseAsymAlgo
  )
{
  switch (BaseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
    return TRUE;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
    return TRUE;
  }
  ASSERT (FALSE);
  return FALSE;
}

/**
  Return asymmetric verify function, based upon the negotiated asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo

  @return asymmetric verify function
**/
ASYM_VERIFY
GetSpdmAsymVerify (
  IN   UINT32                       BaseAsymAlgo
  )
{
  switch (BaseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if OPENSPDM_RSA_SSA_SUPPORT == 1
    return RsaPkcs1VerifyWithNid;
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

/**
  Verifies the asymmetric signature,
  based upon negotiated asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo
  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Context                      Pointer to asymmetric context for signature verification.
  @param  Message                      Pointer to octet message to be checked (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to asymmetric signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
BOOLEAN
EFIAPI
SpdmAsymVerify (
  IN   UINT32                       BaseAsymAlgo,
  IN   UINT32                       BaseHashAlgo,
  IN   VOID                         *Context,
  IN   CONST UINT8                  *Message,
  IN   UINTN                        MessageSize,
  IN   CONST UINT8                  *Signature,
  IN   UINTN                        SigSize
  )
{
  ASYM_VERIFY   VerifyFunction;
  BOOLEAN       NeedHash;
  UINT8         MessageHash[MAX_HASH_SIZE];
  UINTN         HashSize;
  BOOLEAN       Result;
  UINTN         HashNid;

  HashNid = GetSpdmHashNid (BaseHashAlgo);
  NeedHash = SpdmAsymFuncNeedHash (BaseAsymAlgo);

  VerifyFunction = GetSpdmAsymVerify (BaseAsymAlgo);
  if (VerifyFunction == NULL) {
    return FALSE;
  }
  if (NeedHash) {
    HashSize = GetSpdmHashSize (BaseHashAlgo);
    Result = SpdmHashAll (BaseHashAlgo, Message, MessageSize, MessageHash);
    if (!Result) {
      return FALSE;
    }
    return VerifyFunction (Context, HashNid, MessageHash, HashSize, Signature, SigSize);
  } else {
    return VerifyFunction (Context, HashNid, Message, MessageSize, Signature, SigSize);
  }
}

/**
  Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo

  @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
**/
ASYM_GET_PRIVATE_KEY_FROM_PEM
GetSpdmAsymGetPrivateKeyFromPem (
  IN   UINT32                       BaseAsymAlgo
  )
{
  switch (BaseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if (OPENSPDM_RSA_SSA_SUPPORT == 1) || (OPENSPDM_RSA_PSS_SUPPORT == 1)
    return RsaGetPrivateKeyFromPem;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
    return EcGetPrivateKeyFromPem;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

/**
  Retrieve the Private Key from the password-protected PEM key data.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo
  @param  PemData                      Pointer to the PEM-encoded key data to be retrieved.
  @param  PemSize                      Size of the PEM key data in bytes.
  @param  Password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
BOOLEAN
EFIAPI
SpdmAsymGetPrivateKeyFromPem (
  IN   UINT32                       BaseAsymAlgo,
  IN   CONST UINT8                  *PemData,
  IN   UINTN                        PemSize,
  IN   CONST CHAR8                  *Password,
  OUT  VOID                         **Context
  )
{
  ASYM_GET_PRIVATE_KEY_FROM_PEM   AsymGetPrivateKeyFromPem;
  AsymGetPrivateKeyFromPem = GetSpdmAsymGetPrivateKeyFromPem (BaseAsymAlgo);
  if (AsymGetPrivateKeyFromPem == NULL) {
    return FALSE;
  }
  return AsymGetPrivateKeyFromPem (PemData, PemSize, Password, Context);
}

/**
  Return asymmetric sign function, based upon the asymmetric algorithm.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo

  @return asymmetric sign function
**/
ASYM_SIGN
GetSpdmAsymSign (
  IN   UINT32                       BaseAsymAlgo
  )
{
  switch (BaseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
#if OPENSPDM_RSA_SSA_SUPPORT == 1
    return RsaPkcs1SignWithNid;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
#if OPENSPDM_RSA_PSS_SUPPORT == 1
    return RsaPssSign;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
#if OPENSPDM_ECDSA_SUPPORT == 1
    return EcDsaSign;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  @param  BaseAsymAlgo                 SPDM BaseAsymAlgo
  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Context                      Pointer to asymmetric context for signature generation.
  @param  Message                      Pointer to octet message to be signed (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to buffer to receive signature.
  @param  SigSize                      On input, the size of Signature buffer in bytes.
                                       On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
BOOLEAN
EFIAPI
SpdmAsymSign (
  IN      UINT32                       BaseAsymAlgo,
  IN      UINT32                       BaseHashAlgo,
  IN      VOID                         *Context,
  IN      CONST UINT8                  *Message,
  IN      UINTN                        MessageSize,
  OUT     UINT8                        *Signature,
  IN OUT  UINTN                        *SigSize
  )
{
  ASYM_SIGN     AsymSign;
  BOOLEAN       NeedHash;
  UINT8         MessageHash[MAX_HASH_SIZE];
  UINTN         HashSize;
  BOOLEAN       Result;
  UINTN         HashNid;

  HashNid = GetSpdmHashNid (BaseHashAlgo);
  NeedHash = SpdmAsymFuncNeedHash (BaseAsymAlgo);

  AsymSign = GetSpdmAsymSign (BaseAsymAlgo);
  if (AsymSign == NULL) {
    return FALSE;
  }
  if (NeedHash) {
    HashSize = GetSpdmHashSize (BaseHashAlgo);
    Result = SpdmHashAll (BaseHashAlgo, Message, MessageSize, MessageHash);
    if (!Result) {
      return FALSE;
    }
    return AsymSign (Context, HashNid, MessageHash, HashSize, Signature, SigSize);
  } else {
    return AsymSign (Context, HashNid, Message, MessageSize, Signature, SigSize);
  }
}

/**
  This function returns the SPDM requester asymmetric algorithm size.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg

  @return SPDM requester asymmetric algorithm size.
**/
UINT32
EFIAPI
GetSpdmReqAsymSignatureSize (
  IN   UINT16                       ReqBaseAsymAlg
  )
{
  return GetSpdmAsymSignatureSize (ReqBaseAsymAlg);
}

/**
  Return requester asymmetric GET_PUBLIC_KEY_FROM_X509 function, based upon the negotiated requester asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg

  @return requester asymmetric GET_PUBLIC_KEY_FROM_X509 function
**/
ASYM_GET_PUBLIC_KEY_FROM_X509
GetSpdmReqAsymGetPublicKeyFromX509 (
  IN   UINT16                       ReqBaseAsymAlg
  )
{
  return GetSpdmAsymGetPublicKeyFromX509 (ReqBaseAsymAlg);
}

/**
  Retrieve the asymmetric Public Key from one DER-encoded X509 certificate,
  based upon negotiated requester asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg
  @param  Cert                         Pointer to the DER-encoded X509 certificate.
  @param  CertSize                     Size of the X509 certificate in bytes.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
BOOLEAN
EFIAPI
SpdmReqAsymGetPublicKeyFromX509 (
  IN   UINT16                       ReqBaseAsymAlg,
  IN   CONST UINT8                  *Cert,
  IN   UINTN                        CertSize,
  OUT  VOID                         **Context
  )
{
  ASYM_GET_PUBLIC_KEY_FROM_X509   GetPublicKeyFromX509Function;
  GetPublicKeyFromX509Function = GetSpdmReqAsymGetPublicKeyFromX509 (ReqBaseAsymAlg);
  if (GetPublicKeyFromX509Function == NULL) {
    return FALSE;
  }
  return GetPublicKeyFromX509Function (Cert, CertSize, Context);
}

/**
  Return requester asymmetric free function, based upon the negotiated requester asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg

  @return requester asymmetric free function
**/
ASYM_FREE
GetSpdmReqAsymFree (
  IN   UINT16                       ReqBaseAsymAlg
  )
{
  return GetSpdmAsymFree (ReqBaseAsymAlg);
}

/**
  Release the specified asymmetric context,
  based upon negotiated requester asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg
  @param  Context                      Pointer to the asymmetric context to be released.
**/
VOID
EFIAPI
SpdmReqAsymFree (
  IN   UINT16                       ReqBaseAsymAlg,
  IN   VOID                         *Context
  )
{
  ASYM_FREE   FreeFunction;
  FreeFunction = GetSpdmReqAsymFree (ReqBaseAsymAlg);
  if (FreeFunction == NULL) {
    return ;
  }
  FreeFunction (Context);
}

/**
  Return if requester asymmetric function need message hash.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg

  @retval TRUE  requester asymmetric function need message hash
  @retval FALSE requester asymmetric function need raw message
**/
BOOLEAN
SpdmReqAsymFuncNeedHash (
  IN   UINT16                       ReqBaseAsymAlg
  )
{
  return SpdmAsymFuncNeedHash (ReqBaseAsymAlg);
}

/**
  Return requester asymmetric verify function, based upon the negotiated requester asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg

  @return requester asymmetric verify function
**/
ASYM_VERIFY
GetSpdmReqAsymVerify (
  IN   UINT16                       ReqBaseAsymAlg
  )
{
  return GetSpdmAsymVerify (ReqBaseAsymAlg);
}

/**
  Verifies the asymmetric signature,
  based upon negotiated requester asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg
  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Context                      Pointer to asymmetric context for signature verification.
  @param  Message                      Pointer to octet message to be checked (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to asymmetric signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
BOOLEAN
EFIAPI
SpdmReqAsymVerify (
  IN   UINT16                       ReqBaseAsymAlg,
  IN   UINT32                       BaseHashAlgo,
  IN   VOID                         *Context,
  IN   CONST UINT8                  *Message,
  IN   UINTN                        MessageSize,
  IN   CONST UINT8                  *Signature,
  IN   UINTN                        SigSize
  )
{
  ASYM_VERIFY   VerifyFunction;
  BOOLEAN       NeedHash;
  UINT8         MessageHash[MAX_HASH_SIZE];
  UINTN         HashSize;
  BOOLEAN       Result;
  UINTN         HashNid;

  HashNid = GetSpdmHashNid (BaseHashAlgo);
  NeedHash = SpdmReqAsymFuncNeedHash (ReqBaseAsymAlg);

  VerifyFunction = GetSpdmReqAsymVerify (ReqBaseAsymAlg);
  if (VerifyFunction == NULL) {
    return FALSE;
  }
  if (NeedHash) {
    HashSize = GetSpdmHashSize (BaseHashAlgo);
    Result = SpdmHashAll (BaseHashAlgo, Message, MessageSize, MessageHash);
    if (!Result) {
      return FALSE;
    }
    return VerifyFunction (Context, HashNid, MessageHash, HashSize, Signature, SigSize);
  } else {
    return VerifyFunction (Context, HashNid, Message, MessageSize, Signature, SigSize);
  }
}

/**
  Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg

  @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
**/
ASYM_GET_PRIVATE_KEY_FROM_PEM
GetSpdmReqAsymGetPrivateKeyFromPem (
  IN   UINT16                       ReqBaseAsymAlg
  )
{
  return GetSpdmAsymGetPrivateKeyFromPem (ReqBaseAsymAlg);
}

/**
  Retrieve the Private Key from the password-protected PEM key data.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg
  @param  PemData                      Pointer to the PEM-encoded key data to be retrieved.
  @param  PemSize                      Size of the PEM key data in bytes.
  @param  Password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
BOOLEAN
EFIAPI
SpdmReqAsymGetPrivateKeyFromPem (
  IN   UINT16                       ReqBaseAsymAlg,
  IN   CONST UINT8                  *PemData,
  IN   UINTN                        PemSize,
  IN   CONST CHAR8                  *Password,
  OUT  VOID                         **Context
  )
{
  ASYM_GET_PRIVATE_KEY_FROM_PEM   AsymGetPrivateKeyFromPem;
  AsymGetPrivateKeyFromPem = GetSpdmReqAsymGetPrivateKeyFromPem (ReqBaseAsymAlg);
  if (AsymGetPrivateKeyFromPem == NULL) {
    return FALSE;
  }
  return AsymGetPrivateKeyFromPem (PemData, PemSize, Password, Context);
}

/**
  Return asymmetric sign function, based upon the asymmetric algorithm.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg

  @return asymmetric sign function
**/
ASYM_SIGN
GetSpdmReqAsymSign (
  IN   UINT16                       ReqBaseAsymAlg
  )
{
  return GetSpdmAsymSign (ReqBaseAsymAlg);
}

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  @param  ReqBaseAsymAlg               SPDM ReqBaseAsymAlg
  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  Context                      Pointer to asymmetric context for signature generation.
  @param  Message                      Pointer to octet message to be signed (before hash).
  @param  MessageSize                  Size of the message in bytes.
  @param  Signature                    Pointer to buffer to receive signature.
  @param  SigSize                      On input, the size of Signature buffer in bytes.
                                       On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
BOOLEAN
EFIAPI
SpdmReqAsymSign (
  IN      UINT16                       ReqBaseAsymAlg,
  IN      UINT32                       BaseHashAlgo,
  IN      VOID                         *Context,
  IN      CONST UINT8                  *Message,
  IN      UINTN                        MessageSize,
  OUT     UINT8                        *Signature,
  IN OUT  UINTN                        *SigSize
  )
{
  ASYM_SIGN     AsymSign;
  BOOLEAN       NeedHash;
  UINT8         MessageHash[MAX_HASH_SIZE];
  UINTN         HashSize;
  BOOLEAN       Result;
  UINTN         HashNid;

  HashNid = GetSpdmHashNid (BaseHashAlgo);
  NeedHash = SpdmReqAsymFuncNeedHash (ReqBaseAsymAlg);

  AsymSign = GetSpdmReqAsymSign (ReqBaseAsymAlg);
  if (AsymSign == NULL) {
    return FALSE;
  }
  if (NeedHash) {
    HashSize = GetSpdmHashSize (BaseHashAlgo);
    Result = SpdmHashAll (BaseHashAlgo, Message, MessageSize, MessageHash);
    if (!Result) {
      return FALSE;
    }
    return AsymSign (Context, HashNid, MessageHash, HashSize, Signature, SigSize);
  } else {
    return AsymSign (Context, HashNid, Message, MessageSize, Signature, SigSize);
  }
}

/**
  This function returns the SPDM DHE algorithm key size.

  @param  DHENamedGroup                SPDM DHENamedGroup

  @return SPDM DHE algorithm key size.
**/
UINT32
EFIAPI
GetSpdmDhePubKeySize (
  IN   UINT16                       DHENamedGroup
  )
{
  switch (DHENamedGroup) {
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

/**
  Return cipher ID, based upon the negotiated DHE algorithm.

  @param  DHENamedGroup                SPDM DHENamedGroup

  @return DHE cipher ID
**/
UINTN
GetSpdmDheNid (
  IN   UINT16                       DHENamedGroup
  )
{
  switch (DHENamedGroup) {
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
  return CRYPTO_NID_NULL;
}

/**
  Return DHE new by NID function, based upon the negotiated DHE algorithm.

  @param  DHENamedGroup                SPDM DHENamedGroup

  @return DHE new by NID function
**/
DHE_NEW_BY_NID
GetSpdmDheNew (
  IN   UINT16                       DHENamedGroup
  )
{
  switch (DHENamedGroup) {
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_FFDHE_SUPPORT == 1
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

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) Context for subsequent use,
  based upon negotiated DHE algorithm.
  
  @param  DHENamedGroup                SPDM DHENamedGroup

  @return  Pointer to the Diffie-Hellman Context that has been initialized.
**/
VOID *
EFIAPI
SpdmDheNew (
  IN   UINT16                       DHENamedGroup
  )
{
  DHE_NEW_BY_NID   NewFunction;
  UINTN            Nid;

  NewFunction = GetSpdmDheNew (DHENamedGroup);
  if (NewFunction == NULL) {
    return NULL;
  }
  Nid = GetSpdmDheNid (DHENamedGroup);
  if (Nid == 0) {
    return NULL;
  }
  return NewFunction (Nid);
}

/**
  Return DHE free function, based upon the negotiated DHE algorithm.

  @param  DHENamedGroup                SPDM DHENamedGroup

  @return DHE free function
**/
DHE_FREE
GetSpdmDheFree (
  IN   UINT16                       DHENamedGroup
  )
{
  switch (DHENamedGroup) {
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_FFDHE_SUPPORT == 1
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

/**
  Release the specified DHE context,
  based upon negotiated DHE algorithm.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  Context                      Pointer to the DHE context to be released.
**/
VOID
EFIAPI
SpdmDheFree (
  IN   UINT16                       DHENamedGroup,
  IN   VOID                         *Context
  )
{
  DHE_FREE   FreeFunction;
  FreeFunction = GetSpdmDheFree (DHENamedGroup);
  if (FreeFunction == NULL) {
    return ;
  }
  FreeFunction (Context);
}

/**
  Return DHE generate key function, based upon the negotiated DHE algorithm.

  @param  DHENamedGroup                SPDM DHENamedGroup

  @return DHE generate key function
**/
DHE_GENERATE_KEY
GetSpdmDheGenerateKey (
  IN   UINT16                       DHENamedGroup
  )
{
  switch (DHENamedGroup) {
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_FFDHE_SUPPORT == 1
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

/**
  Generates DHE public key,
  based upon negotiated DHE algorithm.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter PublicKey and PublicKeySize. DH context is updated accordingly.
  If the PublicKey buffer is too small to hold the public key, FALSE is returned and
  PublicKeySize is set to the required buffer size to obtain the public key.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  Context                      Pointer to the DHE context.
  @param  PublicKey                    Pointer to the buffer to receive generated public key.
  @param  PublicKeySize                On input, the size of PublicKey buffer in bytes.
                                       On output, the size of data returned in PublicKey buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  PublicKeySize is not large enough.
**/
BOOLEAN
EFIAPI
SpdmDheGenerateKey (
  IN      UINT16                       DHENamedGroup,
  IN OUT  VOID                         *Context,
  OUT     UINT8                        *PublicKey,
  IN OUT  UINTN                        *PublicKeySize
  )
{
  DHE_GENERATE_KEY   GenerateKeyFunction;
  GenerateKeyFunction = GetSpdmDheGenerateKey (DHENamedGroup);
  if (GenerateKeyFunction == NULL) {
    return FALSE;
  }
  return GenerateKeyFunction (Context, PublicKey, PublicKeySize);
}

/**
  Return DHE compute key function, based upon the negotiated DHE algorithm.

  @param  DHENamedGroup                SPDM DHENamedGroup

  @return DHE compute key function
**/
DHE_COMPUTE_KEY
GetSpdmDheComputeKey (
  IN      UINT16                       DHENamedGroup
  )
{
  switch (DHENamedGroup) {
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072:
  case SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096:
#if OPENSPDM_FFDHE_SUPPORT == 1
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

/**
  Computes exchanged common key,
  based upon negotiated DHE algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  Context                      Pointer to the DHE context.
  @param  PeerPublicKey                Pointer to the peer's public key.
  @param  PeerPublicKeySize            Size of peer's public key in bytes.
  @param  Key                          Pointer to the buffer to receive generated key.
  @param  KeySize                      On input, the size of Key buffer in bytes.
                                       On output, the size of data returned in Key buffer in bytes.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  KeySize is not large enough.
**/
BOOLEAN
EFIAPI
SpdmDheComputeKey (
  IN      UINT16                       DHENamedGroup,
  IN OUT  VOID                         *Context,
  IN      CONST UINT8                  *PeerPublic,
  IN      UINTN                        PeerPublicSize,
  OUT     UINT8                        *Key,
  IN OUT  UINTN                        *KeySize
  )
{
  DHE_COMPUTE_KEY   ComputeKeyFunction;
  ComputeKeyFunction = GetSpdmDheComputeKey (DHENamedGroup);
  if (ComputeKeyFunction == NULL) {
    return FALSE;
  }
  return ComputeKeyFunction (Context, PeerPublic, PeerPublicSize, Key, KeySize);
}

/**
  This function returns the SPDM AEAD algorithm key size.

  @param  AEADCipherSuite              SPDM AEADCipherSuite

  @return SPDM AEAD algorithm key size.
**/
UINT32
EFIAPI
GetSpdmAeadKeySize (
  IN   UINT16                       AEADCipherSuite
  )
{
  switch (AEADCipherSuite) {
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
  This function returns the SPDM AEAD algorithm iv size.

  @param  AEADCipherSuite              SPDM AEADCipherSuite

  @return SPDM AEAD algorithm iv size.
**/
UINT32
EFIAPI
GetSpdmAeadIvSize (
  IN   UINT16                       AEADCipherSuite
  )
{
  switch (AEADCipherSuite) {
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
  This function returns the SPDM AEAD algorithm tag size.

  @param  AEADCipherSuite              SPDM AEADCipherSuite

  @return SPDM AEAD algorithm tag size.
**/
UINT32
EFIAPI
GetSpdmAeadTagSize (
  IN   UINT16                       AEADCipherSuite
  )
{
  switch (AEADCipherSuite) {
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
  This function returns the SPDM AEAD algorithm block size.

  @param  AEADCipherSuite              SPDM AEADCipherSuite

  @return SPDM AEAD algorithm block size.
**/
UINT32
EFIAPI
GetSpdmAeadBlockSize (
  IN   UINT16                       AEADCipherSuite
  )
{
  switch (AEADCipherSuite) {
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
  Return AEAD encryption function, based upon the negotiated AEAD algorithm.

  @param  AEADCipherSuite              SPDM AEADCipherSuite

  @return AEAD encryption function
**/
AEAD_ENCRYPT
GetSpdmAeadEncFunc (
  IN   UINT16                       AEADCipherSuite
  )
{
  switch (AEADCipherSuite) {
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

/**
  Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  AEADCipherSuite              SPDM AEADCipherSuite
  @param  Key                          Pointer to the encryption key.
  @param  KeySize                      Size of the encryption key in bytes.
  @param  Iv                           Pointer to the IV value.
  @param  IvSize                       Size of the IV value in bytes.
  @param  AData                        Pointer to the additional authenticated data (AAD).
  @param  ADataSize                    Size of the additional authenticated data (AAD) in bytes.
  @param  DataIn                       Pointer to the input data buffer to be encrypted.
  @param  DataInSize                   Size of the input data buffer in bytes.
  @param  TagOut                       Pointer to a buffer that receives the authentication tag output.
  @param  TagSize                      Size of the authentication tag in bytes.
  @param  DataOut                      Pointer to a buffer that receives the encryption output.
  @param  DataOutSize                  Size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated encryption succeeded.
  @retval FALSE  AEAD authenticated encryption failed.
**/
BOOLEAN
EFIAPI
SpdmAeadEncryption (
  IN   UINT16                       AEADCipherSuite,
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
  AeadEncFunction = GetSpdmAeadEncFunc (AEADCipherSuite);
  if (AeadEncFunction == NULL) {
    return FALSE;
  }
  return AeadEncFunction (Key, KeySize, Iv, IvSize, AData, ADataSize, DataIn, DataInSize, TagOut, TagSize, DataOut, DataOutSize);
}

/**
  Return AEAD decryption function, based upon the negotiated AEAD algorithm.

  @param  AEADCipherSuite              SPDM AEADCipherSuite

  @return AEAD decryption function
**/
AEAD_DECRYPT
GetSpdmAeadDecFunc (
  IN   UINT16                       AEADCipherSuite
  )
{
  switch (AEADCipherSuite) {
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

/**
  Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  AEADCipherSuite              SPDM AEADCipherSuite
  @param  Key                          Pointer to the encryption key.
  @param  KeySize                      Size of the encryption key in bytes.
  @param  Iv                           Pointer to the IV value.
  @param  IvSize                       Size of the IV value in bytes.
  @param  AData                        Pointer to the additional authenticated data (AAD).
  @param  ADataSize                    Size of the additional authenticated data (AAD) in bytes.
  @param  DataIn                       Pointer to the input data buffer to be decrypted.
  @param  DataInSize                   Size of the input data buffer in bytes.
  @param  Tag                          Pointer to a buffer that contains the authentication tag.
  @param  TagSize                      Size of the authentication tag in bytes.
  @param  DataOut                      Pointer to a buffer that receives the decryption output.
  @param  DataOutSize                  Size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated decryption succeeded.
  @retval FALSE  AEAD authenticated decryption failed.
**/
BOOLEAN
EFIAPI
SpdmAeadDecryption (
  IN   UINT16                       AEADCipherSuite,
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
  AeadDecFunction = GetSpdmAeadDecFunc (AEADCipherSuite);
  if (AeadDecFunction == NULL) {
    return FALSE;
  }
  return AeadDecFunction (Key, KeySize, Iv, IvSize, AData, ADataSize, DataIn, DataInSize, Tag, TagSize, DataOut, DataOutSize);
}

/**
  Generates a random byte stream of the specified size.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Size                         Size of random bytes to generate.
  @param  Rand                         Pointer to buffer to receive random value.
**/
VOID
EFIAPI
SpdmGetRandomNumber (
  IN  UINTN                     Size,
  OUT UINT8                     *Rand
  )
{
  RandomBytes (Rand, Size);

  return ;
}

/**
  Check the X509 DataTime is within a valid range.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  From                         notBefore Pointer to DateTime object.
  @param  FromSize                     notBefore DateTime object size.
  @param  To                           notAfter Pointer to DateTime object.
  @param  ToSize                       notAfter DateTime object size.

  @retval  TRUE   verification pass.
  @retval  FALSE  verification fail.
**/
STATIC
BOOLEAN
InternalSpdmX509DateTimeCheck (
  IN UINT8 *From,
  IN UINTN FromSize,
  IN UINT8 *To,
  IN UINTN ToSize
  )
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
  if (ReturnStatus != RETURN_SUCCESS) {
    return FALSE;
  }

  ReturnStatus = X509SetDateTime ("99991231235959Z", T0, &T0Size);
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
SpdmX509CertificateCheck (
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

/**
  Retrieve the SubjectAltName from SubjectAltName Bytes.

  @param[in]      Buffer           Pointer to subjectAltName oct bytes.
  @param[in]      Len              Size of Buffer in bytes.
  @param[out]     NameBuffer       Buffer to contain the retrieved certificate
                                   SubjectAltName. At most NameBufferSize bytes will be
                                   written. Maybe NULL in order to determine the size
                                   buffer needed.
  @param[in,out]  NameBufferSize   The size in bytes of the Name buffer on input,
                                   and the size of buffer returned Name on output.
                                   If NameBuffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.
  @param[out]     Oid              OID of otherName
  @param[in,out]  OidSize          the buffersize for required OID

  @retval RETURN_SUCCESS           The certificate Organization Name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If NameBufferSize is NULL.
                                   If NameBuffer is not NULL and *CommonNameSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the NameBuffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   NameBufferSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
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
  INT32       Length;
  UINTN       ObjLen;
  INT32       Ret;

  Length = (INT32)Len;
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

/**
  Retrieve the SubjectAltName from one X.509 certificate.

  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     NameBuffer       Buffer to contain the retrieved certificate
                                   SubjectAltName. At most NameBufferSize bytes will be
                                   written. Maybe NULL in order to determine the size
                                   buffer needed.
  @param[in,out]  NameBufferSize   The size in bytes of the Name buffer on input,
                                   and the size of buffer returned Name on output.
                                   If NameBuffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.
  @param[out]     Oid              OID of otherName
  @param[in,out]  OidSize          the buffersize for required OID

  @retval RETURN_SUCCESS           The certificate Organization Name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If NameBufferSize is NULL.
                                   If NameBuffer is not NULL and *CommonNameSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the NameBuffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   NameBufferSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
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

/**
  This function verifies the integrity of certificate chain data without SPDM_CERT_CHAIN header.

  @param  CertChainData          The certificate chain data without SPDM_CERT_CHAIN header.
  @param  CertChainDataSize      Size in bytes of the certificate chain data.

  @retval TRUE  certificate chain data integrity verification pass.
  @retval FALSE certificate chain data integrity verification fail.
**/
BOOLEAN
EFIAPI
SpdmVerifyCertChainData (
  IN UINT8                        *CertChainData,
  IN UINTN                        CertChainDataSize
  )
{
  UINT8                                     *RootCertBuffer;
  UINTN                                     RootCertBufferSize;
  UINT8                                     *LeafCertBuffer;
  UINTN                                     LeafCertBufferSize;

  if (CertChainDataSize > MAX_UINT16 - (sizeof(SPDM_CERT_CHAIN) + MAX_HASH_SIZE)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainData - FAIL (chain size too large) !!!\n"));
    return FALSE;
  }

  if (!X509GetCertFromCertChain (CertChainData, CertChainDataSize, 0, &RootCertBuffer, &RootCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainData - FAIL (get root certificate failed)!!!\n"));
    return FALSE;
  }

  if (!X509VerifyCertChain (RootCertBuffer, RootCertBufferSize, CertChainData, CertChainDataSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainData - FAIL (cert chain verify failed)!!!\n"));
    return FALSE;
  }

  if (!X509GetCertFromCertChain (CertChainData, CertChainDataSize, -1, &LeafCertBuffer, &LeafCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainData - FAIL (get leaf certificate failed)!!!\n"));
    return FALSE;
  }

  if(!SpdmX509CertificateCheck (LeafCertBuffer, LeafCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainData - FAIL (leaf certificate check failed)!!!\n"));
    return FALSE;
  }

  return TRUE;
}

/**
  This function verifies the integrity of certificate chain buffer including SPDM_CERT_CHAIN header.

  @param  BaseHashAlgo                 SPDM BaseHashAlgo
  @param  CertChainBuffer              The certificate chain buffer including SPDM_CERT_CHAIN header.
  @param  CertChainBufferSize          Size in bytes of the certificate chain buffer.

  @retval TRUE  certificate chain buffer integrity verification pass.
  @retval FALSE certificate chain buffer integrity verification fail.
**/
BOOLEAN
EFIAPI
SpdmVerifyCertificateChainBuffer (
  IN UINT32                       BaseHashAlgo,
  IN VOID                         *CertChainBuffer,
  IN UINTN                        CertChainBufferSize
  )
{
  UINT8                                     *CertChainData;
  UINTN                                     CertChainDataSize;
  UINT8                                     *RootCertBuffer;
  UINTN                                     RootCertBufferSize;
  UINTN                                     HashSize;
  UINT8                                     CalcRootCertHash[MAX_HASH_SIZE];
  UINT8                                     *LeafCertBuffer;
  UINTN                                     LeafCertBufferSize;

  HashSize = GetSpdmHashSize (BaseHashAlgo);

  if (CertChainBufferSize > MAX_SPDM_MESSAGE_BUFFER_SIZE) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainBuffer - FAIL (buffer too large) !!!\n"));
    return FALSE;
  }

  if (CertChainBufferSize <= sizeof(SPDM_CERT_CHAIN) + HashSize) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainBuffer - FAIL (buffer too small) !!!\n"));
    return FALSE;
  }

  CertChainData = (UINT8 *)CertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertChainDataSize = CertChainBufferSize - sizeof(SPDM_CERT_CHAIN) - HashSize;
  if (!X509GetCertFromCertChain (CertChainData, CertChainDataSize, 0, &RootCertBuffer, &RootCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainBuffer - FAIL (get root certificate failed)!!!\n"));
    return FALSE;
  }

  SpdmHashAll (BaseHashAlgo, RootCertBuffer, RootCertBufferSize, CalcRootCertHash);
  if (CompareMem ((UINT8 *)CertChainBuffer + sizeof(SPDM_CERT_CHAIN), CalcRootCertHash, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainBuffer - FAIL (cert root hash mismatch) !!!\n"));
    return FALSE;
  }

  if (!X509VerifyCertChain (RootCertBuffer, RootCertBufferSize, CertChainData, CertChainDataSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainBuffer - FAIL (cert chain verify failed)!!!\n"));
    return FALSE;
  }

  if (!X509GetCertFromCertChain (CertChainData, CertChainDataSize, -1, &LeafCertBuffer, &LeafCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainBuffer - FAIL (get leaf certificate failed)!!!\n"));
    return FALSE;
  }

  if(!SpdmX509CertificateCheck (LeafCertBuffer, LeafCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainBuffer - FAIL (leaf certificate check failed)!!!\n"));
    return FALSE;
  }

  return TRUE;
}
