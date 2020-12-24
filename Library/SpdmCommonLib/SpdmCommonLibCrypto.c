/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

/**
  Computes the hash of a input data buffer.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
typedef
BOOLEAN
(EFIAPI *HASH_ALL) (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  );

/**
  Computes the HMAC of a input data buffer.

  This function performs the HMAC of a given data buffer, and return the hash value.

  @param  Data                         Pointer to the buffer containing the data to be HMACed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  Key                          Pointer to the user-supplied key.
  @param  KeySize                      Key size in bytes.
  @param  HashValue                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
typedef
BOOLEAN
(EFIAPI *HMAC_ALL) (
  IN   CONST VOID   *Data,
  IN   UINTN        DataSize,
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize,
  OUT  UINT8        *HmacValue
  );

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand.

  @param  Prk                          Pointer to the user-supplied key.
  @param  PrkSize                      Key size in bytes.
  @param  Info                         Pointer to the application specific info.
  @param  InfoSize                     Info size in bytes.
  @param  Out                          Pointer to buffer to receive hkdf value.
  @param  OutSize                      Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
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

/**
  Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD).

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

/**
  Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD).

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

/**
  Retrieve the asymmetric Public Key from one DER-encoded X509 certificate.

  @param  Cert                         Pointer to the DER-encoded X509 certificate.
  @param  CertSize                     Size of the X509 certificate in bytes.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
typedef
BOOLEAN
(EFIAPI *ASYM_GET_PUBLIC_KEY_FROM_X509) (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize,
  OUT  VOID         **Context
  );

/**
  Release the specified asymmetric context.

  @param  Context                      Pointer to the asymmetric context to be released.
**/
typedef
VOID
(EFIAPI *ASYM_FREE) (
  IN  VOID         *Context
  );

/**
  Verifies the asymmetric signature.

  @param  Context                      Pointer to asymmetric context for signature verification.
  @param  MessageHash                  Pointer to octet message hash to be checked.
  @param  HashSize                     Size of the message hash in bytes.
  @param  Signature                    Pointer to asymmetric signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
typedef
BOOLEAN
(EFIAPI *ASYM_VERIFY) (
  IN  VOID         *Context,
  IN  CONST UINT8  *MessageHash,
  IN  UINTN        HashSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  );

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) Context for subsequent use.

  @param Nid cipher NID

  @return  Pointer to the Diffie-Hellman Context that has been initialized.
**/
typedef
VOID *
(EFIAPI *DHE_NEW_BY_NID) (
  IN UINTN  Nid
  );

/**
  Generates DHE public key.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter PublicKey and PublicKeySize. DH context is updated accordingly.
  If the PublicKey buffer is too small to hold the public key, FALSE is returned and
  PublicKeySize is set to the required buffer size to obtain the public key.

  @param  Context                      Pointer to the DHE context.
  @param  PublicKey                    Pointer to the buffer to receive generated public key.
  @param  PublicKeySize                On input, the size of PublicKey buffer in bytes.
                                       On output, the size of data returned in PublicKey buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  PublicKeySize is not large enough.
**/
typedef
BOOLEAN
(EFIAPI *DHE_GENERATE_KEY) (
  IN OUT  VOID   *Context,
  OUT     UINT8  *PublicKey,
  IN OUT  UINTN  *PublicKeySize
  );

/**
  Computes exchanged common key.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

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
typedef
BOOLEAN
(EFIAPI *DHE_COMPUTE_KEY) (
  IN OUT  VOID         *Context,
  IN      CONST UINT8  *PeerPublic,
  IN      UINTN        PeerPublicSize,
  OUT     UINT8        *Key,
  IN OUT  UINTN        *KeySize
  );

/**
  Release the specified DHE context.

  @param  Context                      Pointer to the DHE context to be released.
**/
typedef
VOID
(EFIAPI *DHE_FREE) (
  IN  VOID  *Context
  );

/**
  This function returns the SPDM hash algorithm size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM hash algorithm size.
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

/**
  Return hash function, based upon the negotiated hash algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return hash function
**/
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

/**
  Computes the hash of a input data buffer, based upon the negotiated hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
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

/**
  Return hash function, based upon the negotiated measurement hash algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return hash function
**/
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

/**
  Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
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

/**
  Return HMAC function, based upon the negotiated HMAC algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return HMAC function
**/
HMAC_ALL
GetSpdmHmacFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo) {
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

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Data                         Pointer to the buffer containing the data to be HMACed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  Key                          Pointer to the user-supplied key.
  @param  KeySize                      Key size in bytes.
  @param  HashValue                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
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

/**
  Return HKDF expand function, based upon the negotiated HKDF algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return HKDF expand function
**/
HKDF_EXPAND
GetSpdmHkdfExpandFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo) {
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

  @param  SpdmContext                  A pointer to the SPDM context.
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
  This function returns the SPDM asymmetric algorithm size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM asymmetric algorithm size.
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
  This function returns the SPDM requester asymmetric algorithm size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM requester asymmetric algorithm size.
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
  This function returns the SPDM measurement hash algorithm size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM measurement hash algorithm size.
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
  This function returns the SPDM DHE algorithm key size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM DHE algorithm key size.
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

/**
  Return cipher ID, based upon the negotiated HKDF algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return HKDF expand function
**/
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
  This function returns the SPDM AEAD algorithm key size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm key size.
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
  This function returns the SPDM AEAD algorithm iv size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm iv size.
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
  This function returns the SPDM AEAD algorithm tag size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm tag size.
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
  This function returns the SPDM AEAD algorithm block size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm block size.
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

/**
  Return AEAD encryption function, based upon the negotiated AEAD algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return AEAD encryption function
**/
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

/**
  Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
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

/**
  Return AEAD decryption function, based upon the negotiated AEAD algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return AEAD decryption function
**/
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

/**
  Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
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

/**
  Return asymmetric GET_PUBLIC_KEY_FROM_X509 function, based upon the negotiated asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return asymmetric GET_PUBLIC_KEY_FROM_X509 function
**/
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

/**
  Retrieve the asymmetric Public Key from one DER-encoded X509 certificate,
  based upon negotiated asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Cert                         Pointer to the DER-encoded X509 certificate.
  @param  CertSize                     Size of the X509 certificate in bytes.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
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

/**
  Return asymmetric free function, based upon the negotiated asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return asymmetric free function
**/
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

/**
  Release the specified asymmetric context,
  based upon negotiated asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to the asymmetric context to be released.
**/
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

/**
  Return asymmetric verify function, based upon the negotiated asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return asymmetric verify function
**/
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

/**
  Verifies the asymmetric signature,
  based upon negotiated asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to asymmetric context for signature verification.
  @param  MessageHash                  Pointer to octet message hash to be checked.
  @param  HashSize                     Size of the message hash in bytes.
  @param  Signature                    Pointer to asymmetric signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
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

/**
  Return requester asymmetric GET_PUBLIC_KEY_FROM_X509 function, based upon the negotiated requester asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return requester asymmetric GET_PUBLIC_KEY_FROM_X509 function
**/
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

/**
  Retrieve the asymmetric Public Key from one DER-encoded X509 certificate,
  based upon negotiated requester asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Cert                         Pointer to the DER-encoded X509 certificate.
  @param  CertSize                     Size of the X509 certificate in bytes.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
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

/**
  Return requester asymmetric free function, based upon the negotiated requester asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return requester asymmetric free function
**/
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

/**
  Release the specified asymmetric context,
  based upon negotiated requester asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to the asymmetric context to be released.
**/
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

/**
  Return requester asymmetric verify function, based upon the negotiated requester asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return requester asymmetric verify function
**/
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

/**
  Verifies the asymmetric signature,
  based upon negotiated requester asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to asymmetric context for signature verification.
  @param  MessageHash                  Pointer to octet message hash to be checked.
  @param  HashSize                     Size of the message hash in bytes.
  @param  Signature                    Pointer to asymmetric signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
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

/**
  Return DHE new by NID function, based upon the negotiated DHE algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return DHE new by NID function
**/
DHE_NEW_BY_NID
GetSpdmDheNew (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
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

  @return  Pointer to the Diffie-Hellman Context that has been initialized.
**/
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

/**
  Return DHE free function, based upon the negotiated DHE algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return DHE free function
**/
DHE_FREE
GetSpdmDheFree (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
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

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to the DHE context to be released.
**/
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

/**
  Return DHE generate key function, based upon the negotiated DHE algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return DHE generate key function
**/
DHE_GENERATE_KEY
GetSpdmDheGenerateKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
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

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to the DHE context.
  @param  PublicKey                    Pointer to the buffer to receive generated public key.
  @param  PublicKeySize                On input, the size of PublicKey buffer in bytes.
                                       On output, the size of data returned in PublicKey buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  PublicKeySize is not large enough.
**/
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

/**
  Return DHE compute key function, based upon the negotiated DHE algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return DHE compute key function
**/
DHE_COMPUTE_KEY
GetSpdmDheComputeKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  )
{
  switch (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
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

  @param  SpdmContext                  A pointer to the SPDM context.
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

/**
  Generates a random byte stream of the specified size.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Size                         Size of random bytes to generate.
  @param  Rand                         Pointer to buffer to receive random value.
**/
VOID
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

