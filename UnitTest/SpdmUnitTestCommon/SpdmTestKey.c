/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"

UINT32  mUseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
UINT32  mUseMeasurementHashAlgo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
UINT32  mUseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
UINT16  mUseReqAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
UINT16  mUseDheAlgo = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1;
UINT16  mUseAeadAlgo = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM;
UINT16  mUseKeyScheduleAlgo = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;

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
  Retrieve the Private Key from the password-protected PEM key data.

  @param  PemData                      Pointer to the PEM-encoded key data to be retrieved.
  @param  PemSize                      Size of the PEM key data in bytes.
  @param  Password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
typedef
BOOLEAN
(EFIAPI *ASYM_GET_PRIVATE_KEY_FROM_PEM) (
  IN   CONST UINT8  *PemData,
  IN   UINTN        PemSize,
  IN   CONST CHAR8  *Password,
  OUT  VOID         **Context
  );

/**
  Release the specified asymmetric context

  @param  Context                      Pointer to the asymmetric context to be released.
**/
typedef
VOID
(EFIAPI *ASYM_FREE) (
  IN  VOID         *Context
  );

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  @param  Context                      Pointer to asymmetric context for signature generation.
  @param  MessageHash                  Pointer to octet message hash to be signed.
  @param  HashSize                     Size of the message hash in bytes.
  @param  Signature                    Pointer to buffer to receive signature.
  @param  SigSize                      On input, the size of Signature buffer in bytes.
                                       On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
typedef
BOOLEAN
(EFIAPI *ASYM_SIGN) (
  IN      VOID         *Context,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

VOID  *mResponderPrivateCertData;
UINTN mResponderPrivateCertDataSize;

VOID  *mRequesterPrivateCertData;
UINTN mRequesterPrivateCertDataSize;

UINT32
TestGetSpdmHashSize (
  IN      UINT32       HashAlgo
  )
{
  switch (HashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    return 32;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
    return 48;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
    return 64;
  default:
    ASSERT( FALSE);
    return 0;
  }
}

UINT32
TestGetSpdmMeasurementHashSize (
  IN      UINT32       HashAlgo
  )
{
  switch (HashAlgo) {
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
    return 32;
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
    return 48;
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
    return 64;
  default:
    ASSERT( FALSE);
    return 0;
  }
}

/**
  Return hash function, based upon the negotiated hash algorithm.

  @param  HashAlgo                  The hash algorithm.

  @return hash function
**/
HASH_ALL
TestGetSpdmHashFunc (
  IN      UINT32       HashAlgo
  )
{
  switch (HashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    return Sha256HashAll;
    break;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
    return Sha384HashAll;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
    return Sha512HashAll;
  default:
    return NULL;
  }
}

/**
  Computes the hash of a input data buffer, based upon the negotiated hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  HashAlgo                     The hash algorithm.
  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
BOOLEAN
TestSpdmHashAll (
  IN   UINT32                       HashAlgo,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  )
{
  HASH_ALL   HashFunction;
  HashFunction = TestGetSpdmHashFunc (HashAlgo);
  if (HashFunction == NULL) {
    return FALSE;
  }
  return HashFunction (Data, DataSize, HashValue);
}

/**
  Return HMAC function, based upon the negotiated HMAC algorithm.

  @param  HashAlgo                     The hash algorithm.

  @return HMAC function
**/
HMAC_ALL
TestGetSpdmHmacFunc (
  IN   UINT32                       HashAlgo
  )
{
  switch (HashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    return HmacSha256All;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
    return HmacSha384All;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
    return HmacSha512All;
  default:
    return NULL;
  }
}

/**
  Computes the HMAC of a input data buffer, based upon the negotiated HMAC algorithm.

  This function performs the HMAC of a given data buffer, and return the hash value.

  @param  HashAlgo                     The hash algorithm.
  @param  Data                         Pointer to the buffer containing the data to be HMACed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  Key                          Pointer to the user-supplied key.
  @param  KeySize                      Key size in bytes.
  @param  HashValue                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
BOOLEAN
TestSpdmHmacAll (
  IN   UINT32                       HashAlgo,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  IN   CONST UINT8                  *Key,
  IN   UINTN                        KeySize,
  OUT  UINT8                        *HmacValue
  )
{
  HMAC_ALL   HmacFunction;
  HmacFunction = TestGetSpdmHmacFunc (HashAlgo);
  if (HmacFunction == NULL) {
    return FALSE;
  }
  return HmacFunction (Data, DataSize, Key, KeySize, HmacValue);
}

/**
  Return HKDF expand function, based upon the negotiated HKDF algorithm.

  @param  HashAlgo                     The hash algorithm.

  @return HKDF expand function
**/
HKDF_EXPAND
TestGetSpdmHkdfExpandFunc (
  IN   UINT32                       HashAlgo
  )
{
  switch (HashAlgo) {
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256:
    return HkdfSha256Expand;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384:
    return HkdfSha384Expand;
  case SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512:
    return HkdfSha512Expand;
  default:
    return NULL;
  }
}

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  HashAlgo                     The hash algorithm.
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
TestSpdmHkdfExpand (
  IN   UINT32                       HashAlgo,
  IN   CONST UINT8                  *Prk,
  IN   UINTN                        PrkSize,
  IN   CONST UINT8                  *Info,
  IN   UINTN                        InfoSize,
  OUT  UINT8                        *Out,
  IN   UINTN                        OutSize
  )
{
  HKDF_EXPAND   HkdfExpandFunction;
  HkdfExpandFunction = TestGetSpdmHkdfExpandFunc (HashAlgo);
  if (HkdfExpandFunction == NULL) {
    return FALSE;
  }
  return HkdfExpandFunction (Prk, PrkSize, Info, InfoSize, Out, OutSize);
}

/**
  Return hash function, based upon the negotiated measurement hash algorithm.

  @param  HashAlgo                  The hash algorithm.

  @return hash function
**/
HASH_ALL
TestGetSpdmMeasurementHashFunc (
  IN   UINT32                       HashAlgo
  )
{
  switch (HashAlgo) {
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256:
    return Sha256HashAll;
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384:
    return Sha384HashAll;
  case SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512:
    return Sha512HashAll;
  default:
    return NULL;
  }
}

/**
  Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  HashAlgo                     The hash algorithm.
  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
BOOLEAN
TestSpdmMeasurementHashAll (
  IN   UINT32                       HashAlgo,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  )
{
  HASH_ALL   HashFunction;
  HashFunction = TestGetSpdmMeasurementHashFunc (HashAlgo);
  if (HashFunction == NULL) {
    return FALSE;
  }
  return HashFunction (Data, DataSize, HashValue);
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
  );

/**
  This function verifies the integrity of a certificate chain

  @param  CertBuffer                  A pointer to the certificate chain.
  @param  CertBufferSize              The chain size

  @retval TRUE  certificate chain integrity verification pass.
  @retval FALSE certificate chain integrity verification fail.
**/
BOOLEAN
TestSpdmVerifyCertificateChainData (
  UINT8                                     *CertBuffer,
  UINTN                                     CertBufferSize
  )
{
  UINT8                                     *RootCertBuffer;
  UINTN                                     RootCertBufferSize;
  UINT8                                     *LeafCertBuffer;
  UINTN                                     LeafCertBufferSize;

  if (CertBufferSize > MAX_UINT16 - (sizeof(SPDM_CERT_CHAIN) + MAX_HASH_SIZE)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (chain size too large) !!!\n"));
    return FALSE;
  }

  if (!X509GetCertFromCertChain (CertBuffer, CertBufferSize, 0, &RootCertBuffer, &RootCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (get root certificate failed)!!!\n"));
    return FALSE;
  }

  if (!X509VerifyCertChain (RootCertBuffer, RootCertBufferSize, CertBuffer, CertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (cert chain verify failed)!!!\n"));
    return FALSE;
  }

  if (!X509GetCertFromCertChain (CertBuffer, CertBufferSize, -1, &LeafCertBuffer, &LeafCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
    return FALSE;
  }

  if(!SpdmX509CertificateCheck (LeafCertBuffer, LeafCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (leaf certificate check failed)!!!\n"));
    return FALSE;
  }

  return TRUE;
}

BOOLEAN
ReadResponderPrivateCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size
  )
{
  BOOLEAN  Res;
  CHAR8    *File;

  switch (mUseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    File = "Rsa2048/end_responder.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    File = "Rsa3072/end_responder.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/end_responder.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/end_responder.key";
    break;
  default:
    ASSERT( FALSE);
    return FALSE;
  }
  Res = ReadInputFile (File, Data, Size);
  if (Res) {
    mResponderPrivateCertData = *Data;
    mResponderPrivateCertDataSize = *Size;
  }
  return Res;
}

BOOLEAN
ReadRequesterPrivateCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size
  )
{
  BOOLEAN  Res;
  CHAR8    *File;

  switch (mUseReqAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    File = "Rsa2048/end_requester.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    File = "Rsa3072/end_requester.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/end_requester.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/end_requester.key";
    break;
  default:
    ASSERT( FALSE);
    return FALSE;
  }
  Res = ReadInputFile (File, Data, Size);
  if (Res) {
    mRequesterPrivateCertData = *Data;
    mRequesterPrivateCertDataSize = *Size;
  }
  return Res;
}


BOOLEAN
ReadResponderRootPublicCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  )
{
  BOOLEAN             Res;
  VOID                *FileData;
  UINTN               FileSize;
  SPDM_CERT_CHAIN     *CertChain;
  UINTN               CertChainSize;
  CHAR8               *File;
  UINTN               DigestSize;

  switch (mUseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    File = "Rsa2048/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    File = "Rsa3072/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/ca.cert.der";
    break;
  default:
    ASSERT( FALSE);
    return FALSE;
  }
  Res = ReadInputFile (File, &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  DigestSize = TestGetSpdmHashSize (mUseHashAlgo);

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + DigestSize + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;

  TestSpdmHashAll (mUseHashAlgo, FileData, FileSize, (UINT8 *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + DigestSize,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;
  if (Hash != NULL) {
    *Hash = (CertChain + 1);
  }
  if (HashSize != NULL) {
    *HashSize = DigestSize;
  }

  free (FileData);
  return TRUE;
}

BOOLEAN
ReadResponderRootPublicCertificateBySize (
  IN  UINT16  ChainId,
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  )
{
  BOOLEAN             Res;
  VOID                *FileData;
  UINTN               FileSize;
  SPDM_CERT_CHAIN     *CertChain;
  UINTN               CertChainSize;
  CHAR8               *File;
  UINTN               DigestSize;

  switch (ChainId) {
  case TEST_CERT_SMALL:
    File = "LongChains/Shorter1024B_ca.cert.der";
    break;
  case TEST_CERT_MAXINT16: // DataSize slightly smaller than MAX_INT16
    File = "LongChains/ShorterMAXINT16_ca.cert.der";
    break;
  case TEST_CERT_MAXUINT16: // DataSize slightly smaller than MAX_UINT16
    File = "LongChains/ShorterMAXUINT16_ca.cert.der";
    break;
  case TEST_CERT_MAXUINT16_LARGER: // DataSize larger than MAX_UINT16
    File = "LongChains/LongerMAXUINT16_ca.cert.der";
    break;
  default:
    ASSERT( FALSE);
    return FALSE;
  }
  Res = ReadInputFile (File, &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  DigestSize = TestGetSpdmHashSize (mUseHashAlgo);

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + DigestSize + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;

  TestSpdmHashAll (mUseHashAlgo, FileData, FileSize, (UINT8 *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + DigestSize,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;
  if (Hash != NULL) {
    *Hash = (CertChain + 1);
  }
  if (HashSize != NULL) {
    *HashSize = DigestSize;
  }

  free (FileData);
  return TRUE;
}

BOOLEAN
ReadRequesterRootPublicCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  )
{
  BOOLEAN             Res;
  VOID                *FileData;
  UINTN               FileSize;
  SPDM_CERT_CHAIN     *CertChain;
  UINTN               CertChainSize;
  CHAR8               *File;
  UINTN               DigestSize;

  switch (mUseReqAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    File = "Rsa2048/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    File = "Rsa3072/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/ca.cert.der";
    break;
  default:
    ASSERT( FALSE);
    return FALSE;
  }

  DigestSize = TestGetSpdmHashSize (mUseHashAlgo);

  Res = ReadInputFile (File, &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + DigestSize + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;
  TestSpdmHashAll (mUseHashAlgo, FileData, FileSize, (UINT8 *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + DigestSize,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;
  if (Hash != NULL) {
    *Hash = (CertChain + 1);
  }
  if (HashSize != NULL) {
    *HashSize = DigestSize;
  }

  free (FileData);
  return TRUE;
}

BOOLEAN
ReadResponderPublicCertificateChain (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  )
{
  BOOLEAN             Res;
  VOID                *FileData;
  UINTN               FileSize;
  SPDM_CERT_CHAIN     *CertChain;
  UINTN               CertChainSize;
  CHAR8               *File;
  UINT8               *RootCert;
  UINTN               RootCertLen;
  UINTN               DigestSize;

  switch (mUseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    File = "Rsa2048/bundle_responder.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    File = "Rsa3072/bundle_responder.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/bundle_responder.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/bundle_responder.certchain.der";
    break;
  default:
    ASSERT( FALSE);
    return FALSE;
  }
  Res = ReadInputFile (File, &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  DigestSize = TestGetSpdmHashSize (mUseHashAlgo);

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + DigestSize + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;

  Res = TestSpdmVerifyCertificateChainData(FileData, FileSize);
  if (!Res) {
    free (FileData);
    free (CertChain);
    return Res;
  }

  //
  // Get Root Certificate and calculate hash value
  //
  Res = X509GetCertFromCertChain(FileData, FileSize, 0, &RootCert, &RootCertLen);
  if (!Res) {
    free (FileData);
    free (CertChain);
    return Res;
  }

  TestSpdmHashAll (mUseHashAlgo, RootCert, RootCertLen, (UINT8 *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + DigestSize,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;
  if (Hash != NULL) {
    *Hash = (CertChain + 1);
  }
  if (HashSize != NULL) {
    *HashSize = DigestSize;
  }

  free (FileData);
  return TRUE;
}

BOOLEAN
ReadResponderPublicCertificateChainBySize (
  IN  UINT16  ChainId,
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  )
{
  BOOLEAN             Res;
  VOID                *FileData;
  UINTN               FileSize;
  SPDM_CERT_CHAIN     *CertChain;
  UINTN               CertChainSize;
  CHAR8               *File;
  UINT8               *RootCert;
  UINTN                RootCertLen;
  UINTN               DigestSize;

  switch (ChainId) {
  case TEST_CERT_SMALL: // DataSize smaller than 1024 Bytes
    File = "LongChains/Shorter1024B_bundle_responder.certchain.der";
    break;
  case TEST_CERT_MAXINT16: // DataSize slightly smaller than MAX_INT16
    File = "LongChains/ShorterMAXINT16_bundle_responder.certchain.der";
    break;
  case TEST_CERT_MAXUINT16: // DataSize slightly smaller than MAX_UINT16
    File = "LongChains/ShorterMAXUINT16_bundle_responder.certchain.der";
    break;
  case TEST_CERT_MAXUINT16_LARGER: // DataSize larger than MAX_UINT16
    File = "LongChains/LongerMAXUINT16_bundle_responder.certchain.der";
    break;
  default:
    ASSERT( FALSE);
    return FALSE;
  }
  Res = ReadInputFile (File, &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  DigestSize = TestGetSpdmHashSize (mUseHashAlgo);

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + DigestSize + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;

  Res = TestSpdmVerifyCertificateChainData(FileData, FileSize);
  if (!Res) {
    free (FileData);
    free (CertChain);
    return Res;
  }

  //
  // Get Root Certificate and calculate hash value
  //
  Res = X509GetCertFromCertChain(FileData, FileSize, 0, &RootCert, &RootCertLen);
  if (!Res) {
    free (FileData);
    free (CertChain);
    return Res;
  }

  TestSpdmHashAll (mUseHashAlgo, RootCert, RootCertLen, (UINT8 *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + DigestSize,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;
  if (Hash != NULL) {
    *Hash = (CertChain + 1);
  }
  if (HashSize != NULL) {
    *HashSize = DigestSize;
  }

  free (FileData);
  return TRUE;
}

BOOLEAN
ReadRequesterPublicCertificateChain (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  )
{
  BOOLEAN             Res;
  VOID                *FileData;
  UINTN               FileSize;
  SPDM_CERT_CHAIN     *CertChain;
  UINTN               CertChainSize;
  CHAR8               *File;
  UINT8               *RootCert;
  UINTN               RootCertLen;
  UINTN               DigestSize;

  switch (mUseReqAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    File = "Rsa2048/bundle_requester.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    File = "Rsa3072/bundle_requester.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/bundle_requester.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/bundle_requester.certchain.der";
    break;
  default:
    ASSERT( FALSE);
    return FALSE;
  }
  Res = ReadInputFile (File, &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  DigestSize = TestGetSpdmHashSize (mUseHashAlgo);

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + DigestSize + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;

  Res = TestSpdmVerifyCertificateChainData(FileData, FileSize);
  if (!Res) {
    free (FileData);
    free (CertChain);
    return Res;
  }

  //
  // Get Root Certificate and calculate hash value
  //
  Res = X509GetCertFromCertChain(FileData, FileSize, 0, &RootCert, &RootCertLen);
  if (!Res) {
    free (FileData);
    free (CertChain);
    return Res;
  }

  TestSpdmHashAll (mUseHashAlgo, RootCert, RootCertLen, (UINT8 *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + DigestSize,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;
  if (Hash != NULL) {
    *Hash = (CertChain + 1);
  }
  if (HashSize != NULL) {
    *HashSize = DigestSize;
  }

  free (FileData);
  return TRUE;
}

/**
  Return asymmetric GET_PRIVATE_KEY_FROM_PEM function, based upon the asymmetric algorithm.

  @param  AsymAlgo                     The asymmetric algorithm.

  @return asymmetric GET_PRIVATE_KEY_FROM_PEM function
**/
ASYM_GET_PRIVATE_KEY_FROM_PEM
TestGetSpdmAsymGetPrivateKeyFromPem (
  IN      UINT32       AsymAlgo
  )
{
  switch (AsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
    return RsaGetPrivateKeyFromPem;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
    return EcGetPrivateKeyFromPem;
  }
  return NULL;
}

/**
  Retrieve the Private Key from the password-protected PEM key data.

  @param  AsymAlgo                     The asymmetric algorithm.
  @param  PemData                      Pointer to the PEM-encoded key data to be retrieved.
  @param  PemSize                      Size of the PEM key data in bytes.
  @param  Password                     NULL-terminated passphrase used for encrypted PEM key data.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved private key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Private Key was retrieved successfully.
  @retval  FALSE  Invalid PEM key data or incorrect password.
**/
BOOLEAN
TestSpdmAsymGetPrivateKeyFromPem (
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *PemData,
  IN      UINTN        PemSize,
  IN      CONST CHAR8  *Password,
  OUT     VOID         **Context
  )
{
  ASYM_GET_PRIVATE_KEY_FROM_PEM   AsymGetPrivateKeyFromPem;
  AsymGetPrivateKeyFromPem = TestGetSpdmAsymGetPrivateKeyFromPem (AsymAlgo);
  if (AsymGetPrivateKeyFromPem == NULL) {
    return FALSE;
  }
  return AsymGetPrivateKeyFromPem (PemData, PemSize, Password, Context);
}

/**
  Return asymmetric free function, based upon the asymmetric algorithm.

  @param  AsymAlgo                     The asymmetric algorithm.

  @return asymmetric free function
**/
ASYM_FREE
TestGetSpdmAsymFree (
  IN      UINT32       AsymAlgo
  )
{
  switch (AsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
    return RsaFree;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
    return EcFree;
  }
  return NULL;
}

/**
  Release the specified asymmetric context

  @param  AsymAlgo                     The asymmetric algorithm.
  @param  Context                      Pointer to the asymmetric context to be released.
**/
VOID
TestSpdmAsymFree (
  IN      UINT32       AsymAlgo,
  IN      VOID         *Context
  )
{
  ASYM_FREE   AsymFree;
  AsymFree = TestGetSpdmAsymFree (AsymAlgo);
  if (AsymFree == NULL) {
    return ;
  }
  AsymFree (Context);
}

/**
  Return asymmetric sign function, based upon the asymmetric algorithm.

  @param  AsymAlgo                     The asymmetric algorithm.

  @return asymmetric sign function
**/
ASYM_SIGN
TestGetSpdmAsymSign (
  IN      UINT32       AsymAlgo
  )
{
  switch (AsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    return RsaPkcs1Sign;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
    return RsaPssSign;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
    return EcDsaSign;
  }
  return NULL;
}

/**
  Carries out the signature generation.

  If the Signature buffer is too small to hold the contents of signature, FALSE
  is returned and SigSize is set to the required buffer size to obtain the signature.

  @param  AsymAlgo                     The asymmetric algorithm.
  @param  Context                      Pointer to asymmetric context for signature generation.
  @param  MessageHash                  Pointer to octet message hash to be signed.
  @param  HashSize                     Size of the message hash in bytes.
  @param  Signature                    Pointer to buffer to receive signature.
  @param  SigSize                      On input, the size of Signature buffer in bytes.
                                       On output, the size of data returned in Signature buffer in bytes.

  @retval  TRUE   Signature successfully generated.
  @retval  FALSE  Signature generation failed.
  @retval  FALSE  SigSize is too small.
**/
BOOLEAN
TestSpdmAsymSign (
  IN      UINT32       AsymAlgo,
  IN      VOID         *Context,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  ASYM_SIGN   AsymSign;
  AsymSign = TestGetSpdmAsymSign (AsymAlgo);
  if (AsymSign == NULL) {
    return FALSE;
  }
  return AsymSign (Context, MessageHash, HashSize, Signature, SigSize);
}

/**
  Sign an SPDM message data.

  @param  IsResponder                  Indicates if it is a responder message.
  @param  AsymAlgo                     Indicates the signing algorithm.
                                       For responder, it must align with BaseAsymAlgo (SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_*)
                                       For requester, it must align with ReqBaseAsymAlgo (SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_*)
  @param  MessageHash                  A pointer to a message hash to be signed.
  @param  HashSize                     The size in bytes of the message hash to be signed.
  @param  Signature                    A pointer to a destination buffer to store the signature.
  @param  SigSize                      On input, indicates the size in bytes of the destination buffer to store the signature.
                                       On output, indicates the size in bytes of the signature in the buffer.

  @retval TRUE  signing success.
  @retval FALSE signing fail.
**/
BOOLEAN
SpdmDataSignFunc (
  IN      BOOLEAN      IsResponder,
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  VOID                          *Context;
  VOID                          *PrivatePem;
  UINTN                         PrivatePemSize;
  BOOLEAN                       Result;

  if (IsResponder) {
    if (AsymAlgo != mUseAsymAlgo) {
      return FALSE;
    }
  } else {
    if (AsymAlgo != mUseReqAsymAlgo) {
      return FALSE;
    }
  }

  if (IsResponder) {
    PrivatePem = mResponderPrivateCertData;
    PrivatePemSize = mResponderPrivateCertDataSize;
  } else {
    PrivatePem = mRequesterPrivateCertData;
    PrivatePemSize = mRequesterPrivateCertDataSize;
  }

  Result = TestSpdmAsymGetPrivateKeyFromPem (AsymAlgo, PrivatePem, PrivatePemSize, NULL, &Context);
  if (!Result) {
    return FALSE;
  }
  Result = TestSpdmAsymSign (
             AsymAlgo,
             Context,
             MessageHash,
             HashSize,
             Signature,
             SigSize
             );
  TestSpdmAsymFree (AsymAlgo, Context);

  return Result;
}

BOOLEAN
EFIAPI
SpdmRequesterDataSignFunc (
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  return SpdmDataSignFunc (FALSE, AsymAlgo, MessageHash, HashSize, Signature, SigSize);
}

BOOLEAN
EFIAPI
SpdmResponderDataSignFunc (
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  return SpdmDataSignFunc (TRUE, AsymAlgo, MessageHash, HashSize, Signature, SigSize);
}

UINT8  mMyZeroFilledBuffer[64];

VOID
DumpHexStr (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  )
{
  UINTN Index;

  for (Index = 0; Index < BufferSize; Index++) {
    printf ("%02x", Buffer[Index]);
  }
}

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  The PRK is PSK derived HandshakeSecret.

  @param  HashAlgo                     Indicates the hash algorithm.
  @param  PskHint                      Pointer to the user-supplied PSK Hint.
  @param  PskHintSize                  PSK Hint size in bytes.
  @param  Info                         Pointer to the application specific info.
  @param  InfoSize                     Info size in bytes.
  @param  Out                          Pointer to buffer to receive hkdf value.
  @param  OutSize                      Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
BOOLEAN
EFIAPI
SpdmPskHandshakeSecretHkdfExpandFunc (
  IN      UINT32       HashAlgo,
  IN      CONST UINT8  *PskHint, OPTIONAL
  IN      UINTN        PskHintSize, OPTIONAL
  IN      CONST UINT8  *Info,
  IN      UINTN        InfoSize,
     OUT  UINT8        *Out,
  IN      UINTN        OutSize
  )
{
  VOID                          *Psk;
  UINTN                         PskSize;
  UINTN                         HashSize;
  BOOLEAN                       Result;
  UINT8                         HandshakeSecret[64];

  ASSERT (HashAlgo == mUseHashAlgo);

  if ((PskHint == NULL) && (PskHintSize == 0)) {
    Psk = TEST_PSK_DATA_STRING;
    PskSize = sizeof(TEST_PSK_DATA_STRING);
  } else if ((PskHint != NULL) && (PskHintSize != 0) &&
             (strcmp((const char *)PskHint, TEST_PSK_HINT_STRING) == 0) &&
             (PskHintSize == sizeof(TEST_PSK_HINT_STRING))) {
    Psk = TEST_PSK_DATA_STRING;
    PskSize = sizeof(TEST_PSK_DATA_STRING);
  } else {
    return FALSE;
  }
  printf ("[PSK]: ");
  DumpHexStr (Psk, PskSize);
  printf ("\n");

  HashSize = TestGetSpdmHashSize (HashAlgo);

  Result = TestSpdmHmacAll (HashAlgo, mMyZeroFilledBuffer, HashSize, Psk, PskSize, HandshakeSecret);
  if (!Result) {
    return Result;
  }

  Result = TestSpdmHkdfExpand (HashAlgo, HandshakeSecret, HashSize, Info, InfoSize, Out, OutSize);
  ZeroMem (HandshakeSecret, HashSize);

  return Result;
}

