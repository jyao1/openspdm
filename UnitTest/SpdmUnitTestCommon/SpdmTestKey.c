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

VOID  *mResponderPrivateCertData;
UINTN mResponderPrivateCertDataSize;

VOID  *mRequesterPrivateCertData;
UINTN mRequesterPrivateCertDataSize;

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

  DigestSize = GetSpdmHashSize (mUseHashAlgo);

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + DigestSize + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;

  SpdmHashAll (mUseHashAlgo, FileData, FileSize, (UINT8 *)(CertChain + 1));
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

  DigestSize = GetSpdmHashSize (mUseHashAlgo);

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + DigestSize + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;

  SpdmHashAll (mUseHashAlgo, FileData, FileSize, (UINT8 *)(CertChain + 1));
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

  DigestSize = GetSpdmHashSize (mUseHashAlgo);

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
  SpdmHashAll (mUseHashAlgo, FileData, FileSize, (UINT8 *)(CertChain + 1));
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

  DigestSize = GetSpdmHashSize (mUseHashAlgo);

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

  SpdmHashAll (mUseHashAlgo, RootCert, RootCertLen, (UINT8 *)(CertChain + 1));
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

  DigestSize = GetSpdmHashSize (mUseHashAlgo);

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

  SpdmHashAll (mUseHashAlgo, RootCert, RootCertLen, (UINT8 *)(CertChain + 1));
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

  DigestSize = GetSpdmHashSize (mUseHashAlgo);

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

  SpdmHashAll (mUseHashAlgo, RootCert, RootCertLen, (UINT8 *)(CertChain + 1));
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
EFIAPI
SpdmRequesterDataSignFunc (
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

  if (AsymAlgo != mUseReqAsymAlgo) {
    return FALSE;
  }
  PrivatePem = mRequesterPrivateCertData;
  PrivatePemSize = mRequesterPrivateCertDataSize;
  Result = SpdmReqAsymGetPrivateKeyFromPem (mUseReqAsymAlgo, PrivatePem, PrivatePemSize, NULL, &Context);
  if (!Result) {
    return FALSE;
  }
  Result = SpdmReqAsymSign (
             mUseReqAsymAlgo,
             Context,
             MessageHash,
             HashSize,
             Signature,
             SigSize
             );
  SpdmReqAsymFree (mUseReqAsymAlgo, Context);

  return Result;
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
  VOID                          *Context;
  VOID                          *PrivatePem;
  UINTN                         PrivatePemSize;
  BOOLEAN                       Result;

  if (AsymAlgo != mUseAsymAlgo) {
    return FALSE;
  }
  PrivatePem = mResponderPrivateCertData;
  PrivatePemSize = mResponderPrivateCertDataSize;
  Result = SpdmAsymGetPrivateKeyFromPem (mUseAsymAlgo, PrivatePem, PrivatePemSize, NULL, &Context);
  if (!Result) {
    return FALSE;
  }
  Result = SpdmAsymSign (
             mUseAsymAlgo,
             Context,
             MessageHash,
             HashSize,
             Signature,
             SigSize
             );
  SpdmAsymFree (mUseAsymAlgo, Context);

  return Result;
}

BOOLEAN
EFIAPI
SpdmMeasurementCollectionFunc (
  IN      UINT8        MeasurementSpecification,
  IN      UINT32       MeasurementHashAlgo,
     OUT  UINT8        *DeviceMeasurementCount,
     OUT  VOID         *DeviceMeasurement,
  IN OUT  UINTN        *DeviceMeasurementSize
  )
{
  SPDM_MEASUREMENT_BLOCK_DMTF  *MeasurementBlock;
  UINTN                        HashSize;
  UINT8                        Index;
  UINT8                        Data[MEASUREMENT_MANIFEST_SIZE];
  UINTN                        TotalSize;

  ASSERT (MeasurementSpecification == SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF);
  ASSERT (MeasurementHashAlgo == mUseMeasurementHashAlgo);

  HashSize = GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo);

  *DeviceMeasurementCount = MEASUREMENT_BLOCK_NUMBER;
  TotalSize = (MEASUREMENT_BLOCK_NUMBER - 1) * (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + HashSize) +
                           (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + sizeof(Data));
  ASSERT (*DeviceMeasurementSize >= TotalSize);
  *DeviceMeasurementSize = TotalSize;

  MeasurementBlock = DeviceMeasurement;
  for (Index = 0; Index < MEASUREMENT_BLOCK_NUMBER; Index++) {
    MeasurementBlock->MeasurementBlockCommonHeader.Index = Index + 1;
    MeasurementBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    if (Index < 4) {
      MeasurementBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType = Index;
      MeasurementBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize = (UINT16)HashSize;
    } else {
      MeasurementBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType = Index | SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
      MeasurementBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize = (UINT16)sizeof(Data);
    }
    MeasurementBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + 
                                                                     MeasurementBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize);
    SetMem (Data, sizeof(Data), (UINT8)(Index + 1));
    if (Index < 4) {
      SpdmMeasurementHashAll (mUseMeasurementHashAlgo, Data, sizeof(Data), (VOID *)(MeasurementBlock + 1));
      MeasurementBlock = (VOID *)((UINT8 *)MeasurementBlock + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + HashSize);
    } else {
      CopyMem ((VOID *)(MeasurementBlock + 1), Data, sizeof(Data));
      break;
    }
  }

  return TRUE;
}

UINT8  mMyZeroFilledBuffer[64];
UINT8  gBinStr0[0x12] = {
       0x00, 0x00, // Length - To be filled
       0x73, 0x70, 0x64, 0x6d, 0x31, 0x2e, 0x31, 0x00, // Version: 'spdm1.1/0'
       0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64, 0x00, // label: 'derived/0'
       };

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

  HashSize = GetSpdmHashSize (HashAlgo);

  Result = SpdmHmacAll (HashAlgo, mMyZeroFilledBuffer, HashSize, Psk, PskSize, HandshakeSecret);
  if (!Result) {
    return Result;
  }

  Result = SpdmHkdfExpand (HashAlgo, HandshakeSecret, HashSize, Info, InfoSize, Out, OutSize);
  ZeroMem (HandshakeSecret, HashSize);

  return Result;
}


/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  The PRK is PSK derived MasterSecret.

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
SpdmPskMasterSecretHkdfExpandFunc (
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
  UINT8                         Salt1[64];
  UINT8                         MasterSecret[64];

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

  HashSize = GetSpdmHashSize (HashAlgo);

  Result = SpdmHmacAll (HashAlgo, mMyZeroFilledBuffer, HashSize, Psk, PskSize, HandshakeSecret);
  if (!Result) {
    return Result;
  }

  *(UINT16 *)gBinStr0 = (UINT16)HashSize;
  Result = SpdmHkdfExpand (HashAlgo, HandshakeSecret, HashSize, gBinStr0, sizeof(gBinStr0), Salt1, HashSize);
  ZeroMem (HandshakeSecret, HashSize);
  if (!Result) {
    return Result;
  }

  Result = SpdmHmacAll (HashAlgo, Salt1, HashSize, mMyZeroFilledBuffer, HashSize, MasterSecret);
  ZeroMem (Salt1, HashSize);
  if (!Result) {
    return Result;
  }

  Result = SpdmHkdfExpand (HashAlgo, MasterSecret, HashSize, Info, InfoSize, Out, OutSize);
  ZeroMem (MasterSecret, HashSize);

  return Result;
}
