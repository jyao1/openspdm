/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmTest.h"

#define SHA256_HASH_SIZE  32

typedef
BOOLEAN
(EFIAPI *ASYM_GET_PRIVATE_KEY_FROM_PEM) (
  IN   CONST UINT8  *PemData,
  IN   UINTN        PemSize,
  IN   CONST CHAR8  *Password,
  OUT  VOID         **Context
  );

typedef
VOID
(EFIAPI *ASYM_FREE) (
  IN  VOID         *Context
  );

typedef
BOOLEAN
(EFIAPI *ASYM_SIGN) (
  IN      VOID         *Context,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

BOOLEAN
EFIAPI
Sha256HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  );

VOID  *mResponderPrivateCertData;
UINTN mResponderPrivateCertDataSize;

VOID  *mRequesterPrivateCertData;
UINTN mRequesterPrivateCertDataSize;

BOOLEAN
ReadResponderPrivateCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size
  )
{
  BOOLEAN  Res;
  CHAR8    *File;

  switch (USE_ASYM_ALGO) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    File = "Rsa2048/end_responder.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    File = "Rsa3072/end_responder.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/end_responder.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/end_responder.key";
    break;
  default:
    assert (0);
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

  switch (USE_REQ_ASYM_ALGO) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    File = "Rsa2048/end_requester.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    File = "Rsa3072/end_requester.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/end_requester.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/end_requester.key";
    break;
  default:
    assert (0);
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

  switch (USE_ASYM_ALGO) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    File = "Rsa2048/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    File = "Rsa3072/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/ca.cert.der";
    break;
  default:
    assert (0);
    return FALSE;
  }
  Res = ReadInputFile (File, &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;

  Sha256HashAll (FileData, FileSize, (UINT8 *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;
  if (Hash != NULL) {
    *Hash = (CertChain + 1);
  }
  if (HashSize != NULL) {
    *HashSize = SHA256_HASH_SIZE;
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

  switch (USE_REQ_ASYM_ALGO) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    File = "Rsa2048/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    File = "Rsa3072/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/ca.cert.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/ca.cert.der";
    break;
  default:
    assert (0);
    return FALSE;
  }

  Res = ReadInputFile (File, &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;
  Sha256HashAll (FileData, FileSize, (UINT8 *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;
  if (Hash != NULL) {
    *Hash = (CertChain + 1);
  }
  if (HashSize != NULL) {
    *HashSize = SHA256_HASH_SIZE;
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
  UINTN                RootCertLen;

  switch (USE_ASYM_ALGO) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    File = "Rsa2048/bundle_responder.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    File = "Rsa3072/bundle_responder.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/bundle_responder.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/bundle_responder.certchain.der";
    break;
  default:
    assert (0);
    return FALSE;
  }
  Res = ReadInputFile (File, &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;

  //
  // Get Root Certificate and calculate hash value
  //
  Res = X509GetCertFromCertChain(FileData, FileSize, 0, &RootCert, &RootCertLen);
  if (!Res) {
    free (FileData);
    free (CertChain);
    return Res;
  }

  Sha256HashAll (RootCert, RootCertLen, (UINT8 *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;
  if (Hash != NULL) {
    *Hash = (CertChain + 1);
  }
  if (HashSize != NULL) {
    *HashSize = SHA256_HASH_SIZE;
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

  switch (USE_REQ_ASYM_ALGO) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    File = "Rsa2048/bundle_requester.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    File = "Rsa3072/bundle_requester.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/bundle_requester.certchain.der";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/bundle_requester.certchain.der";
    break;
  default:
    assert (0);
    return FALSE;
  }
  Res = ReadInputFile (File, &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
    free (FileData);
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;

  //
  // Get Root Certificate and calculate hash value
  //
  Res = X509GetCertFromCertChain(FileData, FileSize, 0, &RootCert, &RootCertLen);
  if (!Res) {
    free (FileData);
    free (CertChain);
    return Res;
  }

  Sha256HashAll (RootCert, RootCertLen, (UINT8 *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;
  if (Hash != NULL) {
    *Hash = (CertChain + 1);
  }
  if (HashSize != NULL) {
    *HashSize = SHA256_HASH_SIZE;
  }

  free (FileData);
  return TRUE;
}

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

BOOLEAN
EFIAPI
SpdmDataSignFunc (
  IN      VOID         *SpdmContext,
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
    if (AsymAlgo != USE_ASYM_ALGO) {
      return FALSE;
    }
  } else {
    if (AsymAlgo != USE_REQ_ASYM_ALGO) {
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
