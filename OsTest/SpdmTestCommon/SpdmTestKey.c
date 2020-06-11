/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmTest.h"

#define SHA256_HASH_SIZE  32

BOOLEAN
EFIAPI
Sha256HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  );

BOOLEAN
ReadPrivateCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size
  )
{
  BOOLEAN  Res;

  switch (USE_ASYM_ALGO) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    Res = ReadInputFile ("TestRoot.key", Data, Size);
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    Res = ReadInputFile ("EccTestRoot.key", Data, Size);
    break;
  default:
    assert (0);
    break;
  }
  return Res;
}

BOOLEAN
ReadPublicCertificateChain (
  OUT VOID    **Data,
  OUT UINTN   *Size
  )
{
  BOOLEAN             Res;
  VOID                *FileData;
  UINTN               FileSize;
  SPDM_CERT_CHAIN     *CertChain;
  UINTN               CertChainSize;
  
  switch (USE_ASYM_ALGO) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    Res = ReadInputFile ("TestRoot.cer", &FileData, &FileSize);
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    Res = ReadInputFile ("EccTestRoot.cer", &FileData, &FileSize);
    break;
  default:
    assert (0);
    break;
  }
  if (!Res) {
    return Res;
  }

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE + FileSize;
  CertChain = (VOID *)malloc (CertChainSize);
  if (CertChain == NULL) {
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

  return TRUE;
}
