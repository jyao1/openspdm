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
  IN VOID  *Data,
  IN UINTN DataSize,
  OUT VOID *Hash
  );

BOOLEAN
ReadPrivateCertificate (
  OUT UINT8   **Data,
  OUT UINTN   *Size
  )
{
  BOOLEAN  Res;
  Res = ReadInputFile ("TestRoot.key", Data, Size);
  return Res;
}

BOOLEAN
ReadPublicCertificateChain (
  OUT UINT8   **Data,
  OUT UINTN   *Size
  )
{
  BOOLEAN             Res;
  UINT8               *FileData;
  UINTN               FileSize;
  SPDM_CERT_CHAIN     *CertChain;
  UINTN               CertChainSize;
  
  Res = ReadInputFile ("TestRoot.cer", &FileData, &FileSize);
  if (!Res) {
    return Res;
  }

  CertChainSize = sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE + FileSize;
  CertChain = malloc (CertChainSize);
  if (CertChain == NULL) {
    return FALSE;
  }
  CertChain->Length = (UINT16)CertChainSize;
  CertChain->Reserved = 0;
  Sha256HashAll (FileData, FileSize, (VOID *)(CertChain + 1));
  CopyMem (
    (UINT8 *)CertChain + sizeof(SPDM_CERT_CHAIN) + SHA256_HASH_SIZE,
    FileData,
    FileSize
    );

  *Data = CertChain;
  *Size = CertChainSize;

  return TRUE;
}
