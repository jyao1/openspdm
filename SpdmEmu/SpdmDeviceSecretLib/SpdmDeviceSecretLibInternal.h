/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_DEVICE_SECRET_LIB_INTERNAL_H__
#define __SPDM_DEVICE_SECRET_LIB_INTERNAL_H__

#include <Library/SpdmDeviceSecretLib.h>

#define MEASUREMENT_BLOCK_NUMBER   5
#define MEASUREMENT_MANIFEST_SIZE  128

#define TEST_PSK_DATA_STRING  "TestPskData"
#define TEST_PSK_HINT_STRING  "TestPskHint"

#define TEST_CERT_MAXINT16  1
#define TEST_CERT_MAXUINT16 2
#define TEST_CERT_MAXUINT16_LARGER 3
#define TEST_CERT_SMALL 4

//
// Public Cert
//
BOOLEAN
ReadResponderPublicCertificateChain (
  IN  UINT32  BaseHashAlgo,
  IN  UINT32  BaseAsymAlgo,
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

BOOLEAN
ReadRequesterPublicCertificateChain (
  IN  UINT32  BaseHashAlgo,
  IN  UINT16  ReqBaseAsymAlg,
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

BOOLEAN
ReadResponderRootPublicCertificate (
  IN  UINT32  BaseHashAlgo,
  IN  UINT32  BaseAsymAlgo,
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

BOOLEAN
ReadRequesterRootPublicCertificate (
  IN  UINT32  BaseHashAlgo,
  IN  UINT16  ReqBaseAsymAlg,
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

BOOLEAN
ReadResponderPublicCertificateChainBySize (
  IN  UINT32  BaseHashAlgo,
  IN  UINT32  BaseAsymAlgo,
  IN  UINT16  CertId,
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

BOOLEAN
ReadResponderRootPublicCertificateBySize (
  IN  UINT32  BaseHashAlgo,
  IN  UINT32  BaseAsymAlgo,
  IN  UINT16  CertId,
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

//
// External
//
BOOLEAN
ReadInputFile (
  IN CHAR8    *FileName,
  OUT VOID    **FileData,
  OUT UINTN   *FileSize
  );

VOID
DumpHexStr (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  );

#endif
