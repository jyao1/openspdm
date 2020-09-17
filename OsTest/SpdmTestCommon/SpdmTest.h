/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_TEST_H__
#define __SPDM_TEST_H__

#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SpdmCommonLib.h>

#include "OsInclude.h"
#include "stdio.h"
#include "assert.h"
#include "SpdmTestCommand.h"

//#define USE_ASYM_ALGO  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
#define USE_ASYM_ALGO  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
#define USE_HASH_ALGO  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256
//#define USE_DHE_ALGO   SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
#define USE_DHE_ALGO   SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1
#define USE_AEAD_ALGO  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
//#define USE_AEAD_ALGO  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305
#define USE_REQ_ASYM_ALGO  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
//#define USE_REQ_ASYM_ALGO  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256

#define DEFAULT_OPAQUE_LENGTH             16
#define DEFAULT_OPAQUE_DATA               0xCC

VOID
DumpData (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  );

BOOLEAN
SendPlatformData (
  IN SOCKET           Socket,
  IN UINT32           Command,
  IN UINT32           Session,
  IN UINT8            *SendBuffer,
  IN UINTN            BytesToSend
  );

BOOLEAN
ReceivePlatformData (
  IN  SOCKET           Socket,
  OUT UINT32           *Command,
  OUT UINT32           *Session,
  OUT UINT8            *ReceiveBuffer,
  IN OUT UINTN         *BytesToReceive
  );

BOOLEAN
ReadInputFile (
  IN CHAR8    *FileName,
  OUT VOID    **FileData,
  OUT UINTN   *FileSize
  );

BOOLEAN
WriteOutputFile (
  IN CHAR8   *FileName,
  IN VOID    *FileData,
  IN UINTN   FileSize
  );

BOOLEAN
ReadResponderPrivateCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size
  );

BOOLEAN
ReadRequesterPrivateCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size
  );

BOOLEAN
ReadResponderPublicCertificateChain (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

BOOLEAN
ReadRequesterPublicCertificateChain (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

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
  );

BOOLEAN
ReadResponderRootPublicCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
 );

BOOLEAN
ReadRequesterRootPublicCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
 );

#endif