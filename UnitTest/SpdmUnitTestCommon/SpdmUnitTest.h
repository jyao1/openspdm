/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_UNIT_TEST_H__
#define __SPDM_UNIT_TEST_H__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#undef NULL
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SpdmRequesterLib.h>
#include <Library/SpdmResponderLib.h>
#include <Library/SpdmTransportTestLib.h>
#include <SpdmCommonLibInternal.h>

//#define USE_ASYM_ALGO  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
//#define USE_ASYM_ALGO  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048
#define USE_ASYM_ALGO  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256

#define USE_HASH_ALGO  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256

#define USE_MEASUREMENT_HASH_ALGO  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256

//#define USE_DHE_ALGO   SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048
#define USE_DHE_ALGO   SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1

#define USE_AEAD_ALGO  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM
//#define USE_AEAD_ALGO  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305

#define USE_REQ_ASYM_ALGO  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048
//#define USE_REQ_ASYM_ALGO  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048
//#define USE_REQ_ASYM_ALGO  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256

#define SPDM_TEST_CONTEXT_SIGNATURE  SIGNATURE_32 ('S', 'T', 'C', 'S')

typedef struct {
  UINT32                            Signature;
  BOOLEAN                           IsRequester;
  SPDM_DEVICE_SEND_MESSAGE_FUNC     SendMessage;
  SPDM_DEVICE_RECEIVE_MESSAGE_FUNC  ReceiveMessage;
  SPDM_DEVICE_CONTEXT               SpdmContext;
  UINT32                            CaseId;
} SPDM_TEST_CONTEXT;

#define SPDM_TEST_CONTEXT_FROM_SPDM_PROTOCOL(a)  BASE_CR (a, SPDM_TEST_CONTEXT, SpdmProtocol)
#define SPDM_TEST_CONTEXT_FROM_SPDM_CONTEXT(a)   BASE_CR (a, SPDM_TEST_CONTEXT, SpdmContext)

int SpdmUnitTestGroupSetup(void **state);

int SpdmUnitTestGroupTeardown(void **state);

VOID
SetupSpdmTestContext (
  IN SPDM_TEST_CONTEXT             *SpdmTestContext
  );

SPDM_TEST_CONTEXT *
GetSpdmTestContext (
  VOID
  );

BOOLEAN
ReadInputFile (
  IN CHAR8    *FileName,
  OUT VOID    **FileData,
  OUT UINTN   *FileSize
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

BOOLEAN
TestSpdmAsymGetPrivateKeyFromPem (
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *PemData,
  IN      UINTN        PemSize,
  IN      CONST CHAR8  *Password,
  OUT     VOID         **Context
  );

BOOLEAN
TestSpdmAsymSign (
  IN      UINT32       AsymAlgo,
  IN      VOID         *Context,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

VOID
TestSpdmAsymFree (
  IN      UINT32       AsymAlgo,
  IN      VOID         *Context
  );

BOOLEAN
EFIAPI
SpdmRequesterDataSignFunc (
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

BOOLEAN
EFIAPI
SpdmResponderDataSignFunc (
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

#endif