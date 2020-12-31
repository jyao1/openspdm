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
#include <string.h>

#undef NULL
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SpdmRequesterLib.h>
#include <Library/SpdmResponderLib.h>
#include <Library/SpdmTransportTestLib.h>
#include <SpdmCommonLibInternal.h>
#include <SpdmDeviceSecretLibInternal.h>

extern UINT8   mUseMeasurementSpec;
extern UINT32  mUseMeasurementHashAlgo;
extern UINT32  mUseHashAlgo;
extern UINT32  mUseAsymAlgo;
extern UINT16  mUseReqAsymAlgo;
extern UINT16  mUseDheAlgo;
extern UINT16  mUseAeadAlgo;
extern UINT16  mUseKeyScheduleAlgo;

#define SPDM_TEST_CONTEXT_SIGNATURE  SIGNATURE_32 ('S', 'T', 'C', 'S')

typedef struct {
  UINT32                            Signature;
  BOOLEAN                           IsRequester;
  SPDM_DEVICE_SEND_MESSAGE_FUNC     SendMessage;
  SPDM_DEVICE_RECEIVE_MESSAGE_FUNC  ReceiveMessage;
  VOID                              *SpdmContext;
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

VOID
DumpHexStr (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  );

VOID
DumpData (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  );

VOID
DumpHex (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  );

BOOLEAN
ReadInputFile (
  IN CHAR8    *FileName,
  OUT VOID    **FileData,
  OUT UINTN   *FileSize
  );

#endif
