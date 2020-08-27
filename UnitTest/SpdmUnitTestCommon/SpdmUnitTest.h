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

#undef NULL
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SpdmRequesterLib.h>
#include <Library/SpdmResponderLib.h>
#include <SpdmCommonLibInternal.h>

#define SPDM_TEST_CONTEXT_SIGNATURE  SIGNATURE_32 ('S', 'T', 'C', 'S')

typedef
RETURN_STATUS
(EFIAPI *SPDM_DEVICE_SEND_MESSAGE) (
  IN     UINT32                  *SessionId,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  );

typedef
RETURN_STATUS
(EFIAPI *SPDM_DEVICE_RECEIVE_MESSAGE) (
     OUT UINT32                  **SessionId,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response,
  IN     UINT64                  Timeout
  );

typedef struct {
  UINT32                        Signature;
  BOOLEAN                       IsRequester;
  SPDM_DEVICE_SEND_MESSAGE      SpdmDeviceSendMessage;
  SPDM_DEVICE_RECEIVE_MESSAGE   SpdmDeviceReceiveMessage;
  SPDM_DEVICE_CONTEXT           SpdmContext;
  UINT32                        CaseId;
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

#endif