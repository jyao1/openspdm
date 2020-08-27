/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"

SPDM_TEST_CONTEXT             *mSpdmTestContext;

RETURN_STATUS
EFIAPI
SpdmDeviceSendMessage (
  IN     UINT32                  *SessionId,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  )
{
  if (mSpdmTestContext->SpdmDeviceSendMessage == NULL) {
    return RETURN_UNSUPPORTED;
  }
  return mSpdmTestContext->SpdmDeviceSendMessage (SessionId, RequestSize, Request, Timeout);
}

RETURN_STATUS
EFIAPI
SpdmDeviceReceiveMessage (
     OUT UINT32                  **SessionId,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response,
  IN     UINT64                  Timeout
  )
{
  if (mSpdmTestContext->SpdmDeviceReceiveMessage == NULL) {
    return RETURN_UNSUPPORTED;
  }
  return mSpdmTestContext->SpdmDeviceReceiveMessage (SessionId, ResponseSize, Response, Timeout);
}

SPDM_TEST_CONTEXT *
GetSpdmTestContext (
  VOID
  )
{
  return mSpdmTestContext;
}

VOID
SetupSpdmTestContext (
  IN SPDM_TEST_CONTEXT             *SpdmTestContext
  )
{
  mSpdmTestContext          = SpdmTestContext;
}

int SpdmUnitTestGroupSetup(void **state)
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;
  SPDM_DEVICE_CONTEXT     *SpdmContext;

  SpdmTestContext = mSpdmTestContext;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xFFFFFFFF;

  SpdmInitContext (SpdmContext);

  *state = SpdmTestContext;
  return 0;
}

int SpdmUnitTestGroupTeardown(void **state)
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = *state;
  SpdmTestContext->CaseId = 0xFFFFFFFF;
  return 0;
}
