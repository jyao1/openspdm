/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitFuzzing.h"
#include "ToolChainHarness.h"
#include <SpdmRequesterLibInternal.h>

UINTN
EFIAPI
GetMaxBufferSize (
  VOID
  )
{
  return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

RETURN_STATUS
EFIAPI
SpdmRequesterGetVersionTestSendRequest (
  IN     SPDM_IO_PROTOCOL        *This,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  )
{
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmRequesterGetVersionTestReceiveResponse (
  IN     SPDM_IO_PROTOCOL        *This,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = SPDM_TEST_CONTEXT_FROM_SPDM_PROTOCOL(This);
        
  *ResponseSize = SpdmTestContext->TestBufferSize;
  *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
  CopyMem (Response, SpdmTestContext->TestBuffer, SpdmTestContext->TestBufferSize);

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmRequesterGetVersionTestSecureSendRequest (
  IN     SPDM_IO_PROTOCOL                       *This,
  IN     UINT32                                 SessionId,
  IN     UINTN                                  RequestSize,
  IN     VOID                                   *Request,
  IN     UINT64                                 Timeout
  )
{
  return RETURN_UNSUPPORTED;
}

RETURN_STATUS
EFIAPI
SpdmRequesterGetVersionTestSecureReceiveResponse (
  IN     SPDM_IO_PROTOCOL                       *This,
  IN     UINT32                                 SessionId,
  IN OUT UINTN                                  *ResponseSize,
  IN OUT VOID                                   *Response,
  IN     UINT64                                 Timeout
  )
{
  return RETURN_UNSUPPORTED;
}

VOID TestSpdmRequesterGetVersion (VOID **State) {
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmTestContext = *State;
  SpdmContext = &SpdmTestContext->SpdmContext;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
}

SPDM_TEST_CONTEXT       mSpdmRequesterGetVersionTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  {
    SpdmRequesterGetVersionTestSendRequest,
    SpdmRequesterGetVersionTestReceiveResponse,
    SpdmRequesterGetVersionTestSecureSendRequest,
    SpdmRequesterGetVersionTestSecureReceiveResponse,
    SpdmIoSecureMessagingTypeDmtfMtcp,
    sizeof(UINT32)
  },
};

VOID
EFIAPI
RunTestHarness(
  IN VOID  *TestBuffer,
  IN UINTN TestBufferSize
  )
{
  VOID  *State;

  SetupSpdmTestContext (&mSpdmRequesterGetVersionTestContext);

  mSpdmRequesterGetVersionTestContext.TestBuffer = TestBuffer;
  mSpdmRequesterGetVersionTestContext.TestBufferSize = TestBufferSize;

  TestSpdmRequesterGroupSetup (&State);

  TestSpdmRequesterGetVersion (&State);

  TestSpdmRequesterGroupTeardown (&State);
}

