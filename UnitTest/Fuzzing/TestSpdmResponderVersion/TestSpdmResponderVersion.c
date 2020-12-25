/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitFuzzing.h"
#include "ToolChainHarness.h"
#include <SpdmResponderLibInternal.h>

UINTN
EFIAPI
GetMaxBufferSize (
  VOID
  )
{
  return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

VOID TestSpdmResponderVersion(VOID **State) {
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];

  SpdmTestContext = *State;
  SpdmContext = SpdmTestContext->SpdmContext;

  ResponseSize = sizeof(Response);
  SpdmGetResponseVersion (SpdmContext, SpdmTestContext->TestBufferSize, SpdmTestContext->TestBuffer, &ResponseSize, Response);
}

SPDM_TEST_CONTEXT       mSpdmResponderVersionTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

VOID
EFIAPI
RunTestHarness(
  IN VOID  *TestBuffer,
  IN UINTN TestBufferSize
  )
{
  VOID  *State;

  SetupSpdmTestContext (&mSpdmResponderVersionTestContext);

  mSpdmResponderVersionTestContext.TestBuffer = TestBuffer;
  mSpdmResponderVersionTestContext.TestBufferSize = TestBufferSize;

  SpdmUnitTestGroupSetup (&State);

  TestSpdmResponderVersion (&State);

  SpdmUnitTestGroupTeardown (&State);
}

