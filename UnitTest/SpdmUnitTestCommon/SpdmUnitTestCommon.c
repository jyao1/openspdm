/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"

SPDM_TEST_CONTEXT             *mSpdmTestContext;

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
  mSpdmTestContext = SpdmTestContext;
}

int SpdmUnitTestGroupSetup(void **state)
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;
  SPDM_DEVICE_CONTEXT     *SpdmContext;

  SpdmTestContext = mSpdmTestContext;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xFFFFFFFF;

  SpdmInitContext (SpdmContext);
  SpdmRegisterDeviceIoFunc (SpdmContext, SpdmTestContext->SendMessage, SpdmTestContext->ReceiveMessage);

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
