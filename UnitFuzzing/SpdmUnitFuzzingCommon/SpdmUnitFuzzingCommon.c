/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitFuzzing.h"

SPDM_TEST_CONTEXT       *mSpdmTestContext;

SPDM_TEST_CONTEXT *
GetSpdmTestContext (
  VOID
  )
{
  return mSpdmTestContext;
}

VOID
SetupSpdmTestContext (
  IN SPDM_TEST_CONTEXT       *SpdmTestContext
  )
{
  mSpdmTestContext = SpdmTestContext;
}

UINTN SpdmUnitTestGroupSetup(VOID **State)
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;
  SPDM_DEVICE_CONTEXT     *SpdmContext;

  SpdmTestContext = mSpdmTestContext;
  SpdmContext = &SpdmTestContext->SpdmContext;

  SpdmInitContext (SpdmContext);
  SpdmRegisterDeviceIoFunc (SpdmContext, SpdmTestContext->SendMessage, SpdmTestContext->ReceiveMessage);
  SpdmRegisterTransportLayerFunc (SpdmContext, SpdmTransportTestEncodeMessage, SpdmTransportTestDecodeMessage);

  *State = SpdmTestContext;
  return 0;
}

UINTN SpdmUnitTestGroupTeardown(VOID **State)
{
  return 0;
}
