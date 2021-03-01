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
  VOID                    *SpdmContext;

  SpdmTestContext = mSpdmTestContext;
  SpdmTestContext->SpdmContext = (VOID *)malloc (SpdmGetContextSize());
  if (SpdmTestContext->SpdmContext == NULL) {
    return -1;
  }
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xFFFFFFFF;

  SpdmInitContext (SpdmContext);
  SpdmRegisterDeviceIoFunc (SpdmContext, SpdmTestContext->SendMessage, SpdmTestContext->ReceiveMessage);
  SpdmRegisterTransportLayerFunc (SpdmContext, SpdmTransportTestEncodeMessage, SpdmTransportTestDecodeMessage);

  *state = SpdmTestContext;
  return 0;
}

int SpdmUnitTestGroupTeardown(void **state)
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = *state;
  free (SpdmTestContext->SpdmContext);
  SpdmTestContext->SpdmContext = NULL;
  SpdmTestContext->CaseId = 0xFFFFFFFF;
  return 0;
}
