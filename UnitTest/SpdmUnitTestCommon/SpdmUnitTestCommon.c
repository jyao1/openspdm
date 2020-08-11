/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"

extern SPDM_TEST_CONTEXT       mSpdmTestContext;

int TestSpdmRequesterGroupSetup(void **state)
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;
  SPDM_DEVICE_CONTEXT     *SpdmContext;
  UINT32                  Data32;
  SPDM_DATA_PARAMETER     Parameter;

  SpdmTestContext = &mSpdmTestContext;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xFFFFFFFF;

  SpdmInitContext (SpdmContext);
  if (SpdmTestContext->IsRequester) {
    SpdmRegisterSpdmIo (SpdmContext, &SpdmTestContext->SpdmProtocol);
  } else {
    ZeroMem (&Parameter, sizeof(Parameter));
    Data32 = SpdmTestContext->SpdmProtocol.Alignment;
    SpdmSetData (SpdmContext, SpdmDataIoSizeAlignment, &Parameter, &Data32, sizeof(Data32));
    Data32 = (UINT32)SpdmTestContext->SpdmProtocol.SecureMessageType;
    SpdmSetData (SpdmContext, SpdmDataIoSecureMessageType, &Parameter, &Data32, sizeof(Data32));
  }

  *state = SpdmTestContext;
  return 0;
}

int TestSpdmRequesterGroupTeardown(void **state)
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = *state;
  SpdmTestContext->CaseId = 0xFFFFFFFF;
  return 0;
}
