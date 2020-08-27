/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest1 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_CAPABILITIES,
  },
};
UINTN mSpdmGetCapabilityRequest1Size = sizeof(mSpdmGetCapabilityRequest1);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_CAPABILITIES,
  },
};
UINTN mSpdmGetCapabilityRequest2Size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

void TestSpdmResponderCapabilityCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest1Size, &mSpdmGetCapabilityRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CAPABILITIES_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CAPABILITIES);
}

void TestSpdmResponderCapabilityCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest2Size, &mSpdmGetCapabilityRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest1Size, &mSpdmGetCapabilityRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
}

void TestSpdmResponderCapabilityCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest1Size, &mSpdmGetCapabilityRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
}

void TestSpdmResponderCapabilityCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest1Size, &mSpdmGetCapabilityRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(&SpdmResponse->Reserved);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
  assert_int_equal (ErrorData->RequestCode, SPDM_GET_CAPABILITIES);
}

void TestSpdmResponderCapabilityCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState = 0;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest1Size, &mSpdmGetCapabilityRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

SPDM_TEST_CONTEXT       mSpdmResponderCapabilityTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderCapabilityTestMain(void) {
  const struct CMUnitTest SpdmResponderCapabilityTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderCapabilityCase1),
    // Bad Request Size
    cmocka_unit_test(TestSpdmResponderCapabilityCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderCapabilityCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderCapabilityCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderCapabilityCase5),
    // SpdmCmdReceiveState Check
    cmocka_unit_test(TestSpdmResponderCapabilityCase6),
  };

  SetupSpdmTestContext (&mSpdmResponderCapabilityTestContext);

  return cmocka_run_group_tests(SpdmResponderCapabilityTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
