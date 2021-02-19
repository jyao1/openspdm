/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

SPDM_NEGOTIATE_ALGORITHMS_REQUEST    mSpdmNegotiateAlgorithmRequest1 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_NEGOTIATE_ALGORITHMS,
    0,
    0
  },
  sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST),
  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};
UINTN mSpdmNegotiateAlgorithmRequest1Size = sizeof(mSpdmNegotiateAlgorithmRequest1);

SPDM_NEGOTIATE_ALGORITHMS_REQUEST    mSpdmNegotiateAlgorithmRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_NEGOTIATE_ALGORITHMS,
    0,
    0
  },
  sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST),
  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};
UINTN mSpdmNegotiateAlgorithmRequest2Size = sizeof(SPDM_MESSAGE_HEADER);

void TestSpdmResponderAlgorithmCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;  
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ALGORITHMS_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ALGORITHMS);
}

void TestSpdmResponderAlgorithmCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest2Size, &mSpdmNegotiateAlgorithmRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderAlgorithmCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
}

void TestSpdmResponderAlgorithmCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
}

void TestSpdmResponderAlgorithmCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(&SpdmResponse->Length);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_NEGOTIATE_ALGORITHMS);
}

void TestSpdmResponderAlgorithmCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_ALGORITHMS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ResponseState = SpdmResponseStateNormal;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

SPDM_TEST_CONTEXT       mSpdmResponderAlgorithmTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderAlgorithmTestMain(void) {
  const struct CMUnitTest SpdmResponderAlgorithmTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderAlgorithmCase1),
    // Bad Request Size
    cmocka_unit_test(TestSpdmResponderAlgorithmCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderAlgorithmCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderAlgorithmCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderAlgorithmCase5),
    // ConnectionState Check
    cmocka_unit_test(TestSpdmResponderAlgorithmCase6),
  };

  mSpdmNegotiateAlgorithmRequest1.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest1.BaseHashAlgo = mUseHashAlgo;
  mSpdmNegotiateAlgorithmRequest2.BaseAsymAlgo = mUseAsymAlgo;
  mSpdmNegotiateAlgorithmRequest2.BaseHashAlgo = mUseHashAlgo;

  SetupSpdmTestContext (&mSpdmResponderAlgorithmTestContext);

  return cmocka_run_group_tests(SpdmResponderAlgorithmTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
