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
  0,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
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
  0,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseAlgorithm (SpdmContext, mSpdmNegotiateAlgorithmRequest1Size, &mSpdmNegotiateAlgorithmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(&SpdmResponse->Length);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState = 0;

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
    // SpdmCmdReceiveState Check
    cmocka_unit_test(TestSpdmResponderAlgorithmCase6),
  };

  SetupSpdmTestContext (&mSpdmResponderAlgorithmTestContext);

  return cmocka_run_group_tests(SpdmResponderAlgorithmTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
