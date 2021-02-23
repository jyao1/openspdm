/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

SPDM_CHALLENGE_REQUEST    mSpdmChallengeRequest1 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_CHALLENGE,
    0,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH
  },
};
UINTN mSpdmChallengeRequest1Size = sizeof(mSpdmChallengeRequest1);

SPDM_CHALLENGE_REQUEST    mSpdmChallengeRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_CHALLENGE,
    0,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH
  },
};
UINTN mSpdmChallengeRequest2Size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

void TestSpdmResponderChallengeAuthCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CHALLENGE_AUTH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest1Size, &mSpdmChallengeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + GetSpdmHashSize (mUseHashAlgo) + SPDM_NONCE_SIZE + 0 + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CHALLENGE_AUTH);
  assert_int_equal (SpdmResponse->Header.Param1, 0);
  assert_int_equal (SpdmResponse->Header.Param2, 1 << 0);
  free(Data1);
}

void TestSpdmResponderChallengeAuthCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CHALLENGE_AUTH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest2.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest2Size, &mSpdmChallengeRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data1);
}

void TestSpdmResponderChallengeAuthCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CHALLENGE_AUTH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest1Size, &mSpdmChallengeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
  free(Data1);
}

void TestSpdmResponderChallengeAuthCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CHALLENGE_AUTH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest1Size, &mSpdmChallengeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
  free(Data1);
}

void TestSpdmResponderChallengeAuthCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CHALLENGE_AUTH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest1Size, &mSpdmChallengeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(SpdmResponse + 1);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_CHALLENGE);
  free(Data1);
}

void TestSpdmResponderChallengeAuthCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CHALLENGE_AUTH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ResponseState = SpdmResponseStateNormal;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest1Size, &mSpdmChallengeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data1);
}

SPDM_TEST_CONTEXT       mSpdmResponderChallengeAuthTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderChallengeAuthTestMain(void) {
  const struct CMUnitTest SpdmResponderChallengeAuthTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase1),
    // Bad Request Size
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase5),
    // ConnectionState Check
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase6),
  };

  SetupSpdmTestContext (&mSpdmResponderChallengeAuthTestContext);

  return cmocka_run_group_tests(SpdmResponderChallengeAuthTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
