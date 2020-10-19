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
  VOID                 *Data2;
  UINTN                DataSize2;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
  ReadResponderPublicCertificateChain (&Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data1;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.SpdmDataSignFunc = SpdmDataSignFunc;
  ReadResponderPrivateCertificate (&Data2, &DataSize2);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest1Size, &mSpdmChallengeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + GetSpdmHashSize(SpdmContext) + SPDM_NONCE_SIZE + GetSpdmHashSize(SpdmContext) + sizeof(UINT16) + 0 + GetSpdmAsymSize (SpdmContext));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CHALLENGE_AUTH);
  assert_int_equal (SpdmResponse->Header.Param1, 0);
  assert_int_equal (SpdmResponse->Header.Param2, 1 << 0);
  free(Data1);
  free(Data2);
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
  VOID                 *Data2;
  UINTN                DataSize2;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
  ReadResponderPublicCertificateChain (&Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data1;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.SpdmDataSignFunc = SpdmDataSignFunc;
  ReadResponderPrivateCertificate (&Data2, &DataSize2);

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
  free(Data2);
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
  VOID                 *Data2;
  UINTN                DataSize2;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
  ReadResponderPublicCertificateChain (&Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data1;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.SpdmDataSignFunc = SpdmDataSignFunc;
  ReadResponderPrivateCertificate (&Data2, &DataSize2);

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
  free(Data2);
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
  VOID                 *Data2;
  UINTN                DataSize2;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
  ReadResponderPublicCertificateChain (&Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data1;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.SpdmDataSignFunc = SpdmDataSignFunc;
  ReadResponderPrivateCertificate (&Data2, &DataSize2);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest1Size, &mSpdmChallengeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
  free(Data1);
  free(Data2);
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
  VOID                 *Data2;
  UINTN                DataSize2;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
  ReadResponderPublicCertificateChain (&Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data1;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.SpdmDataSignFunc = SpdmDataSignFunc;
  ReadResponderPrivateCertificate (&Data2, &DataSize2);

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
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
  assert_int_equal (ErrorData->RequestCode, SPDM_CHALLENGE);
  free(Data1);
  free(Data2);
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
  VOID                 *Data2;
  UINTN                DataSize2;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
  ReadResponderPublicCertificateChain (&Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data1;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.SpdmDataSignFunc = SpdmDataSignFunc;
  ReadResponderPrivateCertificate (&Data2, &DataSize2);

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
  free(Data2);
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
    // SpdmCmdReceiveState Check
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase6),
  };

  SetupSpdmTestContext (&mSpdmResponderChallengeAuthTestContext);

  return cmocka_run_group_tests(SpdmResponderChallengeAuthTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
