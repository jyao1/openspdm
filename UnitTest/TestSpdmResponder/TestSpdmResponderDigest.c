/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

SPDM_GET_DIGESTS_REQUEST    mSpdmGetDigestRequest1 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_DIGESTS,
  },
};
UINTN mSpdmGetDigestRequest1Size = sizeof(mSpdmGetDigestRequest1);

SPDM_GET_DIGESTS_REQUEST    mSpdmGetDigestRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_DIGESTS,
  },
};
UINTN mSpdmGetDigestRequest2Size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

STATIC UINT8                  LocalCertificateChain[MAX_SPDM_MESSAGE_BUFFER_SIZE];

void TestSpdmResponderDigestCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseDigest (SpdmContext, mSpdmGetDigestRequest1Size, &mSpdmGetDigestRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_DIGESTS_RESPONSE) + 32);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_DIGESTS);
}

void TestSpdmResponderDigestCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseDigest (SpdmContext, mSpdmGetDigestRequest2Size, &mSpdmGetDigestRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderDigestCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseDigest (SpdmContext, mSpdmGetDigestRequest1Size, &mSpdmGetDigestRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
}

void TestSpdmResponderDigestCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseDigest (SpdmContext, mSpdmGetDigestRequest1Size, &mSpdmGetDigestRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
}

void TestSpdmResponderDigestCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseDigest (SpdmContext, mSpdmGetDigestRequest1Size, &mSpdmGetDigestRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(SpdmResponse + 1);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
  assert_int_equal (ErrorData->RequestCode, SPDM_GET_DIGESTS);
}

void TestSpdmResponderDigestCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseDigest (SpdmContext, mSpdmGetDigestRequest1Size, &mSpdmGetDigestRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderDigestCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  SpdmContext->Transcript.MessageB.BufferSize = SpdmContext->Transcript.MessageB.MaxBufferSize;
  Status = SpdmGetResponseDigest (SpdmContext, mSpdmGetDigestRequest1Size, &mSpdmGetDigestRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderDigestCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  SpdmContext->Transcript.MessageB.BufferSize = SpdmContext->Transcript.MessageB.MaxBufferSize - sizeof(SPDM_GET_DIGESTS_REQUEST);
  Status = SpdmGetResponseDigest (SpdmContext, mSpdmGetDigestRequest1Size, &mSpdmGetDigestRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderDigestCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse;
  UINTN                Index;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  
  for (Index = 0; Index < MAX_SPDM_SLOT_COUNT; Index++) {
    SpdmContext->LocalContext.LocalCertChainProvision[Index] = NULL;
    SpdmContext->LocalContext.LocalCertChainProvisionSize[Index] = 0;
  }
  SpdmContext->LocalContext.SlotCount = 0;

  ResponseSize = sizeof(Response);
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  Status = SpdmGetResponseDigest (SpdmContext, mSpdmGetDigestRequest1Size, &mSpdmGetDigestRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, SPDM_GET_DIGESTS);
}

SPDM_TEST_CONTEXT       mSpdmResponderDigestTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderDigestTestMain(void) {
  const struct CMUnitTest SpdmResponderDigestTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderDigestCase1),
    // Bad Request Size
    cmocka_unit_test(TestSpdmResponderDigestCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderDigestCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderDigestCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderDigestCase5),
    // SpdmCmdReceiveState Check
    cmocka_unit_test(TestSpdmResponderDigestCase6),
    // Internal cache full (request message)
    cmocka_unit_test(TestSpdmResponderDigestCase7),
    // Internal cache full (response message)
    cmocka_unit_test(TestSpdmResponderDigestCase8),
    // No digest to send
    cmocka_unit_test(TestSpdmResponderDigestCase9),
  };

  SetupSpdmTestContext (&mSpdmResponderDigestTestContext);

  return cmocka_run_group_tests(SpdmResponderDigestTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
