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

/**
  Test 1: receives a valid GET_DIGESTS request message from Requester
  Expected Behavior: produces a valid DIGESTS response message
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated; 
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseDigest (SpdmContext, mSpdmGetDigestRequest1Size, &mSpdmGetDigestRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize(SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_DIGESTS);
}

/**
  Test 2: receives a GET_DIGESTS request message with bad size from Requester
  Expected Behavior: produces an ERROR response message with error code = InvalidRequest
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
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

/**
  Test 3: receives a valid GET_DIGESTS request message from Requester, but Responder is not ready to accept the new 
  request message (is busy) and may be able to process the request message if it is sent again in the future
  Expected Behavior: produces an ERROR response message with error code = Busy
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
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

/**
  Test 4: receives a valid GET_DIGESTS request message from Requester, but Responder needs the Requester to reissue GET_VERSION to resynchronize
  Expected Behavior: produces an ERROR response message with error code = RequestResynch
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
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
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
}

/**
  Test 5: receives a valid GET_DIGESTS request message from Requester, but Responder cannot produce the response message in time 
  Expected Behavior: produces an ERROR response message with error code = ResponseNotReady
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
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
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_GET_DIGESTS);
}

/**
  Test 6: receives a valid GET_DIGESTS request message from Requester, but ConnectionState equals to zero and makes the check fail, 
  meaning that steps GET_CAPABILITIES-CAPABILITIES and NEGOTIATE_ALGORITHMS-ALGORITHMS of the protocol were not previously completed
  Expected Behavior: produces an ERROR response message with error code = UnexpectedRequest
**/
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
  SpdmContext->ResponseState = SpdmResponseStateNormal;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
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

/**
  Test 7: receives a valid GET_DIGESTS request message from Requester, but the request message cannot be appended to the internal cache since the internal cache is full
  Expected Behavior: produces an ERROR response message with error code = InvalidRequest
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
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

/**
  Test 8: receives a valid GET_DIGESTS request message from Requester, but the response message cannot be appended to the internal cache since the internal cache is full
  Expected Behavior: produces an ERROR response message with error code = InvalidRequest
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
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

/**
  Test 9: receives a valid GET_DIGESTS request message from Requester, but there is no local certificate chain, i.e. there is no digest to send
  Expected Behavior: produces an ERROR response message with error code = UnsupportedRequest
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
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
    // ConnectionState Check
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
