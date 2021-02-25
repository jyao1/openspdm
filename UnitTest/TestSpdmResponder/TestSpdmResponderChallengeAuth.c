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
    SPDM_MESSAGE_VERSION_11,
    SPDM_CHALLENGE,
    0,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH
  },
};
UINTN mSpdmChallengeRequest1Size = sizeof(mSpdmChallengeRequest1);

SPDM_CHALLENGE_REQUEST    mSpdmChallengeRequest2 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_CHALLENGE,
    0,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH
  },
};
UINTN mSpdmChallengeRequest2Size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

SPDM_CHALLENGE_REQUEST    mSpdmChallengeRequest3 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_CHALLENGE,
    MAX_SPDM_SLOT_COUNT,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH
  },
};
UINTN mSpdmChallengeRequest3Size = sizeof(mSpdmChallengeRequest3);

SPDM_CHALLENGE_REQUEST    mSpdmChallengeRequest4 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_CHALLENGE,
    1,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH
  },
};
UINTN mSpdmChallengeRequest4Size = sizeof(mSpdmChallengeRequest4);

SPDM_CHALLENGE_REQUEST    mSpdmChallengeRequest5 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_CHALLENGE,
    0,
    SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH
  },
};
UINTN mSpdmChallengeRequest5Size = sizeof(mSpdmChallengeRequest5);

SPDM_CHALLENGE_REQUEST    mSpdmChallengeRequest6 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_CHALLENGE,
    0,
    SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH
  },
};
UINTN mSpdmChallengeRequest6Size = sizeof(mSpdmChallengeRequest6);

UINT8 OpaqueChallengeAuthRsp[9] = "openspdm";

/**
  Test 1: receiving a correct CHALLENGE message from the requester with
  no opaque data, no measurements, and slot number 0.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
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
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

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

/**
  Test 2: receiving a CHALLENGE message larger than specified.
  Expected behavior: the responder refuses the CHALLENGE message and produces an
  ERROR message indicating the InvalidRequest.
**/
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
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

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

/**
  Test 3: receiving a correct CHALLENGE from the requester, but the responder is in
  a Busy state.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the Busy state.
**/
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
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

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

/**
  Test 4: receiving a correct CHALLENGE from the requester, but the responder requires
  resynchronization with the requester.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the NeedResynch state.
**/
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
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

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

/**
  Test 5: receiving a correct CHALLENGE from the requester, but the responder could not
  produce the response in time.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the ResponseNotReady state.
**/
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
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

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

/**
  Test 6: receiving a correct CHALLENGE from the requester, but the responder is not set
  no receive a CHALLENGE message because previous messages (namely, GET_CAPABILITIES,
  NEGOTIATE_ALGORITHMS or GET_DIGESTS) have not been received.
  Expected behavior: the responder rejects the request, and produces an ERROR message
  indicating the UnexpectedRequest.
**/
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
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

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

/**
  Test 7: receiving a correct CHALLENGE from the requester, but the responder does not
  have the challenge capability set.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
void TestSpdmResponderChallengeAuthCase7(void **state) {
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
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  // SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest1Size, &mSpdmChallengeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, SPDM_CHALLENGE);
  free(Data1);
}

/**
  Test 8: receiving an incorrect CHALLENGE from the requester, with the slot number
  larger than the specification limit.
  Expected behavior: the responder rejects the request, and produces an ERROR message
  indicating the UnexpectedRequest.
**/
void TestSpdmResponderChallengeAuthCase8(void **state) {
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
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest3Size, &mSpdmChallengeRequest3, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data1);
}

/**
  Test 9: eceiving a correct CHALLENGE message from the requester with
  no opaque data, no measurements, and slot number 1.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
void TestSpdmResponderChallengeAuthCase9(void **state) {
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
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[1] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[1] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 2;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest4Size, &mSpdmChallengeRequest4, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + GetSpdmHashSize (mUseHashAlgo) + SPDM_NONCE_SIZE + 0 + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CHALLENGE_AUTH);
  assert_int_equal (SpdmResponse->Header.Param1, 1);
  assert_int_equal (SpdmResponse->Header.Param2, 1 << 1);
  free(Data1);
}

/**
  Test 10: receiving a correct CHALLENGE from the requester, but with certificate
  unavailable at the requested slot number (1).
  Expected behavior: the responder rejects the request, and produces an ERROR message
  indicating the UnexpectedRequest.
**/
void TestSpdmResponderChallengeAuthCase10(void **state) {
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
  SpdmTestContext->CaseId = 0xA;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest3Size, &mSpdmChallengeRequest3, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data1);
}

/**
  Test 11: receiving a correct CHALLENGE message from the requester with opaque 
  data as the bytes of the string "openspdm", no measurements, and slot number 0.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
void TestSpdmResponderChallengeAuthCase11(void **state) {
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
  SpdmTestContext->CaseId = 0xB;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 8;
  SpdmContext->LocalContext.OpaqueChallengeAuthRsp = OpaqueChallengeAuthRsp;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest1Size, &mSpdmChallengeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + GetSpdmHashSize (mUseHashAlgo) + SPDM_NONCE_SIZE + 0 + sizeof(UINT16) + 8 + GetSpdmAsymSignatureSize (mUseAsymAlgo));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CHALLENGE_AUTH);
  assert_int_equal (SpdmResponse->Header.Param1, 0);
  assert_int_equal (SpdmResponse->Header.Param2, 1 << 0);
  free(Data1);
}

/**
  Test 12: receiving a correct CHALLENGE message from the requester with
  no opaque data, TCB measurement hash, and slot number 0.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
void TestSpdmResponderChallengeAuthCase12(void **state) {
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
  SpdmTestContext->CaseId = 0xC;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; //additional measurement capability
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest5Size, &mSpdmChallengeRequest5, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + GetSpdmHashSize (mUseHashAlgo) + SPDM_NONCE_SIZE + GetSpdmHashSize (mUseHashAlgo) + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CHALLENGE_AUTH);
  assert_int_equal (SpdmResponse->Header.Param1, 0);
  assert_int_equal (SpdmResponse->Header.Param2, 1 << 0);
  free(Data1);
}

/**
  Test 13: receiving a correct CHALLENGE message from the requester with
  no opaque data, all measurement hashes, and slot number 0.
  Expected behavior: the responder accepts the request and produces a valid 
  CHALLENGE_AUTH response message.
**/
void TestSpdmResponderChallengeAuthCase13(void **state) {
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
  SpdmTestContext->CaseId = 0xD;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; //additional measurement capability
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest1.Nonce);
  Status = SpdmGetResponseChallengeAuth (SpdmContext, mSpdmChallengeRequest6Size, &mSpdmChallengeRequest6, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + GetSpdmHashSize (mUseHashAlgo) + SPDM_NONCE_SIZE + GetSpdmHashSize (mUseHashAlgo) + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CHALLENGE_AUTH);
  assert_int_equal (SpdmResponse->Header.Param1, 0);
  assert_int_equal (SpdmResponse->Header.Param2, 1 << 0);
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
    // SpdmCmdReceiveState Check
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase6),
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase7),
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase8),
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase9),
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase10),
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase11),
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase12),
    cmocka_unit_test(TestSpdmResponderChallengeAuthCase13),
  };

  SetupSpdmTestContext (&mSpdmResponderChallengeAuthTestContext);

  return cmocka_run_group_tests(SpdmResponderChallengeAuthTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
