/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

#pragma pack(1)

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               ReqSessionID;
  UINT16               PSKHintLength;
  UINT16               RequesterContextLength;
  UINT16               OpaqueLength;
  UINT8                PSKHint[MAX_SPDM_PSK_HINT_LENGTH];
  UINT8                RequesterContext[DEFAULT_CONTEXT_LENGTH];
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
} SPDM_PSK_EXCHANGE_REQUEST_MINE;

#pragma pack()

STATIC UINT8                  LocalPskHint[32];

SPDM_PSK_EXCHANGE_REQUEST_MINE    mSpdmPskExchangeRequest1 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_PSK_EXCHANGE,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
    0
  },
};
UINTN mSpdmPskExchangeRequest1Size = sizeof(mSpdmPskExchangeRequest1);

SPDM_PSK_EXCHANGE_REQUEST_MINE    mSpdmPskExchangeRequest2 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_PSK_EXCHANGE,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
    0
  },
};
UINTN mSpdmPskExchangeRequest2Size = sizeof(SPDM_PSK_EXCHANGE_REQUEST);

void TestSpdmResponderPskExchangeCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_PSK_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                OpaquePskExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  mSpdmPskExchangeRequest1.PSKHintLength = (UINT16)SpdmContext->LocalContext.PskHintSize;
  mSpdmPskExchangeRequest1.RequesterContextLength = DEFAULT_CONTEXT_LENGTH;
  OpaquePskExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  mSpdmPskExchangeRequest1.OpaqueLength = (UINT16)OpaquePskExchangeReqSize;
  mSpdmPskExchangeRequest1.ReqSessionID = 0xFFFF;
  Ptr = mSpdmPskExchangeRequest1.PSKHint;
  CopyMem (Ptr, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize);
  Ptr += mSpdmPskExchangeRequest1.PSKHintLength;
  SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
  Ptr += mSpdmPskExchangeRequest1.RequesterContextLength;
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaquePskExchangeReqSize, Ptr);
  Ptr += OpaquePskExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponsePskExchange (SpdmContext, mSpdmPskExchangeRequest1Size, &mSpdmPskExchangeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);  
  assert_int_equal (SpdmSecuredMessageGetSessionState (SpdmContext->SessionInfo[0].SecuredMessageContext), SpdmSessionStateHandshaking);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_PSK_EXCHANGE_RSP);  
  assert_int_equal (SpdmResponse->RspSessionID, 0xFFFF);
  free(Data1);
}

void TestSpdmResponderPskExchangeCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_PSK_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                OpaquePskExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  mSpdmPskExchangeRequest2.PSKHintLength = (UINT16)SpdmContext->LocalContext.PskHintSize;
  mSpdmPskExchangeRequest2.RequesterContextLength = DEFAULT_CONTEXT_LENGTH;
  OpaquePskExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  mSpdmPskExchangeRequest2.OpaqueLength = (UINT16)OpaquePskExchangeReqSize;
  mSpdmPskExchangeRequest2.ReqSessionID = 0xFFFF;
  Ptr = mSpdmPskExchangeRequest2.PSKHint;
  CopyMem (Ptr, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize);
  Ptr += mSpdmPskExchangeRequest2.PSKHintLength;
  SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
  Ptr += mSpdmPskExchangeRequest2.RequesterContextLength;
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaquePskExchangeReqSize, Ptr);
  Ptr += OpaquePskExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponsePskExchange (SpdmContext, mSpdmPskExchangeRequest2Size, &mSpdmPskExchangeRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data1);
}

void TestSpdmResponderPskExchangeCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_PSK_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                OpaquePskExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  mSpdmPskExchangeRequest1.PSKHintLength = (UINT16)SpdmContext->LocalContext.PskHintSize;
  mSpdmPskExchangeRequest1.RequesterContextLength = DEFAULT_CONTEXT_LENGTH;
  OpaquePskExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  mSpdmPskExchangeRequest1.OpaqueLength = (UINT16)OpaquePskExchangeReqSize;
  mSpdmPskExchangeRequest1.ReqSessionID = 0xFFFF;
  Ptr = mSpdmPskExchangeRequest1.PSKHint;
  CopyMem (Ptr, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize);
  Ptr += mSpdmPskExchangeRequest1.PSKHintLength;
  SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
  Ptr += mSpdmPskExchangeRequest1.RequesterContextLength;
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaquePskExchangeReqSize, Ptr);
  Ptr += OpaquePskExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponsePskExchange (SpdmContext, mSpdmPskExchangeRequest1Size, &mSpdmPskExchangeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
  free(Data1);
}

void TestSpdmResponderPskExchangeCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_PSK_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                OpaquePskExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  mSpdmPskExchangeRequest1.PSKHintLength = (UINT16)SpdmContext->LocalContext.PskHintSize;
  mSpdmPskExchangeRequest1.RequesterContextLength = DEFAULT_CONTEXT_LENGTH;
  OpaquePskExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  mSpdmPskExchangeRequest1.OpaqueLength = (UINT16)OpaquePskExchangeReqSize;
  mSpdmPskExchangeRequest1.ReqSessionID = 0xFFFF;
  Ptr = mSpdmPskExchangeRequest1.PSKHint;
  CopyMem (Ptr, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize);
  Ptr += mSpdmPskExchangeRequest1.PSKHintLength;
  SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
  Ptr += mSpdmPskExchangeRequest1.RequesterContextLength;
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaquePskExchangeReqSize, Ptr);
  Ptr += OpaquePskExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponsePskExchange (SpdmContext, mSpdmPskExchangeRequest1Size, &mSpdmPskExchangeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
  free(Data1);
}

void TestSpdmResponderPskExchangeCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_PSK_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                OpaquePskExchangeReqSize;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  mSpdmPskExchangeRequest1.PSKHintLength = (UINT16)SpdmContext->LocalContext.PskHintSize;
  mSpdmPskExchangeRequest1.RequesterContextLength = DEFAULT_CONTEXT_LENGTH;
  OpaquePskExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  mSpdmPskExchangeRequest1.OpaqueLength = (UINT16)OpaquePskExchangeReqSize;
  mSpdmPskExchangeRequest1.ReqSessionID = 0xFFFF;
  Ptr = mSpdmPskExchangeRequest1.PSKHint;
  CopyMem (Ptr, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize);
  Ptr += mSpdmPskExchangeRequest1.PSKHintLength;
  SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
  Ptr += mSpdmPskExchangeRequest1.RequesterContextLength;
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaquePskExchangeReqSize, Ptr);
  Ptr += OpaquePskExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponsePskExchange (SpdmContext, mSpdmPskExchangeRequest1Size, &mSpdmPskExchangeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(&SpdmResponse->RspSessionID);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_PSK_EXCHANGE);
  free(Data1);
}

void TestSpdmResponderPskExchangeCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_PSK_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                OpaquePskExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ResponseState = SpdmResponseStateNormal;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  mSpdmPskExchangeRequest1.PSKHintLength = (UINT16)SpdmContext->LocalContext.PskHintSize;
  mSpdmPskExchangeRequest1.RequesterContextLength = DEFAULT_CONTEXT_LENGTH;
  OpaquePskExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  mSpdmPskExchangeRequest1.OpaqueLength = (UINT16)OpaquePskExchangeReqSize;
  mSpdmPskExchangeRequest1.ReqSessionID = 0xFFFF;
  Ptr = mSpdmPskExchangeRequest1.PSKHint;
  CopyMem (Ptr, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize);
  Ptr += mSpdmPskExchangeRequest1.PSKHintLength;
  SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
  Ptr += mSpdmPskExchangeRequest1.RequesterContextLength;
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaquePskExchangeReqSize, Ptr);
  Ptr += OpaquePskExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponsePskExchange (SpdmContext, mSpdmPskExchangeRequest1Size, &mSpdmPskExchangeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data1);
}

SPDM_TEST_CONTEXT       mSpdmResponderPskExchangeTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderPskExchangeTestMain(void) {
  const struct CMUnitTest SpdmResponderPskExchangeTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderPskExchangeCase1),
    // Bad Request Size
    cmocka_unit_test(TestSpdmResponderPskExchangeCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderPskExchangeCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderPskExchangeCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderPskExchangeCase5),
    // ConnectionState Check
    cmocka_unit_test(TestSpdmResponderPskExchangeCase6),
  };

  SetupSpdmTestContext (&mSpdmResponderPskExchangeTestContext);

  return cmocka_run_group_tests(SpdmResponderPskExchangeTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
