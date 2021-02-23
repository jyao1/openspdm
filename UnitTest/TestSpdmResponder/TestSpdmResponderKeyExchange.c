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
  UINT16               Reserved;
  UINT8                RandomData[SPDM_RANDOM_DATA_SIZE];
  UINT8                ExchangeData[MAX_DHE_KEY_SIZE];
  UINT16               OpaqueLength;
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
} SPDM_KEY_EXCHANGE_REQUEST_MINE;

#pragma pack()

SPDM_KEY_EXCHANGE_REQUEST_MINE    mSpdmKeyExchangeRequest1 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_KEY_EXCHANGE,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
    0
  },
};
UINTN mSpdmKeyExchangeRequest1Size = sizeof(mSpdmKeyExchangeRequest1);

SPDM_KEY_EXCHANGE_REQUEST_MINE    mSpdmKeyExchangeRequest2 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_KEY_EXCHANGE,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
    0
  },
};
UINTN mSpdmKeyExchangeRequest2Size = sizeof(SPDM_KEY_EXCHANGE_REQUEST);

void TestSpdmResponderKeyExchangeCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_KEY_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                DheKeySize;
  VOID                 *DHEContext;
  UINTN                OpaqueKeyExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, mSpdmKeyExchangeRequest1.RandomData);
  mSpdmKeyExchangeRequest1.ReqSessionID = 0xFFFF;
  mSpdmKeyExchangeRequest1.Reserved = 0;
  Ptr = mSpdmKeyExchangeRequest1.ExchangeData;
  DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
  DHEContext = SpdmDheNew (mUseDheAlgo);
  SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
  Ptr += DheKeySize;
  SpdmDheFree (mUseDheAlgo, DHEContext);
  OpaqueKeyExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeReqSize;
  Ptr += sizeof(UINT16);
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaqueKeyExchangeReqSize, Ptr); 
  Ptr += OpaqueKeyExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseKeyExchange (SpdmContext, mSpdmKeyExchangeRequest1Size, &mSpdmKeyExchangeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);  
  assert_int_equal (SpdmSecuredMessageGetSessionState (SpdmContext->SessionInfo[0].SecuredMessageContext), SpdmSessionStateHandshaking);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_KEY_EXCHANGE_RSP);  
  assert_int_equal (SpdmResponse->RspSessionID, 0xFFFF);
  free(Data1);
}

void TestSpdmResponderKeyExchangeCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_KEY_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                DheKeySize;
  VOID                 *DHEContext;
  UINTN                OpaqueKeyExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, mSpdmKeyExchangeRequest2.RandomData);
  mSpdmKeyExchangeRequest2.ReqSessionID = 0xFFFF;
  mSpdmKeyExchangeRequest2.Reserved = 0;
  Ptr = mSpdmKeyExchangeRequest2.ExchangeData;
  DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
  DHEContext = SpdmDheNew (mUseDheAlgo);
  SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
  Ptr += DheKeySize;
  SpdmDheFree (mUseDheAlgo, DHEContext);
  OpaqueKeyExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeReqSize;
  Ptr += sizeof(UINT16);
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaqueKeyExchangeReqSize, Ptr); 
  Ptr += OpaqueKeyExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseKeyExchange (SpdmContext, mSpdmKeyExchangeRequest2Size, &mSpdmKeyExchangeRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data1);
}

void TestSpdmResponderKeyExchangeCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_KEY_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                DheKeySize;
  VOID                 *DHEContext;
  UINTN                OpaqueKeyExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, mSpdmKeyExchangeRequest1.RandomData);
  mSpdmKeyExchangeRequest1.ReqSessionID = 0xFFFF;
  mSpdmKeyExchangeRequest1.Reserved = 0;
  Ptr = mSpdmKeyExchangeRequest1.ExchangeData;
  DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
  DHEContext = SpdmDheNew (mUseDheAlgo);
  SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
  Ptr += DheKeySize;
  SpdmDheFree (mUseDheAlgo, DHEContext);
  OpaqueKeyExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeReqSize;
  Ptr += sizeof(UINT16);
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaqueKeyExchangeReqSize, Ptr); 
  Ptr += OpaqueKeyExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseKeyExchange (SpdmContext, mSpdmKeyExchangeRequest1Size, &mSpdmKeyExchangeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
  free(Data1);
}

void TestSpdmResponderKeyExchangeCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_KEY_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                DheKeySize;
  VOID                 *DHEContext;
  UINTN                OpaqueKeyExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, mSpdmKeyExchangeRequest1.RandomData);
  mSpdmKeyExchangeRequest1.ReqSessionID = 0xFFFF;
  mSpdmKeyExchangeRequest1.Reserved = 0;
  Ptr = mSpdmKeyExchangeRequest1.ExchangeData;
  DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
  DHEContext = SpdmDheNew (mUseDheAlgo);
  SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
  Ptr += DheKeySize;
  SpdmDheFree (mUseDheAlgo, DHEContext);
  OpaqueKeyExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeReqSize;
  Ptr += sizeof(UINT16);
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaqueKeyExchangeReqSize, Ptr); 
  Ptr += OpaqueKeyExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseKeyExchange (SpdmContext, mSpdmKeyExchangeRequest1Size, &mSpdmKeyExchangeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
  free(Data1);
}

void TestSpdmResponderKeyExchangeCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_KEY_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;
  UINT8                *Ptr;
  UINTN                DheKeySize;
  VOID                 *DHEContext;
  UINTN                OpaqueKeyExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, mSpdmKeyExchangeRequest1.RandomData);
  mSpdmKeyExchangeRequest1.ReqSessionID = 0xFFFF;
  mSpdmKeyExchangeRequest1.Reserved = 0;
  Ptr = mSpdmKeyExchangeRequest1.ExchangeData;
  DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
  DHEContext = SpdmDheNew (mUseDheAlgo);
  SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
  Ptr += DheKeySize;
  SpdmDheFree (mUseDheAlgo, DHEContext);
  OpaqueKeyExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeReqSize;
  Ptr += sizeof(UINT16);
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaqueKeyExchangeReqSize, Ptr); 
  Ptr += OpaqueKeyExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseKeyExchange (SpdmContext, mSpdmKeyExchangeRequest1Size, &mSpdmKeyExchangeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(&SpdmResponse->RspSessionID);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_KEY_EXCHANGE);
  free(Data1);
}

void TestSpdmResponderKeyExchangeCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_KEY_EXCHANGE_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINTN                DheKeySize;
  VOID                 *DHEContext;
  UINTN                OpaqueKeyExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ResponseState = SpdmResponseStateNormal;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data1, &DataSize1, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data1;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize1;  
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, mSpdmKeyExchangeRequest1.RandomData);
  mSpdmKeyExchangeRequest1.ReqSessionID = 0xFFFF;
  mSpdmKeyExchangeRequest1.Reserved = 0;
  Ptr = mSpdmKeyExchangeRequest1.ExchangeData;
  DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
  DHEContext = SpdmDheNew (mUseDheAlgo);
  SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
  Ptr += DheKeySize;
  SpdmDheFree (mUseDheAlgo, DHEContext);
  OpaqueKeyExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeReqSize;
  Ptr += sizeof(UINT16);
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaqueKeyExchangeReqSize, Ptr); 
  Ptr += OpaqueKeyExchangeReqSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseKeyExchange (SpdmContext, mSpdmKeyExchangeRequest1Size, &mSpdmKeyExchangeRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data1);
}

SPDM_TEST_CONTEXT       mSpdmResponderKeyExchangeTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderKeyExchangeTestMain(void) {
  const struct CMUnitTest SpdmResponderKeyExchangeTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderKeyExchangeCase1),
    // Bad Request Size
    cmocka_unit_test(TestSpdmResponderKeyExchangeCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderKeyExchangeCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderKeyExchangeCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderKeyExchangeCase5),
    // ConnectionState Check
    cmocka_unit_test(TestSpdmResponderKeyExchangeCase6),
  };

  SetupSpdmTestContext (&mSpdmResponderKeyExchangeTestContext);

  return cmocka_run_group_tests(SpdmResponderKeyExchangeTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
