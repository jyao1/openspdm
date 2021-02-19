/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>
#include <SpdmSecuredMessageLibInternal.h>

#pragma pack(1)

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                Signature[MAX_ASYM_KEY_SIZE];
  UINT8                VerifyData[MAX_HASH_SIZE];
} SPDM_FINISH_REQUEST_MINE;

#pragma pack()

SPDM_FINISH_REQUEST_MINE    mSpdmFinishRequest1 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_FINISH,
    0,
    0
  },
};
UINTN mSpdmFinishRequest1Size = sizeof(mSpdmFinishRequest1);

SPDM_FINISH_REQUEST_MINE    mSpdmFinishRequest2 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_FINISH,
    0,
    0
  },
};
UINTN mSpdmFinishRequest2Size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

UINT8 mDummyBuffer[MAX_HASH_SIZE];

VOID
SpdmSecuredMessageSetRequestFinishedKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *Key,
  IN UINTN                        KeySize
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  ASSERT (KeySize == SecuredMessageContext->HashSize);
  CopyMem (SecuredMessageContext->HandshakeSecret.RequestFinishedKey, Key, SecuredMessageContext->HashSize);
}

void TestSpdmResponderFinishCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_FINISH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINT8                *CertBuffer;
  UINTN                CertBufferSize;
  UINT8                CertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER THCurr;
  UINT8                RequestFinishedKey[MAX_HASH_SIZE];
  SPDM_SESSION_INFO    *SessionInfo;
  UINT32               SessionId;
  UINT32               HashSize;
  UINT32               HmacSize;

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
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SessionId = 0xFFFFFFFF;
  SpdmContext->LatestSessionId = SessionId;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, FALSE);
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  SetMem (mDummyBuffer, HashSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetRequestFinishedKey (SessionInfo->SecuredMessageContext, mDummyBuffer, HashSize);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateHandshaking);

  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  HmacSize = GetSpdmHashSize (mUseHashAlgo);
  Ptr = mSpdmFinishRequest1.Signature;
  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
  CertBuffer = (UINT8 *)Data1 + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = DataSize1 - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
  // Transcript.MessageA size is 0
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  // SessionTranscript.MessageK is 0 
  AppendManagedBuffer (&THCurr, (UINT8 *)&mSpdmFinishRequest1, sizeof(SPDM_FINISH_REQUEST));
  SetMem (RequestFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), RequestFinishedKey, HashSize, Ptr);
  mSpdmFinishRequest1Size = sizeof(SPDM_FINISH_REQUEST) + HmacSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseFinish (SpdmContext, mSpdmFinishRequest1Size, &mSpdmFinishRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_FINISH_RESPONSE) + HmacSize);  
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_FINISH_RSP);  
  free(Data1);
}

void TestSpdmResponderFinishCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_FINISH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINT8                *CertBuffer;
  UINTN                CertBufferSize;
  UINT8                CertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER THCurr;
  UINT8                RequestFinishedKey[MAX_HASH_SIZE];
  SPDM_SESSION_INFO    *SessionInfo;
  UINT32               SessionId;
  UINT32               HashSize;

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
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SessionId = 0xFFFFFFFF;
  SpdmContext->LatestSessionId = SessionId;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, FALSE);
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  SetMem (mDummyBuffer, HashSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetRequestFinishedKey (SessionInfo->SecuredMessageContext, mDummyBuffer, HashSize);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateHandshaking);

  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  Ptr = mSpdmFinishRequest2.Signature;
  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
  CertBuffer = (UINT8 *)Data1 + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = DataSize1 - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
  // Transcript.MessageA size is 0
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  // SessionTranscript.MessageK is 0 
  AppendManagedBuffer (&THCurr, (UINT8 *)&mSpdmFinishRequest2, sizeof(SPDM_FINISH_REQUEST));
  SetMem (RequestFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), RequestFinishedKey, HashSize, Ptr);
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseFinish (SpdmContext, mSpdmFinishRequest2Size, &mSpdmFinishRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data1);
}

void TestSpdmResponderFinishCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_FINISH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINT8                *CertBuffer;
  UINTN                CertBufferSize;
  UINT8                CertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER THCurr;
  UINT8                RequestFinishedKey[MAX_HASH_SIZE];
  SPDM_SESSION_INFO    *SessionInfo;
  UINT32               SessionId;
  UINT32               HashSize;
  UINT32               HmacSize;

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
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SessionId = 0xFFFFFFFF;
  SpdmContext->LatestSessionId = SessionId;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, FALSE);
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  SetMem (mDummyBuffer, HashSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetRequestFinishedKey (SessionInfo->SecuredMessageContext, mDummyBuffer, HashSize);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateHandshaking);

  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  HmacSize = GetSpdmHashSize (mUseHashAlgo);
  Ptr = mSpdmFinishRequest1.Signature;
  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
  CertBuffer = (UINT8 *)Data1 + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = DataSize1 - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
  // Transcript.MessageA size is 0
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  // SessionTranscript.MessageK is 0 
  AppendManagedBuffer (&THCurr, (UINT8 *)&mSpdmFinishRequest1, sizeof(SPDM_FINISH_REQUEST));
  SetMem (RequestFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), RequestFinishedKey, HashSize, Ptr);
  mSpdmFinishRequest1Size = sizeof(SPDM_FINISH_REQUEST) + HmacSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseFinish (SpdmContext, mSpdmFinishRequest1Size, &mSpdmFinishRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
  free(Data1);
}

void TestSpdmResponderFinishCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_FINISH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINT8                *CertBuffer;
  UINTN                CertBufferSize;
  UINT8                CertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER THCurr;
  UINT8                RequestFinishedKey[MAX_HASH_SIZE];
  SPDM_SESSION_INFO    *SessionInfo;
  UINT32               SessionId;
  UINT32               HashSize;
  UINT32               HmacSize;

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
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SessionId = 0xFFFFFFFF;
  SpdmContext->LatestSessionId = SessionId;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, FALSE);
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  SetMem (mDummyBuffer, HashSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetRequestFinishedKey (SessionInfo->SecuredMessageContext, mDummyBuffer, HashSize);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateHandshaking);

  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  HmacSize = GetSpdmHashSize (mUseHashAlgo);
  Ptr = mSpdmFinishRequest1.Signature;
  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
  CertBuffer = (UINT8 *)Data1 + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = DataSize1 - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
  // Transcript.MessageA size is 0
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  // SessionTranscript.MessageK is 0 
  AppendManagedBuffer (&THCurr, (UINT8 *)&mSpdmFinishRequest1, sizeof(SPDM_FINISH_REQUEST));
  SetMem (RequestFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), RequestFinishedKey, HashSize, Ptr);
  mSpdmFinishRequest1Size = sizeof(SPDM_FINISH_REQUEST) + HmacSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseFinish (SpdmContext, mSpdmFinishRequest1Size, &mSpdmFinishRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
  free(Data1);
}

void TestSpdmResponderFinishCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_FINISH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINT8                *CertBuffer;
  UINTN                CertBufferSize;
  UINT8                CertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER THCurr;
  UINT8                RequestFinishedKey[MAX_HASH_SIZE];
  SPDM_SESSION_INFO    *SessionInfo;
  UINT32               SessionId;
  UINT32               HashSize;
  UINT32               HmacSize;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;
  
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
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SessionId = 0xFFFFFFFF;
  SpdmContext->LatestSessionId = SessionId;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, FALSE);
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  SetMem (mDummyBuffer, HashSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetRequestFinishedKey (SessionInfo->SecuredMessageContext, mDummyBuffer, HashSize);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateHandshaking);

  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  HmacSize = GetSpdmHashSize (mUseHashAlgo);
  Ptr = mSpdmFinishRequest1.Signature;
  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
  CertBuffer = (UINT8 *)Data1 + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = DataSize1 - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
  // Transcript.MessageA size is 0
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  // SessionTranscript.MessageK is 0 
  AppendManagedBuffer (&THCurr, (UINT8 *)&mSpdmFinishRequest1, sizeof(SPDM_FINISH_REQUEST));
  SetMem (RequestFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), RequestFinishedKey, HashSize, Ptr);
  mSpdmFinishRequest1Size = sizeof(SPDM_FINISH_REQUEST) + HmacSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseFinish (SpdmContext, mSpdmFinishRequest1Size, &mSpdmFinishRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(SpdmResponse + 1);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_FINISH);
  free(Data1);
}

void TestSpdmResponderFinishCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_FINISH_RESPONSE *SpdmResponse;
  VOID                 *Data1;
  UINTN                DataSize1;
  UINT8                *Ptr;
  UINT8                *CertBuffer;
  UINTN                CertBufferSize;
  UINT8                CertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER THCurr;
  UINT8                RequestFinishedKey[MAX_HASH_SIZE];
  SPDM_SESSION_INFO    *SessionInfo;
  UINT32               SessionId;
  UINT32               HashSize;
  UINT32               HmacSize;
  
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
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data1;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize1;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SessionId = 0xFFFFFFFF;
  SpdmContext->LatestSessionId = SessionId;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, FALSE);
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  SetMem (mDummyBuffer, HashSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetRequestFinishedKey (SessionInfo->SecuredMessageContext, mDummyBuffer, HashSize);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateHandshaking);

  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  HmacSize = GetSpdmHashSize (mUseHashAlgo);
  Ptr = mSpdmFinishRequest1.Signature;
  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
  CertBuffer = (UINT8 *)Data1 + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = DataSize1 - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
  // Transcript.MessageA size is 0
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  // SessionTranscript.MessageK is 0 
  AppendManagedBuffer (&THCurr, (UINT8 *)&mSpdmFinishRequest1, sizeof(SPDM_FINISH_REQUEST));
  SetMem (RequestFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), RequestFinishedKey, HashSize, Ptr);
  mSpdmFinishRequest1Size = sizeof(SPDM_FINISH_REQUEST) + HmacSize;
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseFinish (SpdmContext, mSpdmFinishRequest1Size, &mSpdmFinishRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data1);
}

SPDM_TEST_CONTEXT       mSpdmResponderFinishTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderFinishTestMain(void) {
  const struct CMUnitTest SpdmResponderFinishTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderFinishCase1),
    // Bad Request Size
    cmocka_unit_test(TestSpdmResponderFinishCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderFinishCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderFinishCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderFinishCase5),
    // ConnectionState Check
    cmocka_unit_test(TestSpdmResponderFinishCase6),
  };

  SetupSpdmTestContext (&mSpdmResponderFinishTestContext);

  return cmocka_run_group_tests(SpdmResponderFinishTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
