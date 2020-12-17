/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

STATIC UINTN                  LocalBufferSize;
STATIC UINT8                  LocalBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

RETURN_STATUS
EFIAPI
SpdmRequesterFinishTestSendMessage (
  IN     VOID                    *SpdmContext,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;
  UINT8                   *Ptr;

  SpdmTestContext = GetSpdmTestContext ();
  Ptr = (UINT8 *)Request;
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;
  case 0x2:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x3:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x4:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x5:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x6:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x7:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x8:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x9:
  {
    STATIC UINTN SubIndex = 0;
    if (SubIndex == 0) {
      LocalBufferSize = 0;
      CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
      LocalBufferSize += (RequestSize - 1);
      SubIndex ++;
    }
  }
    return RETURN_SUCCESS;
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmRequesterFinishTestReceiveMessage (
  IN     VOID                    *SpdmContext,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = GetSpdmTestContext ();
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;

  case 0x2:
  {
    SPDM_FINISH_RESPONSE          *SpdmResponse;
    UINT32                        HashSize;
    UINT32                        HmacSize;
    UINT8                         *Ptr;
    VOID                          *Data;
    UINTN                         DataSize; 
    UINT8                         *CertBuffer;
    UINTN                         CertBufferSize;
    UINT8                         CertBufferHash[MAX_HASH_SIZE];
    LARGE_MANAGED_BUFFER          THCurr;
    UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    HashSize = GetSpdmHashSize (SpdmContext);
    HmacSize = GetSpdmHashSize (SpdmContext);
    TempBufSize = sizeof(SPDM_FINISH_RESPONSE) + HmacSize;
    SpdmResponse = (VOID *)TempBuf;
 
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_FINISH_RSP;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    Ptr = (VOID *)(SpdmResponse + 1);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, sizeof(SPDM_FINISH_RESPONSE));
    LocalBufferSize += sizeof(SPDM_FINISH_RESPONSE);
    ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
    InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
    CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);
    // Transcript.MessageA size is 0
    AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
    // SessionTranscript.MessageK is 0 
    AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
    SetMem (ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
    SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseFinishedKey, HashSize, Ptr);
    Ptr += HmacSize;
    free(Data);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_FINISH_RESPONSE          *SpdmResponse;
    UINT32                        HashSize;
    UINT32                        HmacSize;
    UINT8                         *Ptr;
    VOID                          *Data;
    UINTN                         DataSize; 
    UINT8                         *CertBuffer;
    UINTN                         CertBufferSize;
    UINT8                         CertBufferHash[MAX_HASH_SIZE];
    LARGE_MANAGED_BUFFER          THCurr;
    UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;    
    
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    HashSize = GetSpdmHashSize (SpdmContext);
    HmacSize = GetSpdmHashSize (SpdmContext);
    TempBufSize = sizeof(SPDM_FINISH_RESPONSE) + HmacSize;
    SpdmResponse = (VOID *)TempBuf;
    
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_FINISH_RSP;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    Ptr = (VOID *)(SpdmResponse + 1);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, sizeof(SPDM_FINISH_RESPONSE));
    LocalBufferSize += sizeof(SPDM_FINISH_RESPONSE);
    ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
    InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
    CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);
    // Transcript.MessageA size is 0
    AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
    // SessionTranscript.MessageK is 0 
    AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
    SetMem (ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
    SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseFinishedKey, HashSize, Ptr);
    Ptr += HmacSize;
    free(Data);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x4:
  {
    SPDM_ERROR_RESPONSE    SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x5:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x6:
  {
    STATIC UINTN SubIndex1 = 0;
    if (SubIndex1 == 0) {
      SPDM_ERROR_RESPONSE  SpdmResponse;

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
      SpdmResponse.Header.Param2 = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex1 ++;
    } else if (SubIndex1 == 1) {
      SPDM_FINISH_RESPONSE          *SpdmResponse;
      UINT32                        HashSize;
      UINT32                        HmacSize;
      UINT8                         *Ptr;
      VOID                          *Data;
      UINTN                         DataSize; 
      UINT8                         *CertBuffer;
      UINTN                         CertBufferSize;
      UINT8                         CertBufferHash[MAX_HASH_SIZE];
      LARGE_MANAGED_BUFFER          THCurr;
      UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
      HashSize = GetSpdmHashSize (SpdmContext);
      HmacSize = GetSpdmHashSize (SpdmContext);
      TempBufSize = sizeof(SPDM_FINISH_RESPONSE) + HmacSize;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse->Header.RequestResponseCode = SPDM_FINISH_RSP;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      Ptr = (VOID *)(SpdmResponse + 1);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, sizeof(SPDM_FINISH_RESPONSE));
      LocalBufferSize += sizeof(SPDM_FINISH_RESPONSE);
      ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
      InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
      CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);
      // Transcript.MessageA size is 0
      AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
      // SessionTranscript.MessageK is 0 
      AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
      SetMem (ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
      SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseFinishedKey, HashSize, Ptr);
      Ptr += HmacSize;
      free(Data);
 
      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
  }
    return RETURN_SUCCESS;

  case 0x7:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x8:
  {
    SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.ExtendErrorData.RDTExponent = 1;
    SpdmResponse.ExtendErrorData.RDTM = 1;
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_FINISH;
    SpdmResponse.ExtendErrorData.Token = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x9:
  {
    STATIC UINTN SubIndex2 = 0;
    if (SubIndex2 == 0) {
      SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.ExtendErrorData.RDTExponent = 1;
      SpdmResponse.ExtendErrorData.RDTM = 1;
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_FINISH;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex2 ++;
    } else if (SubIndex2 == 1) {
      SPDM_FINISH_RESPONSE          *SpdmResponse;
      UINT32                        HashSize;
      UINT32                        HmacSize;
      UINT8                         *Ptr;
      VOID                          *Data;
      UINTN                         DataSize; 
      UINT8                         *CertBuffer;
      UINTN                         CertBufferSize;
      UINT8                         CertBufferHash[MAX_HASH_SIZE];
      LARGE_MANAGED_BUFFER          THCurr;
      UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
      HashSize = GetSpdmHashSize (SpdmContext);
      HmacSize = GetSpdmHashSize (SpdmContext);
      TempBufSize = sizeof(SPDM_FINISH_RESPONSE) + HmacSize;
      SpdmResponse = (VOID *)TempBuf;
      
      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse->Header.RequestResponseCode = SPDM_FINISH_RSP;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      Ptr = (VOID *)(SpdmResponse + 1);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, sizeof(SPDM_FINISH_RESPONSE));
      LocalBufferSize += sizeof(SPDM_FINISH_RESPONSE);
      ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
      InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
      CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);
      // Transcript.MessageA size is 0
      AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
      // SessionTranscript.MessageK is 0 
      AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
      SetMem (ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
      SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseFinishedKey, HashSize, Ptr);
      Ptr += HmacSize;
      free(Data);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

void TestSpdmRequesterFinishCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                SlotIdParam; 
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_KEY_EXCHANGE_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  ZeroMem (SessionInfo, sizeof(*SessionInfo));
  SessionInfo->SessionId = SessionId;
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->MutAuthRequested = 0;
  SessionInfo->SessionTranscript.MessageF.BufferSize = 0;
  SessionInfo->HashSize = GetSpdmHashSize (SpdmContext);
  SessionInfo->DheKeySize = GetSpdmDheKeySize (SpdmContext);  
  SetMem (SessionInfo->HandshakeSecret.ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SlotIdParam = 0;
  Status = SpdmSendReceiveFinish (SpdmContext, SessionId, SlotIdParam); 
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterFinishCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_KEY_EXCHANGE_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  ZeroMem (SessionInfo, sizeof(*SessionInfo));
  SessionInfo->SessionId = SessionId;
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->MutAuthRequested = 0;
  SessionInfo->SessionTranscript.MessageF.BufferSize = 0;
  SessionInfo->HashSize = GetSpdmHashSize (SpdmContext);
  SessionInfo->DheKeySize = GetSpdmDheKeySize (SpdmContext);  
  SetMem (SessionInfo->HandshakeSecret.ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SlotIdParam = 0;
  Status = SpdmSendReceiveFinish (SpdmContext, SessionId, SlotIdParam); 
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->SessionInfo[0].SessionState, SpdmStateEstablished);
  free(Data);
}

void TestSpdmRequesterFinishCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->SpdmCmdReceiveState = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  ZeroMem (SessionInfo, sizeof(*SessionInfo));
  SessionInfo->SessionId = SessionId;
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->MutAuthRequested = 0;
  SessionInfo->SessionTranscript.MessageF.BufferSize = 0;
  SessionInfo->HashSize = GetSpdmHashSize (SpdmContext);
  SessionInfo->DheKeySize = GetSpdmDheKeySize (SpdmContext);  
  SetMem (SessionInfo->HandshakeSecret.ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SlotIdParam = 0;
  Status = SpdmSendReceiveFinish (SpdmContext, SessionId, SlotIdParam); 
  assert_int_equal (Status, RETURN_DEVICE_ERROR);  
  free(Data);
}

void TestSpdmRequesterFinishCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_KEY_EXCHANGE_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  ZeroMem (SessionInfo, sizeof(*SessionInfo));
  SessionInfo->SessionId = SessionId;
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->MutAuthRequested = 0;
  SessionInfo->SessionTranscript.MessageF.BufferSize = 0;
  SessionInfo->HashSize = GetSpdmHashSize (SpdmContext);
  SessionInfo->DheKeySize = GetSpdmDheKeySize (SpdmContext);  
  SetMem (SessionInfo->HandshakeSecret.ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SlotIdParam = 0;
  Status = SpdmSendReceiveFinish (SpdmContext, SessionId, SlotIdParam); 
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterFinishCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_KEY_EXCHANGE_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  ZeroMem (SessionInfo, sizeof(*SessionInfo));
  SessionInfo->SessionId = SessionId;
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->MutAuthRequested = 0;
  SessionInfo->SessionTranscript.MessageF.BufferSize = 0;
  SessionInfo->HashSize = GetSpdmHashSize (SpdmContext);
  SessionInfo->DheKeySize = GetSpdmDheKeySize (SpdmContext);  
  SetMem (SessionInfo->HandshakeSecret.ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SlotIdParam = 0;
  Status = SpdmSendReceiveFinish (SpdmContext, SessionId, SlotIdParam); 
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  free(Data);
}

void TestSpdmRequesterFinishCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_KEY_EXCHANGE_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  ZeroMem (SessionInfo, sizeof(*SessionInfo));
  SessionInfo->SessionId = SessionId;
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->MutAuthRequested = 0;
  SessionInfo->SessionTranscript.MessageF.BufferSize = 0;
  SessionInfo->HashSize = GetSpdmHashSize (SpdmContext);
  SessionInfo->DheKeySize = GetSpdmDheKeySize (SpdmContext);  
  SetMem (SessionInfo->HandshakeSecret.ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SlotIdParam = 0;
  Status = SpdmSendReceiveFinish (SpdmContext, SessionId, SlotIdParam); 
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->SessionInfo[0].SessionState, SpdmStateEstablished);
  free(Data);
}

void TestSpdmRequesterFinishCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_KEY_EXCHANGE_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  ZeroMem (SessionInfo, sizeof(*SessionInfo));
  SessionInfo->SessionId = SessionId;
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->MutAuthRequested = 0;
  SessionInfo->SessionTranscript.MessageF.BufferSize = 0;
  SessionInfo->HashSize = GetSpdmHashSize (SpdmContext);
  SessionInfo->DheKeySize = GetSpdmDheKeySize (SpdmContext);  
  SetMem (SessionInfo->HandshakeSecret.ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SlotIdParam = 0;
  Status = SpdmSendReceiveFinish (SpdmContext, SessionId, SlotIdParam); 
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->SpdmCmdReceiveState, 0);
  free(Data);
}

void TestSpdmRequesterFinishCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_KEY_EXCHANGE_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  ZeroMem (SessionInfo, sizeof(*SessionInfo));
  SessionInfo->SessionId = SessionId;
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->MutAuthRequested = 0;
  SessionInfo->SessionTranscript.MessageF.BufferSize = 0;
  SessionInfo->HashSize = GetSpdmHashSize (SpdmContext);
  SessionInfo->DheKeySize = GetSpdmDheKeySize (SpdmContext);  
  SetMem (SessionInfo->HandshakeSecret.ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SlotIdParam = 0;
  Status = SpdmSendReceiveFinish (SpdmContext, SessionId, SlotIdParam); 
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterFinishCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_KEY_EXCHANGE_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  ZeroMem (SessionInfo, sizeof(*SessionInfo));
  SessionInfo->SessionId = SessionId;
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->MutAuthRequested = 0;
  SessionInfo->SessionTranscript.MessageF.BufferSize = 0;
  SessionInfo->HashSize = GetSpdmHashSize (SpdmContext);
  SessionInfo->DheKeySize = GetSpdmDheKeySize (SpdmContext);  
  SetMem (SessionInfo->HandshakeSecret.ResponseFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SlotIdParam = 0;
  Status = SpdmSendReceiveFinish (SpdmContext, SessionId, SlotIdParam); 
  assert_int_equal (Status, RETURN_SUCCESS); 
  assert_int_equal (SpdmContext->SessionInfo[0].SessionState, SpdmStateEstablished);
  free(Data);
}

SPDM_TEST_CONTEXT       mSpdmRequesterFinishTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterFinishTestSendMessage,
  SpdmRequesterFinishTestReceiveMessage,
};

int SpdmRequesterFinishTestMain(void) {
  const struct CMUnitTest SpdmRequesterFinishTests[] = {
      // SendRequest failed
      cmocka_unit_test(TestSpdmRequesterFinishCase1),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterFinishCase2),
      // SpdmCmdReceiveState check failed
      cmocka_unit_test(TestSpdmRequesterFinishCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterFinishCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterFinishCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterFinishCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterFinishCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterFinishCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterFinishCase9),
  };
  
  SetupSpdmTestContext (&mSpdmRequesterFinishTestContext);

  return cmocka_run_group_tests(SpdmRequesterFinishTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
