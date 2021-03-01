/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>
#include <SpdmSecuredMessageLibInternal.h>

STATIC UINT8                  LocalPskHint[32];
STATIC UINT8                  mDummyKeyBuffer[MAX_AEAD_KEY_SIZE];
STATIC UINT8                  mDummySaltBuffer[MAX_AEAD_IV_SIZE];

VOID
SpdmSecuredMessageSetResponseDataEncryptionKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *Key,
  IN UINTN                        KeySize
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  ASSERT (KeySize == SecuredMessageContext->AeadKeySize);
  CopyMem (SecuredMessageContext->ApplicationSecret.ResponseDataEncryptionKey, Key, SecuredMessageContext->AeadKeySize);
}

VOID
SpdmSecuredMessageSetResponseDataSalt (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *Salt,
  IN UINTN                        SaltSize
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  ASSERT (SaltSize == SecuredMessageContext->AeadIvSize);
  CopyMem (SecuredMessageContext->ApplicationSecret.ResponseDataSalt, Salt, SecuredMessageContext->AeadIvSize);
}

RETURN_STATUS
EFIAPI
SpdmRequesterHeartbeatTestSendMessage (
  IN     VOID                    *SpdmContext,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = GetSpdmTestContext ();
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;
  case 0x2:
    return RETURN_SUCCESS;
  case 0x3:
    return RETURN_SUCCESS;
  case 0x4:    
    return RETURN_SUCCESS;
  case 0x5:    
    return RETURN_SUCCESS;
  case 0x6:   
    return RETURN_SUCCESS;
  case 0x7:    
    return RETURN_SUCCESS;
  case 0x8:   
    return RETURN_SUCCESS;
  case 0x9:
    return RETURN_SUCCESS;
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmRequesterHeartbeatTestReceiveMessage (
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
    SPDM_HEARTBEAT_RESPONSE       *SpdmResponse; 
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    UINT32                        SessionId;
    SPDM_SESSION_INFO             *SessionInfo;

    SessionId = 0xFFFFFFFF;
    TempBufSize = sizeof(SPDM_HEARTBEAT_RESPONSE);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_HEARTBEAT_ACK;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, &SessionId, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);    
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
    if (SessionInfo == NULL) {
      return RETURN_DEVICE_ERROR;
    }
    /* WALKAROUND: If just use single context to encode message and then decode message */
    ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber --;
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_HEARTBEAT_RESPONSE       *SpdmResponse; 
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    UINT32                        SessionId;    
    SPDM_SESSION_INFO             *SessionInfo;

    SessionId = 0xFFFFFFFF;
    TempBufSize = sizeof(SPDM_HEARTBEAT_RESPONSE);
    SpdmResponse = (VOID *)TempBuf;
    
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_HEARTBEAT_ACK;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, &SessionId, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
    if (SessionInfo == NULL) {
      return RETURN_DEVICE_ERROR;
    }
    ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber --;
  }
    return RETURN_SUCCESS;

  case 0x4:
  {
    SPDM_ERROR_RESPONSE    SpdmResponse;
    UINT32                 SessionId;
    SPDM_SESSION_INFO      *SessionInfo;

    SessionId = 0xFFFFFFFF;
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, &SessionId, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
    if (SessionInfo == NULL) {
      return RETURN_DEVICE_ERROR;
    }
    ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber --;
  }
    return RETURN_SUCCESS;

  case 0x5:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;
    UINT32               SessionId;
    SPDM_SESSION_INFO    *SessionInfo;

    SessionId = 0xFFFFFFFF;
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, &SessionId, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
    if (SessionInfo == NULL) {
      return RETURN_DEVICE_ERROR;
    }
    ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber --;
  }
    return RETURN_SUCCESS;

  case 0x6:
  {
    STATIC UINTN SubIndex1 = 0;
    if (SubIndex1 == 0) {
      SPDM_ERROR_RESPONSE  SpdmResponse;
      UINT32               SessionId; 
      SPDM_SESSION_INFO    *SessionInfo;

      SessionId = 0xFFFFFFFF;
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
      SpdmResponse.Header.Param2 = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, &SessionId, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex1 ++;
      SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
      if (SessionInfo == NULL) {
        return RETURN_DEVICE_ERROR;
      }
      ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber --;
    } else if (SubIndex1 == 1) {
      SPDM_HEARTBEAT_RESPONSE      *SpdmResponse; 
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT32                        SessionId;
      SPDM_SESSION_INFO             *SessionInfo;

      SessionId = 0xFFFFFFFF;
      TempBufSize = sizeof(SPDM_HEARTBEAT_RESPONSE);
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse->Header.RequestResponseCode = SPDM_HEARTBEAT_ACK;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, &SessionId, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
      SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
      if (SessionInfo == NULL) {
        return RETURN_DEVICE_ERROR;
      }
      ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber --;
    }
  }
    return RETURN_SUCCESS;

  case 0x7:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;
    UINT32               SessionId;
    SPDM_SESSION_INFO    *SessionInfo;

    SessionId = 0xFFFFFFFF;
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, &SessionId, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
    if (SessionInfo == NULL) {
      return RETURN_DEVICE_ERROR;
    }
    ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber --;
  }
    return RETURN_SUCCESS;

  case 0x8:
  {
    SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;
    UINT32                                       SessionId;
    SPDM_SESSION_INFO                            *SessionInfo;

    SessionId = 0xFFFFFFFF;
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.ExtendErrorData.RDTExponent = 1;
    SpdmResponse.ExtendErrorData.RDTM = 1;
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_HEARTBEAT;
    SpdmResponse.ExtendErrorData.Token = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, &SessionId, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
    if (SessionInfo == NULL) {
      return RETURN_DEVICE_ERROR;
    }
    ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber --;
  }
    return RETURN_SUCCESS;

  case 0x9:
  {
    STATIC UINTN SubIndex2 = 0;
    if (SubIndex2 == 0) {
      SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;
      UINT32                                       SessionId;
      SPDM_SESSION_INFO                            *SessionInfo;
      
      SessionId = 0xFFFFFFFF;
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.ExtendErrorData.RDTExponent = 1;
      SpdmResponse.ExtendErrorData.RDTM = 1;
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_HEARTBEAT;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, &SessionId, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex2 ++;
      SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
      if (SessionInfo == NULL) {
        return RETURN_DEVICE_ERROR;
      }
      ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber --;
    } else if (SubIndex2 == 1) {
      SPDM_HEARTBEAT_RESPONSE       *SpdmResponse; 
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT32                        SessionId;
      SPDM_SESSION_INFO             *SessionInfo;

      SessionId = 0xFFFFFFFF;
      TempBufSize = sizeof(SPDM_HEARTBEAT_RESPONSE);
      SpdmResponse = (VOID *)TempBuf;
      
      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse->Header.RequestResponseCode = SPDM_HEARTBEAT_ACK;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, &SessionId, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
      SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
      if (SessionInfo == NULL) {
        return RETURN_DEVICE_ERROR;
      }
      ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber --;
    }
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

void TestSpdmRequesterHeartbeatCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId; 
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, TRUE);  
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);

  Status = SpdmHeartbeat (SpdmContext, SessionId); 
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterHeartbeatCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, TRUE);  
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);
  SetMem (mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataEncryptionKey (SessionInfo->SecuredMessageContext, mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize);
  SetMem (mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataSalt (SessionInfo->SecuredMessageContext, mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize);
  ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber = 0;

  Status = SpdmHeartbeat (SpdmContext, SessionId); 
  assert_int_equal (Status, RETURN_SUCCESS);
  free(Data);
}

void TestSpdmRequesterHeartbeatCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;
  
  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, TRUE);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);
  SetMem (mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataEncryptionKey (SessionInfo->SecuredMessageContext, mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize);
  SetMem (mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataSalt (SessionInfo->SecuredMessageContext, mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize);
  ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber = 0;

  Status = SpdmHeartbeat (SpdmContext, SessionId); 
  assert_int_equal (Status, RETURN_UNSUPPORTED);  
  free(Data);
}

void TestSpdmRequesterHeartbeatCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, TRUE);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);  
  SetMem (mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataEncryptionKey (SessionInfo->SecuredMessageContext, mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize);
  SetMem (mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataSalt (SessionInfo->SecuredMessageContext, mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize);
  ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber = 0;
  
  Status = SpdmHeartbeat (SpdmContext, SessionId); 
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterHeartbeatCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, TRUE);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);  
  SetMem (mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataEncryptionKey (SessionInfo->SecuredMessageContext, mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize);
  SetMem (mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataSalt (SessionInfo->SecuredMessageContext, mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize);
  ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber = 0;
  
  Status = SpdmHeartbeat (SpdmContext, SessionId); 
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  free(Data);
}

void TestSpdmRequesterHeartbeatCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, TRUE);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);
  SetMem (mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataEncryptionKey (SessionInfo->SecuredMessageContext, mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize);
  SetMem (mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataSalt (SessionInfo->SecuredMessageContext, mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize);
  ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber = 0;
  
  Status = SpdmHeartbeat (SpdmContext, SessionId); 
  assert_int_equal (Status, RETURN_SUCCESS);
  free(Data);
}

void TestSpdmRequesterHeartbeatCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, TRUE);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);
  SetMem (mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataEncryptionKey (SessionInfo->SecuredMessageContext, mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize);
  SetMem (mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataSalt (SessionInfo->SecuredMessageContext, mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize);
  ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber = 0;
  
  Status = SpdmHeartbeat (SpdmContext, SessionId); 
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->ConnectionInfo.ConnectionState, SpdmConnectionStateNotStarted);
  free(Data);
}

void TestSpdmRequesterHeartbeatCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, TRUE);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);
  SetMem (mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataEncryptionKey (SessionInfo->SecuredMessageContext, mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize);
  SetMem (mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataSalt (SessionInfo->SecuredMessageContext, mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize);
  ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber = 0;
  
  Status = SpdmHeartbeat (SpdmContext, SessionId); 
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterHeartbeatCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  SPDM_SESSION_INFO    *SessionInfo;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  SessionId = 0xFFFFFFFF;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, TRUE);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);
  SetMem (mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataEncryptionKey (SessionInfo->SecuredMessageContext, mDummyKeyBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadKeySize);
  SetMem (mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetResponseDataSalt (SessionInfo->SecuredMessageContext, mDummySaltBuffer, ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->AeadIvSize);
  ((SPDM_SECURED_MESSAGE_CONTEXT*)(SessionInfo->SecuredMessageContext))->ApplicationSecret.ResponseDataSequenceNumber = 0;
  
  Status = SpdmHeartbeat (SpdmContext, SessionId); 
  assert_int_equal (Status, RETURN_SUCCESS); 
  free(Data);
}

SPDM_TEST_CONTEXT       mSpdmRequesterHeartbeatTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterHeartbeatTestSendMessage,
  SpdmRequesterHeartbeatTestReceiveMessage,
};

int SpdmRequesterHeartbeatTestMain(void) {
  const struct CMUnitTest SpdmRequesterHeartbeatTests[] = {
      // SendRequest failed
      cmocka_unit_test(TestSpdmRequesterHeartbeatCase1),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterHeartbeatCase2),
      // ConnectionState check failed
      cmocka_unit_test(TestSpdmRequesterHeartbeatCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterHeartbeatCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterHeartbeatCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterHeartbeatCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterHeartbeatCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterHeartbeatCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterHeartbeatCase9),
  };
  
  SetupSpdmTestContext (&mSpdmRequesterHeartbeatTestContext);

  return cmocka_run_group_tests(SpdmRequesterHeartbeatTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
