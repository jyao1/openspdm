/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

typedef struct {
  UINT8                    RequestResponseCode;
  SPDM_GET_RESPONSE_FUNC   GetResponseFunc;
} SPDM_GET_RESPONSE_STRUCT;

typedef struct {
  UINT8                            RequestResponseCode;
  SPDM_GET_RESPONSE_SESSION_FUNC   GetResponseSessionFunc;
} SPDM_GET_RESPONSE_SESSION_STRUCT;

SPDM_GET_RESPONSE_STRUCT  mSpdmGetResponseStruct[] = {
  {SPDM_GET_VERSION,            SpdmGetResponseVersion},
  {SPDM_GET_CAPABILITIES,       SpdmGetResponseCapability},
  {SPDM_NEGOTIATE_ALGORITHMS,   SpdmGetResponseAlgorithm},
  {SPDM_GET_DIGESTS,            SpdmGetResponseDigest},
  {SPDM_GET_CERTIFICATE,        SpdmGetResponseCertificate},
  {SPDM_CHALLENGE,              SpdmGetResponseChallenge},
  {SPDM_GET_MEASUREMENTS,       SpdmGetResponseMeasurement},
  {SPDM_KEY_EXCHANGE,           SpdmGetResponseKeyExchange},
  {SPDM_PSK_EXCHANGE,           SpdmGetResponsePskExchange},
};

SPDM_GET_RESPONSE_SESSION_STRUCT  mSpdmGetResponseSessionStruct[] = {
  {SPDM_FINISH,                         SpdmGetResponseFinish},
  {SPDM_PSK_FINISH,                     SpdmGetResponsePskFinish},
  {SPDM_END_SESSION,                    SpdmGetResponseEndSession},
  {SPDM_HEARTBEAT,                      SpdmGetResponseHeartbeat},
  {SPDM_KEY_UPDATE,                     SpdmGetResponseKeyUpdate},
  {SPDM_GET_ENCAPSULATED_REQUEST,       SpdmGetResponseEncapsulatedRequest},
  {SPDM_DELIVER_ENCAPSULATED_RESPONSE,  SpdmGetResponseEncapsulatedResponseAck},
};

SPDM_GET_RESPONSE_FUNC
SpdmGetResponseFuncViaLastRequest (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext
  )
{
  UINTN                Index;
  SPDM_MESSAGE_HEADER  *SpdmRequest;

  SpdmRequest = (VOID *)SpdmContext->LastSpdmRequest;
  for (Index = 0; Index < sizeof(mSpdmGetResponseStruct)/sizeof(mSpdmGetResponseStruct[0]); Index++) {
    if (SpdmRequest->RequestResponseCode == mSpdmGetResponseStruct[Index].RequestResponseCode) {
      return mSpdmGetResponseStruct[Index].GetResponseFunc;
    }
  }
  return NULL;
}

SPDM_GET_RESPONSE_SESSION_FUNC
SpdmGetResponseSessionFuncViaLastRequest (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext
  )
{
  UINTN                Index;
  SPDM_MESSAGE_HEADER  *SpdmRequest;

  SpdmRequest = (VOID *)SpdmContext->LastSpdmRequest;
  for (Index = 0; Index < sizeof(mSpdmGetResponseSessionStruct)/sizeof(mSpdmGetResponseSessionStruct[0]); Index++) {
    if (SpdmRequest->RequestResponseCode == mSpdmGetResponseSessionStruct[Index].RequestResponseCode) {
      return mSpdmGetResponseSessionStruct[Index].GetResponseSessionFunc;
    }
  }
  return NULL;
}

RETURN_STATUS
SpdmDecReceiveRequest (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT32                  SessionId,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN OUT UINTN                   *DecRequestSize,
     OUT VOID                    *DecRequest
  )
{
  UINTN                          PlainTextSize;
  UINTN                          CipherTextSize;
  UINTN                          AeadBlockSize;
  UINTN                          AeadTagSize;
  UINT8                          *AData;
  UINT8                          *EncMsg;
  UINT8                          *DecMsg;
  UINT8                          *Tag;
  MCTP_MESSAGE_PLAINTEXT_HEADER  *RecordHeader;
  MCTP_MESSAGE_CIPHERTEXT_HEADER *EncMsgHeader;
  AEAD_DECRYPT                   AeadDecFunc;
  BOOLEAN                        Result;
  VOID                           *Key;
  UINT8                          Salt[MAX_AEAD_IV_SIZE];
  SPDM_SESSION_INFO              *SessionInfo;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }
  
  switch (SessionInfo->SessionState) {
  case SpdmStateHandshaking:
    Key = SessionInfo->HandshakeSecret.RequestHandshakeEncryptionKey;
    CopyMem (Salt, SessionInfo->HandshakeSecret.RequestHandshakeSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber;
    SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber ++;
    break;
  case SpdmStateEstablished:
    Key = SessionInfo->ApplicationSecret.RequestDataEncryptionKey;
    CopyMem (Salt, SessionInfo->ApplicationSecret.RequestDataSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->ApplicationSecret.RequestDataSequenceNumber;
    SessionInfo->ApplicationSecret.RequestDataSequenceNumber ++;
    break;
  default:
    ASSERT(FALSE);
    return RETURN_UNSUPPORTED;
    break;
  }
  
  AeadDecFunc = GetSpdmAeadDecFunc (SpdmContext);
  AeadBlockSize = GetSpdmAeadBlockSize (SpdmContext);
  AeadTagSize = GetSpdmAeadTagSize (SpdmContext);

  if (RequestSize < sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) + AeadBlockSize + AeadTagSize) {
    return RETURN_DEVICE_ERROR;
  }
  RecordHeader = (VOID *)Request;
  if (RecordHeader->SessionId != SessionId) {
    return RETURN_DEVICE_ERROR;
  }
  if (RecordHeader->Length != RequestSize) {
    return RETURN_DEVICE_ERROR;
  }
  CipherTextSize = (RequestSize - sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) - AeadTagSize) / AeadBlockSize * AeadBlockSize;
  RequestSize = CipherTextSize + sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) + AeadTagSize;
  EncMsgHeader = (VOID *)(RecordHeader + 1);
  AData = (UINT8 *)RecordHeader;
  EncMsg = (UINT8 *)EncMsgHeader;
  DecMsg = (UINT8 *)EncMsgHeader;
  Tag = (UINT8 *)Request + RequestSize - AeadTagSize;
  Result = AeadDecFunc (
             Key,
             SessionInfo->AeadKeySize,
             Salt,
             SessionInfo->AeadIvSize,
             (UINT8 *)AData,
             sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER),
             EncMsg,
             CipherTextSize,
             Tag,
             AeadTagSize,
             DecMsg,
             &CipherTextSize
             );
  if (!Result) {
    return RETURN_DEVICE_ERROR;
  }
  PlainTextSize = EncMsgHeader->TrueLength;
  if (PlainTextSize > CipherTextSize) {
    return RETURN_DEVICE_ERROR;      
  }
  if (EncMsgHeader->EncapsulatedMessageType.MessageType != MCTP_MESSAGE_TYPE_SPDM) {
    return RETURN_DEVICE_ERROR;
  }

  if (*DecRequestSize < PlainTextSize) {
    *DecRequestSize = PlainTextSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *DecRequestSize = PlainTextSize;
  CopyMem (DecRequest, EncMsgHeader + 1, PlainTextSize);

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmReceiveRequestSession (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT32                  SessionId,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request
  )
{
  RETURN_STATUS             Status;
  UINTN                     DecRequestSize;
  UINT8                     DecRequest[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_SESSION_INFO         *SessionInfo;
  SPDM_MESSAGE_HEADER       *SpdmRequest;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  if (Request == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  if (RequestSize == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  if (SpdmContext->Alignment > 1) {
    ASSERT ((RequestSize & (SpdmContext->Alignment - 1)) == 0);
  }

  DEBUG((DEBUG_INFO, "SpdmReceiveRequestSession[%x] ...\n", SessionId));

  SpdmRequest = (VOID *)SpdmContext->LastSpdmRequest;
  SpdmContext->LastSpdmRequestSize = 0;
  ZeroMem (SpdmContext->LastSpdmRequest, sizeof(SpdmContext->LastSpdmRequest));

  switch (SessionInfo->SessionState) {
  case SpdmStateHandshaking:
  case SpdmStateEstablished:
  
    ASSERT (SpdmContext->SecureMessageType == SpdmIoSecureMessagingTypeDmtfMtcp);

    DecRequestSize = sizeof(DecRequest);
    ZeroMem (DecRequest, sizeof(DecRequest));
    Status = SpdmDecReceiveRequest (SpdmContext, SessionId, RequestSize, Request, &DecRequestSize, DecRequest);
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "SpdmDecReceiveRequest - %p\n", Status));
      return Status;
    }
    SpdmContext->LastSpdmRequestSize = DecRequestSize;
    CopyMem (SpdmRequest, DecRequest, DecRequestSize);

    DEBUG((DEBUG_INFO, "SpdmReceiveRequestSession[%x] (0x%x): \n", SessionId, SpdmContext->LastSpdmRequestSize));
    InternalDumpHex ((UINT8 *)SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);

    break;
  default:
    ASSERT (FALSE);
    return RETURN_OUT_OF_RESOURCES;
    break;
  }

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmReceiveRequest (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request
  )
{
  SPDM_MESSAGE_HEADER       *SpdmRequest;

  if (Request == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  if (RequestSize == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  if (SpdmContext->Alignment > 1) {
    ASSERT ((RequestSize & (SpdmContext->Alignment - 1)) == 0);
  }

  DEBUG((DEBUG_INFO, "SpdmReceiveRequest (0x%x): \n", RequestSize));
  InternalDumpHex (Request, RequestSize);

  SpdmRequest = (VOID *)SpdmContext->LastSpdmRequest;
  SpdmContext->LastSpdmRequestSize = RequestSize;
  CopyMem (SpdmRequest, Request, RequestSize);

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmEncSendResponse (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT32                  SessionId,
  IN     UINTN                   ResponseSize,
  IN     VOID                    *Response,
  IN OUT UINTN                   *EncResponseSize,
     OUT VOID                    *EncResponse
  )
{
  UINT8                          *WrappedResponse;
  UINTN                          WrappedResponseSize;
  UINTN                          PlainTextSize;
  UINTN                          CipherTextSize;
  UINTN                          AeadBlockSize;
  UINTN                          AeadTagSize;
  UINT8                          *AData;
  UINT8                          *EncMsg;
  UINT8                          *DecMsg;
  UINT8                          *Tag;
  MCTP_MESSAGE_PLAINTEXT_HEADER  *RecordHeader;
  MCTP_MESSAGE_CIPHERTEXT_HEADER *EncMsgHeader;
  AEAD_ENCRYPT                   AeadEncFunc;
  BOOLEAN                        Result;
  VOID                           *Key;
  UINT8                          Salt[MAX_AEAD_IV_SIZE];
  SPDM_SESSION_INFO              *SessionInfo;
  
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }
  
  switch (SessionInfo->SessionState) {
  case SpdmStateHandshaking:
    Key = SessionInfo->HandshakeSecret.ResponseHandshakeEncryptionKey;
    CopyMem (Salt, SessionInfo->HandshakeSecret.ResponseHandshakeSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->HandshakeSecret.ResponseHandshakeSequenceNumber;
    SessionInfo->HandshakeSecret.ResponseHandshakeSequenceNumber ++;
    break;
  case SpdmStateEstablished:
    Key = SessionInfo->ApplicationSecret.ResponseDataEncryptionKey;
    CopyMem (Salt, SessionInfo->ApplicationSecret.ResponseDataSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->ApplicationSecret.ResponseDataSequenceNumber;
    SessionInfo->ApplicationSecret.ResponseDataSequenceNumber ++;
    break;
  default:
    ASSERT(FALSE);
    return RETURN_UNSUPPORTED;
    break;
  }
    
  AeadEncFunc = GetSpdmAeadEncFunc (SpdmContext);
  AeadBlockSize = GetSpdmAeadBlockSize (SpdmContext);
  AeadTagSize = GetSpdmAeadTagSize (SpdmContext);
  PlainTextSize = sizeof(MCTP_MESSAGE_CIPHERTEXT_HEADER) + ResponseSize;
  CipherTextSize = (PlainTextSize + AeadBlockSize - 1) / AeadBlockSize * AeadBlockSize;
  WrappedResponseSize = sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) + CipherTextSize + AeadTagSize;
  if ((SpdmContext->Alignment > 1) && 
      ((WrappedResponseSize & (SpdmContext->Alignment - 1)) != 0)) {
    WrappedResponseSize = (WrappedResponseSize + (SpdmContext->Alignment - 1)) & ~(SpdmContext->Alignment - 1);
  }

  if (*EncResponseSize < WrappedResponseSize) {
    *EncResponseSize = WrappedResponseSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *EncResponseSize = WrappedResponseSize;
  WrappedResponse = EncResponse;
  RecordHeader = (VOID *)WrappedResponse;
  RecordHeader->SessionId = SessionId;
  RecordHeader->Length = (UINT16)WrappedResponseSize;
  EncMsgHeader = (VOID *)(RecordHeader + 1);
  EncMsgHeader->TrueLength = (UINT16)ResponseSize;
  EncMsgHeader->EncapsulatedMessageType.MessageType = MCTP_MESSAGE_TYPE_SPDM;
  CopyMem (EncMsgHeader + 1, Response, ResponseSize);
  AData = (UINT8 *)RecordHeader;
  EncMsg = (UINT8 *)EncMsgHeader;
  DecMsg = (UINT8 *)EncMsgHeader;
  Tag = WrappedResponse + sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) + CipherTextSize;
  Result = AeadEncFunc (
             Key,
             SessionInfo->AeadKeySize,
             Salt,
             SessionInfo->AeadIvSize,
             (UINT8 *)AData,
             sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER),
             DecMsg,
             CipherTextSize,
             Tag,
             AeadTagSize,
             EncMsg,
             &CipherTextSize
             );
  if (!Result) {
    return RETURN_OUT_OF_RESOURCES;
  }
  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmSendResponseSession (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT32                  SessionId,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response
  )
{
  UINT8                             MyResponse[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                             MyResponseSize;
  UINTN                             EncResponseSize;
  UINT8                             EncResponse[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  RETURN_STATUS                     Status;
  SPDM_GET_RESPONSE_SESSION_FUNC    GetResponseSessionFunc;
  SPDM_SESSION_INFO                 *SessionInfo;
  SPDM_MESSAGE_HEADER               *SpdmRequest;
  SPDM_MESSAGE_HEADER               *SpdmResponse;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  if (Response == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  if (ResponseSize == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  if (*ResponseSize == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  DEBUG((DEBUG_INFO, "SpdmSendResponseSession[%x] ...\n", SessionId));

  SpdmRequest = (VOID *)SpdmContext->LastSpdmRequest;
  if (SpdmContext->LastSpdmRequestSize == 0) {
    return RETURN_NOT_READY;
  }

  MyResponseSize = sizeof(MyResponse);
  ZeroMem (MyResponse, sizeof(MyResponse));
  GetResponseSessionFunc = SpdmGetResponseSessionFuncViaLastRequest (SpdmContext);
  if (GetResponseSessionFunc == NULL) {
    GetResponseSessionFunc = (SPDM_GET_RESPONSE_SESSION_FUNC)SpdmContext->GetResponseSessionFunc;
  }
  if (GetResponseSessionFunc != NULL) {
    Status = GetResponseSessionFunc (SpdmContext, SessionId, SpdmContext->LastSpdmRequestSize, SpdmContext->LastSpdmRequest, &MyResponseSize, MyResponse);
  } else {
    Status = RETURN_NOT_FOUND;
  }
  if (Status != RETURN_SUCCESS) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SpdmRequest->RequestResponseCode, &MyResponseSize, MyResponse);
  }

  DEBUG((DEBUG_INFO, "SpdmSendResponseSession[%x] (0x%x): \n", SessionId, MyResponseSize));
  InternalDumpHex (MyResponse, MyResponseSize);

  switch (SessionInfo->SessionState) {
  case SpdmStateHandshaking:
  case SpdmStateEstablished:
  
    ASSERT (SpdmContext->SecureMessageType == SpdmIoSecureMessagingTypeDmtfMtcp);

    EncResponseSize = sizeof(EncResponse);
    ZeroMem (EncResponse, sizeof(EncResponse));
    Status = SpdmEncSendResponse (SpdmContext, SessionId, MyResponseSize, MyResponse, &EncResponseSize, EncResponse);
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "SpdmEncSendResponse - %p\n", Status));
      return Status;
    }

    if (*ResponseSize < EncResponseSize) {
      CopyMem (Response, EncResponse, *ResponseSize);
      *ResponseSize = EncResponseSize;
      return RETURN_BUFFER_TOO_SMALL;
    }  
    CopyMem (Response, EncResponse, EncResponseSize);
    *ResponseSize = EncResponseSize;
    break;
  default:
    ASSERT (FALSE);
    return RETURN_OUT_OF_RESOURCES;
    break;
  }

  SpdmResponse = (VOID *)MyResponse;
  switch (SpdmResponse->RequestResponseCode) {
  case SPDM_FINISH_RSP:
    SessionInfo->SessionState = SpdmStateEstablished;
    break;
  case SPDM_PSK_FINISH_RSP:
    SessionInfo->SessionState = SpdmStateEstablished;
    break;
  case SPDM_END_SESSION_ACK:
    SessionInfo->SessionState = SpdmStateNotStarted;
    SpdmFreeSessionId(SpdmContext, SessionId);
    break;
  }
  
  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmSendResponse (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response
  )
{
  UINT8                     MyResponse[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                     MyResponseSize;
  RETURN_STATUS             Status;
  SPDM_GET_RESPONSE_FUNC    GetResponseFunc;
  SPDM_MESSAGE_HEADER       *SpdmRequest;

  DEBUG((DEBUG_INFO, "SpdmSendResponse ...\n"));

  if (Response == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  if (ResponseSize == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  if (*ResponseSize == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  SpdmRequest = (VOID *)SpdmContext->LastSpdmRequest;
  if (SpdmContext->LastSpdmRequestSize == 0) {
    return RETURN_NOT_READY;
  }

  MyResponseSize = sizeof(MyResponse);
  ZeroMem (MyResponse, sizeof(MyResponse));
  GetResponseFunc = SpdmGetResponseFuncViaLastRequest (SpdmContext);
  if (GetResponseFunc == NULL) {
    GetResponseFunc = (SPDM_GET_RESPONSE_FUNC)SpdmContext->GetResponseFunc;
  }
  if (GetResponseFunc != NULL) {
    Status = GetResponseFunc (SpdmContext, SpdmContext->LastSpdmRequestSize, SpdmContext->LastSpdmRequest, &MyResponseSize, MyResponse);
  } else {
    Status = RETURN_NOT_FOUND;
  }
  if (Status != RETURN_SUCCESS) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SpdmRequest->RequestResponseCode, &MyResponseSize, MyResponse);
  }

  if (SpdmContext->Alignment > 1) {
    MyResponseSize = (MyResponseSize + (SpdmContext->Alignment - 1)) & ~(SpdmContext->Alignment - 1);
  }

  if (*ResponseSize < MyResponseSize) {
    CopyMem (Response, MyResponse, *ResponseSize);
    *ResponseSize = MyResponseSize;
    return RETURN_BUFFER_TOO_SMALL;
  }  
  CopyMem (Response, MyResponse, MyResponseSize);
  *ResponseSize = MyResponseSize;

  DEBUG((DEBUG_INFO, "SpdmSendResponse (0x%x): \n", *ResponseSize));
  InternalDumpHex (Response, *ResponseSize);

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmRegisterGetResponseFunc (
  IN  VOID                    *Context,
  IN  SPDM_GET_RESPONSE_FUNC  GetResponseFunc
  )
{
  SPDM_DEVICE_CONTEXT      *SpdmContext;

  SpdmContext = Context;
  SpdmContext->GetResponseFunc = (UINTN)GetResponseFunc;

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmRegisterGetResponseSessionFunc (
  IN  VOID                            *Context,
  IN  SPDM_GET_RESPONSE_SESSION_FUNC  GetResponseSessionFunc
  )
{
  SPDM_DEVICE_CONTEXT      *SpdmContext;

  SpdmContext = Context;
  SpdmContext->GetResponseSessionFunc = (UINTN)GetResponseSessionFunc;

  return RETURN_SUCCESS;
}
