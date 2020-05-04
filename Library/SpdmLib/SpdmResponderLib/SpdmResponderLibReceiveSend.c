/** @file
  EDKII Device Security library for SPDM device.
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
  {SPDM_FINISH,                 SpdmGetResponseFinish},
  {SPDM_PSK_FINISH,             SpdmGetResponsePskFinish},
  {SPDM_END_SESSION,            SpdmGetResponseEndSession},
};

SPDM_GET_RESPONSE_FUNC
SpdmReturnGetResponseFuncViaLastRequest (
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
SpdmReturnGetResponseSessionFuncViaLastRequest (
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
  IN     UINT8                   SessionId,
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
  case EdkiiSpdmStateHandshaking:
    Key = SessionInfo->RequestHandshakeEncryptionKey;
    CopyMem (Salt, SessionInfo->RequestHandshakeSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->RequestHandshakeSequenceNumber;
    SessionInfo->RequestHandshakeSequenceNumber ++;
    break;
  case EdkiiSpdmStateEstablished:
    Key = SessionInfo->RequestDataEncryptionKey;
    CopyMem (Salt, SessionInfo->RequestDataSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->RequestDataSequenceNumber;
    SessionInfo->RequestDataSequenceNumber ++;
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
  CipherTextSize = RequestSize - sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) - AeadTagSize;
  RecordHeader = (VOID *)Request;
  if (RecordHeader->SessionId != SessionId) {
    return RETURN_DEVICE_ERROR;
  }
  if (RecordHeader->Length != RequestSize) {
    return RETURN_DEVICE_ERROR;
  }
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
  IN     UINT8                   SessionId,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request
  )
{
  RETURN_STATUS             Status;
  UINTN                     DecRequestSize;
  UINT8                     DecRequest[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                     HmacSize;
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

  SpdmRequest = (VOID *)SpdmContext->LastSpdmRequest;
  SpdmContext->LastSpdmRequestSize = 0;
  ZeroMem (SpdmContext->LastSpdmRequest, sizeof(SpdmContext->LastSpdmRequest));

  switch (SessionInfo->SessionState) {
  case EdkiiSpdmStateHandshaking:
  case EdkiiSpdmStateEstablished:
    DecRequestSize = sizeof(DecRequest);
    ZeroMem (DecRequest, sizeof(DecRequest));
    Status = SpdmDecReceiveRequest (SpdmContext, SessionId, RequestSize, Request, &DecRequestSize, DecRequest);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
    SpdmContext->LastSpdmRequestSize = DecRequestSize;
    CopyMem (SpdmRequest, DecRequest, DecRequestSize);
    break;
  default:
    ASSERT (FALSE);
    return RETURN_OUT_OF_RESOURCES;
    break;
  }
  
  switch (SpdmRequest->RequestResponseCode) {
  case SPDM_FINISH:
    // remove HMAC
    HmacSize = GetSpdmHashSize (SpdmContext);
    if (RequestSize > HmacSize) {
      AppendManagedBuffer (&SpdmContext->Transcript.MessageF, SpdmRequest, DecRequestSize - HmacSize);
    }
    break;
  case SPDM_PSK_FINISH:
    // remove HMAC
    HmacSize = GetSpdmHashSize (SpdmContext);
    if (RequestSize > HmacSize) {
      AppendManagedBuffer (&SpdmContext->Transcript.MessagePF, SpdmRequest, DecRequestSize - HmacSize);
    }
    break;
  case SPDM_END_SESSION:
    break;
  case SPDM_VENDOR_DEFINED_REQUEST:
    break;
  default:
    ASSERT(FALSE);
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

  SpdmRequest = (VOID *)SpdmContext->LastSpdmRequest;
  SpdmContext->LastSpdmRequestSize = RequestSize;
  CopyMem (SpdmRequest, Request, RequestSize);
  
  switch (SpdmRequest->RequestResponseCode) {
  case SPDM_GET_VERSION:
    ResetManagedBuffer (&SpdmContext->Transcript.MessageA);
    ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
    ResetManagedBuffer (&SpdmContext->Transcript.MessageC);
    ResetManagedBuffer (&SpdmContext->Transcript.M1M2);
    // passthru
  case SPDM_GET_CAPABILITIES:
  case SPDM_NEGOTIATE_ALGORITHMS:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageA, SpdmRequest, RequestSize);
    break;
  case SPDM_GET_DIGESTS:
  case SPDM_GET_CERTIFICATE:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageB, SpdmRequest, RequestSize);
    break;
  case SPDM_CHALLENGE:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageC, SpdmRequest, RequestSize);
    break;
  case SPDM_GET_MEASUREMENTS:
    ResetManagedBuffer (&SpdmContext->Transcript.M1M2);

    if ((SpdmRequest->Param1 & BIT0) != 0) {
      SpdmContext->Transcript.GetMeasurementWithSign = TRUE;
    } else {
      SpdmContext->Transcript.GetMeasurementWithSign = FALSE;
    }
    AppendManagedBuffer (&SpdmContext->Transcript.L1L2, SpdmRequest, RequestSize);
    break;
  case SPDM_KEY_EXCHANGE:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageK, SpdmRequest, RequestSize);
    break;
  case SPDM_PSK_EXCHANGE:
    AppendManagedBuffer (&SpdmContext->Transcript.MessagePK, SpdmRequest, RequestSize);
    break;
  case SPDM_VENDOR_DEFINED_REQUEST:
    break;
  default:
    ASSERT(FALSE);
    break;
  }

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmEncSendResponse (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT8                   SessionId,
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
  case EdkiiSpdmStateHandshaking:
    Key = SessionInfo->ResponseHandshakeEncryptionKey;
    CopyMem (Salt, SessionInfo->ResponseHandshakeSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->ResponseHandshakeSequenceNumber;
    SessionInfo->ResponseHandshakeSequenceNumber ++;
    break;
  case EdkiiSpdmStateEstablished:
    Key = SessionInfo->ResponseDataEncryptionKey;
    CopyMem (Salt, SessionInfo->ResponseDataSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->ResponseDataSequenceNumber;
    SessionInfo->ResponseDataSequenceNumber ++;
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
  IN     UINT8                   SessionId,
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

  SpdmRequest = (VOID *)SpdmContext->LastSpdmRequest;
  if (SpdmContext->LastSpdmRequestSize == 0) {
    return RETURN_NOT_READY;
  }

  MyResponseSize = sizeof(MyResponse);
  ZeroMem (MyResponse, sizeof(MyResponse));
  GetResponseSessionFunc = SpdmReturnGetResponseSessionFuncViaLastRequest (SpdmContext);
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

  switch (SessionInfo->SessionState) {
  case EdkiiSpdmStateHandshaking:
  case EdkiiSpdmStateEstablished:
    EncResponseSize = sizeof(EncResponse);
    ZeroMem (EncResponse, sizeof(EncResponse));
    Status = SpdmEncSendResponse (SpdmContext, SessionId, MyResponseSize, MyResponse, &EncResponseSize, EncResponse);
    if (RETURN_ERROR(Status)) {
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
    AppendManagedBuffer (&SpdmContext->Transcript.MessageF, MyResponse, MyResponseSize);
    SessionInfo->SessionState = EdkiiSpdmStateEstablished;
    break;
  case SPDM_PSK_FINISH_RSP:
    AppendManagedBuffer (&SpdmContext->Transcript.MessagePF, MyResponse, MyResponseSize);
    SessionInfo->SessionState = EdkiiSpdmStateEstablished;
    break;
  case SPDM_END_SESSION_ACK:
    SessionInfo->SessionState = EdkiiSpdmStateNotStarted;
    break;
  case SPDM_VENDOR_DEFINED_RESPONSE:
    break;
  default:
    ASSERT(FALSE);
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
  SPDM_MESSAGE_HEADER       *SpdmResponse;

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
  GetResponseFunc = SpdmReturnGetResponseFuncViaLastRequest (SpdmContext);
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

  if (*ResponseSize < MyResponseSize) {
    CopyMem (Response, MyResponse, *ResponseSize);
    *ResponseSize = MyResponseSize;
    return RETURN_BUFFER_TOO_SMALL;
  }  
  CopyMem (Response, MyResponse, MyResponseSize);
  *ResponseSize = MyResponseSize;

  SpdmResponse = (VOID *)MyResponse;
  switch (SpdmResponse->RequestResponseCode) {
  case SPDM_VERSION:
  case SPDM_CAPABILITIES:
  case SPDM_ALGORITHMS:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageA, MyResponse, MyResponseSize);
    break;
  case SPDM_DIGESTS:
  case SPDM_CERTIFICATE:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageB, MyResponse, MyResponseSize);
    break;
  case SPDM_CHALLENGE_AUTH:
    //
    // The signature is generated in the reponse.
    //
    ResetManagedBuffer (&SpdmContext->Transcript.M1M2);
    break;
  case SPDM_MEASUREMENTS:
    if (SpdmContext->Transcript.GetMeasurementWithSign) {
      //
      // The signature is generated in the reponse.
      //
      ResetManagedBuffer (&SpdmContext->Transcript.L1L2);
    } else {
      AppendManagedBuffer (&SpdmContext->Transcript.L1L2, MyResponse, MyResponseSize);
    }
    break;
  case SPDM_KEY_EXCHANGE_RSP:
    //
    // The signature and HMAC are generated in the reponse.
    //
    break;
  case SPDM_PSK_EXCHANGE_RSP:
    //
    // The signature and HMAC are generated in the reponse.
    //
    break;
  case SPDM_VENDOR_DEFINED_RESPONSE:
    break;
  default:
    ASSERT(FALSE);
    break;
  }

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
