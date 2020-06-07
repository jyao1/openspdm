/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

RETURN_STATUS
SpdmEncSendRequest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *EncRequestSize,
     OUT VOID                 *EncRequest
  )
{
  UINT8                          *WrappedRequest;
  UINTN                          WrappedRequestSize;
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
    Key = SessionInfo->RequestHandshakeEncryptionKey;
    CopyMem (Salt, SessionInfo->RequestHandshakeSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->RequestHandshakeSequenceNumber;
    SessionInfo->RequestHandshakeSequenceNumber ++;
    break;
  case SpdmStateEstablished:
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
  
  AeadEncFunc = GetSpdmAeadEncFunc (SpdmContext);
  AeadBlockSize = GetSpdmAeadBlockSize (SpdmContext);
  AeadTagSize = GetSpdmAeadTagSize (SpdmContext);
  PlainTextSize = sizeof(MCTP_MESSAGE_CIPHERTEXT_HEADER) + RequestSize;
  CipherTextSize = (PlainTextSize + AeadBlockSize - 1) / AeadBlockSize * AeadBlockSize;
  WrappedRequestSize = sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) + CipherTextSize + AeadTagSize;
  if (*EncRequestSize < WrappedRequestSize) {
    *EncRequestSize = WrappedRequestSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *EncRequestSize = WrappedRequestSize;
  WrappedRequest = EncRequest;
  RecordHeader = (VOID *)WrappedRequest;
  RecordHeader->SessionId = SessionId;
  RecordHeader->Length = (UINT16)WrappedRequestSize;
  EncMsgHeader = (VOID *)(RecordHeader + 1);
  EncMsgHeader->TrueLength = (UINT16)RequestSize;
  EncMsgHeader->EncapsulatedMessageType.MessageType = MCTP_MESSAGE_TYPE_SPDM;
  CopyMem (EncMsgHeader + 1, Request, RequestSize);
  AData = (UINT8 *)RecordHeader;
  EncMsg = (UINT8 *)EncMsgHeader;
  DecMsg = (UINT8 *)EncMsgHeader;
  Tag = WrappedRequest + sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) + CipherTextSize;
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
SpdmSendRequestSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request
  )
{
  RETURN_STATUS                      Status;
  UINT8                              EncRequest[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                              EncRequestSize;
  SPDM_SESSION_INFO                  *SessionInfo;
  SPDM_MESSAGE_HEADER                *SpdmRequest;

  DEBUG((DEBUG_INFO, "SpdmSendRequestSession[%x] (0x%x): \n", SessionId, RequestSize));
  InternalDumpHex (Request, RequestSize);

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  switch (SessionInfo->SessionState) {
  case SpdmStateHandshaking:
  case SpdmStateEstablished:
    EncRequestSize = sizeof(EncRequest);
    ZeroMem (EncRequest, sizeof(EncRequest));
    Status = SpdmEncSendRequest (SpdmContext, SessionId, RequestSize, Request, &EncRequestSize, EncRequest);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
    Status = SpdmContext->SpdmIo->SecureSendRequest (SpdmContext->SpdmIo, SpdmIoSecureMessagingTypeDmtfMtcp, SessionId, EncRequestSize, EncRequest, 0);
    break;
  default:
    ASSERT (FALSE);
    return RETURN_OUT_OF_RESOURCES;
  }

  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmSendRequestSession[%x] Status - %p\n", SessionId, Status));
  } else {
    SpdmRequest = Request;
    switch (SpdmRequest->RequestResponseCode) {
    case SPDM_FINISH:
      //
      // Message is appended for MAC calculation
      //
      break;
    case SPDM_PSK_FINISH:
      //
      // Message is appended for MAC calculation
      //
      break;
    case SPDM_END_SESSION:
      break;
    case SPDM_VENDOR_DEFINED_REQUEST:
      break;
    default:
      ASSERT(FALSE);
      break;
    }
  }

  return Status;
}

/**
  Send a SPDM request command to a device.
  
  @param  SpdmContext                  The SPDM context for the device.
  @param  RequestSize                  Size in bytes of the request data buffer.
  @param  Request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
                                       
  @retval RETURN_SUCCESS                  The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM request is sent to the device.
  @retval RETURN_INVALID_PARAMETER        The Request is NULL or the RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                       to execute.
**/
RETURN_STATUS
SpdmSendRequest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request
  )
{
  RETURN_STATUS                      Status;
  SPDM_MESSAGE_HEADER                *SpdmRequest;

  DEBUG((DEBUG_INFO, "SpdmSendRequest (0x%x): \n", RequestSize));
  InternalDumpHex (Request, RequestSize);

  Status = SpdmContext->SpdmIo->SendRequest (SpdmContext->SpdmIo, RequestSize, Request, 0);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmSendRequest Status - %p\n", Status));
  } else {
    SpdmRequest = Request;
    switch (SpdmRequest->RequestResponseCode) {
    case SPDM_GET_VERSION:
      ResetManagedBuffer (&SpdmContext->Transcript.MessageA);
      ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
      ResetManagedBuffer (&SpdmContext->Transcript.MessageC);
      ResetManagedBuffer (&SpdmContext->Transcript.M1M2);
      // passthru
    case SPDM_GET_CAPABILITIES:
    case SPDM_NEGOTIATE_ALGORITHMS:
      AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Request, RequestSize);
      break;
    case SPDM_GET_DIGESTS:
    case SPDM_GET_CERTIFICATE:
      AppendManagedBuffer (&SpdmContext->Transcript.MessageB, Request, RequestSize);
      break;
    case SPDM_CHALLENGE:
      AppendManagedBuffer (&SpdmContext->Transcript.MessageC, Request, RequestSize);
      break;
    case SPDM_GET_MEASUREMENTS:
      ResetManagedBuffer (&SpdmContext->Transcript.M1M2);
      
      if ((((SPDM_MESSAGE_HEADER *)Request)->Param1 & BIT0) != 0) {
        SpdmContext->Transcript.GetMeasurementWithSign = TRUE;
      } else {
        SpdmContext->Transcript.GetMeasurementWithSign = FALSE;
      }
      AppendManagedBuffer (&SpdmContext->Transcript.L1L2, Request, RequestSize);
      break;
    case SPDM_KEY_EXCHANGE:
      // will be done in KeyExchange, because SessionInfo is unknown.
      break;
    case SPDM_PSK_EXCHANGE:
      // will be done in KeyExchange, because SessionInfo is unknown.
      break;
    case SPDM_VENDOR_DEFINED_REQUEST:
      break;
    default:
      ASSERT(FALSE);
      break;
    }
  }

  return Status;
}

RETURN_STATUS
SpdmDecReceiveResponse (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINTN                ResponseSize,
  IN     VOID                 *Response,
  IN OUT UINTN                *DecResponseSize,
     OUT VOID                 *DecResponse
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
    Key = SessionInfo->ResponseHandshakeEncryptionKey;
    CopyMem (Salt, SessionInfo->ResponseHandshakeSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->ResponseHandshakeSequenceNumber;
    SessionInfo->ResponseHandshakeSequenceNumber ++;
    break;
  case SpdmStateEstablished:
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
  
  AeadDecFunc = GetSpdmAeadDecFunc (SpdmContext);
  AeadBlockSize = GetSpdmAeadBlockSize (SpdmContext);
  AeadTagSize = GetSpdmAeadTagSize (SpdmContext);

  if (ResponseSize < sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) + AeadBlockSize + AeadTagSize) {
    return RETURN_DEVICE_ERROR;
  }
  CipherTextSize = ResponseSize - sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) - AeadTagSize;
  RecordHeader = (VOID *)Response;
  if (RecordHeader->SessionId != SessionId) {
    return RETURN_DEVICE_ERROR;
  }
  if (RecordHeader->Length != ResponseSize) {
    return RETURN_DEVICE_ERROR;
  }
  EncMsgHeader = (VOID *)(RecordHeader + 1);
  AData = (UINT8 *)RecordHeader;
  EncMsg = (UINT8 *)EncMsgHeader;
  DecMsg = (UINT8 *)EncMsgHeader;
  Tag = (UINT8 *)Response + ResponseSize - AeadTagSize;
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

  if (*DecResponseSize < PlainTextSize) {
    *DecResponseSize = PlainTextSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *DecResponseSize = PlainTextSize;
  CopyMem (DecResponse, EncMsgHeader + 1, PlainTextSize);

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmReceiveResponseSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN OUT UINTN                *ResponseSize,
  IN OUT VOID                 *Response
  )
{
  RETURN_STATUS                  Status;
  UINTN                          MyResponseSize;
  UINT8                          MyResponse[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                          DecResponseSize;
  UINT8                          DecResponse[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_SESSION_INFO              *SessionInfo;
  SPDM_MESSAGE_HEADER            *SpdmResponse;
  
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  switch (SessionInfo->SessionState) {
  case SpdmStateHandshaking:
  case SpdmStateEstablished:
    MyResponseSize = sizeof(MyResponse);
    ZeroMem (MyResponse, sizeof(MyResponse));
    Status = SpdmContext->SpdmIo->SecureReceiveResponse (SpdmContext->SpdmIo, SpdmIoSecureMessagingTypeDmtfMtcp, SessionId, &MyResponseSize, MyResponse, 0);
    if (RETURN_ERROR(Status)) {
      DEBUG((DEBUG_INFO, "SpdmReceiveResponseSession[%x] Status - %p\n", SessionId, Status));
      return Status;
    }
    DecResponseSize = sizeof(DecResponse);
    ZeroMem (DecResponse, sizeof(DecResponse));
    Status = SpdmDecReceiveResponse (SpdmContext, SessionId, MyResponseSize, MyResponse, &DecResponseSize, DecResponse);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
    if (*ResponseSize < DecResponseSize) {
      *ResponseSize = DecResponseSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *ResponseSize = DecResponseSize;
    CopyMem (Response, DecResponse, DecResponseSize);
    break;
  default:
    ASSERT (FALSE);
    return RETURN_OUT_OF_RESOURCES;
    break;
  }

  DEBUG((DEBUG_INFO, "SpdmReceiveResponseSession[%x] (0x%x): \n", SessionId, *ResponseSize));
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmReceiveResponseSession[%x] Status - %p\n", SessionId, Status));    
  } else {
    InternalDumpHex (Response, *ResponseSize);

    SpdmResponse = Response;
    switch (SpdmResponse->RequestResponseCode) {
    case SPDM_FINISH_RSP:
      // will be done in Finish().
      break;
    case SPDM_PSK_FINISH_RSP:
      // will be done in Finish().
      break;
    case SPDM_END_SESSION_ACK:
      break;
    case SPDM_VENDOR_DEFINED_RESPONSE:
      break;
    default:
      ASSERT(FALSE);
      break;
    }
  }
  return Status;
}

/**
  Receive a SPDM response from a device.
  
  @param  SpdmContext                  The SPDM context for the device.
  @param  ResponseSize                 Size in bytes of the response data buffer.
  @param  Response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
                                       
  @retval RETURN_SUCCESS                  The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM response is received from the device.
  @retval RETURN_INVALID_PARAMETER        The Reponse is NULL, ResponseSize is NULL or
                                       the *RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM response
                                       to execute.
**/
RETURN_STATUS
SpdmReceiveResponse (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *ResponseSize,
  IN OUT VOID                 *Response
  )
{
  RETURN_STATUS             Status;
  UINTN                     SignatureSize;
  SPDM_MESSAGE_HEADER       *SpdmResponse;
  
  Status = SpdmContext->SpdmIo->ReceiveResponse (SpdmContext->SpdmIo, ResponseSize, Response, 0);

  DEBUG((DEBUG_INFO, "SpdmReceiveResponse (0x%x): \n", *ResponseSize));
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmReceiveResponse Status - %p\n", Status));    
  } else {
    InternalDumpHex (Response, *ResponseSize);

    SpdmResponse = Response;
    switch (SpdmResponse->RequestResponseCode) {
    case SPDM_VERSION:
    case SPDM_CAPABILITIES:
    case SPDM_ALGORITHMS:
      AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Response, *ResponseSize);
      break;
    case SPDM_DIGESTS:
    case SPDM_CERTIFICATE:
      AppendManagedBuffer (&SpdmContext->Transcript.MessageB, Response, *ResponseSize);
      break;
    case SPDM_CHALLENGE_AUTH:
      // Need remove signature.
      SignatureSize = GetSpdmAsymSize (SpdmContext);
      if (*ResponseSize > SignatureSize) {
        AppendManagedBuffer (&SpdmContext->Transcript.MessageC, Response, *ResponseSize - SignatureSize);
        AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
        AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageB), GetManagedBufferSize(&SpdmContext->Transcript.MessageB));
        AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageC), GetManagedBufferSize(&SpdmContext->Transcript.MessageC));
      }
      break;
    case SPDM_MEASUREMENTS:
      if (SpdmContext->Transcript.GetMeasurementWithSign) {
        // Need remove signature.
        SignatureSize = GetSpdmAsymSize (SpdmContext);
        if (*ResponseSize > SignatureSize) {
          AppendManagedBuffer (&SpdmContext->Transcript.L1L2, Response, *ResponseSize - SignatureSize);
        }
      } else {
        AppendManagedBuffer (&SpdmContext->Transcript.L1L2, Response, *ResponseSize);
      }
      break;
    case SPDM_KEY_EXCHANGE_RSP:
      // will be done in KeyExchange, because SessionInfo is unknown.
      break;
    case SPDM_PSK_EXCHANGE_RSP:
      // will be done in KeyExchange, because SessionInfo is unknown.
      break;
    case SPDM_VENDOR_DEFINED_RESPONSE:
      break;
    default:
      ASSERT(FALSE);
      break;
    }
  }
  return Status;
}
