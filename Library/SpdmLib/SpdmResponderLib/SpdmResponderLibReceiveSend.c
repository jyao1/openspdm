/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

typedef struct {
  UINT8                            RequestResponseCode;
  SPDM_GET_SPDM_RESPONSE_FUNC      GetResponseFunc;
} SPDM_GET_RESPONSE_STRUCT;

SPDM_GET_RESPONSE_STRUCT  mSpdmGetResponseStruct[] = {
  {SPDM_GET_VERSION,                    SpdmGetResponseVersion},
  {SPDM_GET_CAPABILITIES,               SpdmGetResponseCapability},
  {SPDM_NEGOTIATE_ALGORITHMS,           SpdmGetResponseAlgorithm},
  {SPDM_GET_DIGESTS,                    SpdmGetResponseDigest},
  {SPDM_GET_CERTIFICATE,                SpdmGetResponseCertificate},
  {SPDM_CHALLENGE,                      SpdmGetResponseChallengeAuth},
  {SPDM_GET_MEASUREMENTS,               SpdmGetResponseMeasurement},
  {SPDM_KEY_EXCHANGE,                   SpdmGetResponseKeyExchange},
  {SPDM_PSK_EXCHANGE,                   SpdmGetResponsePskExchange},
  {SPDM_GET_ENCAPSULATED_REQUEST,       SpdmGetResponseEncapsulatedRequest},
  {SPDM_DELIVER_ENCAPSULATED_RESPONSE,  SpdmGetResponseEncapsulatedResponseAck},
  {SPDM_RESPOND_IF_READY,               SpdmGetResponseRespondIfReady},

  {SPDM_FINISH,                         SpdmGetResponseFinish},
  {SPDM_PSK_FINISH,                     SpdmGetResponsePskFinish},
  {SPDM_END_SESSION,                    SpdmGetResponseEndSession},
  {SPDM_HEARTBEAT,                      SpdmGetResponseHeartbeat},
  {SPDM_KEY_UPDATE,                     SpdmGetResponseKeyUpdate},
};

SPDM_GET_SPDM_RESPONSE_FUNC
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

SPDM_GET_SPDM_RESPONSE_FUNC
SpdmGetResponseFuncViaRequestCode (
  IN     UINT8                    RequestCode
  )
{
  UINTN                Index;

  ASSERT(RequestCode != SPDM_RESPOND_IF_READY);
  for (Index = 0; Index < sizeof(mSpdmGetResponseStruct)/sizeof(mSpdmGetResponseStruct[0]); Index++) {
    if (RequestCode == mSpdmGetResponseStruct[Index].RequestResponseCode) {
      return mSpdmGetResponseStruct[Index].GetResponseFunc;
    }
  }
  return NULL;
}

RETURN_STATUS
SpdmReceiveRequestEx (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
     OUT UINT32                  **SessionId,
     OUT BOOLEAN                 *IsAppMessage,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request
  )
{
  RETURN_STATUS             Status;
  SPDM_SESSION_INFO         *SessionInfo;
  UINT32                    *MessageSessionId;

  if (Request == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  if (RequestSize == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  DEBUG((DEBUG_INFO, "SpdmReceiveRequest[.] ...\n"));

  MessageSessionId = NULL;
  SpdmContext->LastSpdmRequestSessionIdValid = FALSE;
  SpdmContext->LastSpdmRequestSize = sizeof(SpdmContext->LastSpdmRequest);
  Status = SpdmContext->TransportDecodeMessage (SpdmContext, &MessageSessionId, IsAppMessage, TRUE, RequestSize, Request, &SpdmContext->LastSpdmRequestSize, SpdmContext->LastSpdmRequest);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "TransportDecodeMessage : %p\n", Status));
    return Status;
  }

  *SessionId = MessageSessionId;

  if (MessageSessionId != NULL) {
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, *MessageSessionId);
    if (SessionInfo == NULL) {
      return RETURN_UNSUPPORTED;
    }
    SpdmContext->LastSpdmRequestSessionId = *MessageSessionId;
    SpdmContext->LastSpdmRequestSessionIdValid = TRUE;
  } 

  DEBUG((DEBUG_INFO, "SpdmReceiveRequest[%x] (0x%x): \n", (MessageSessionId != NULL) ? *MessageSessionId : 0, SpdmContext->LastSpdmRequestSize));
  InternalDumpHex ((UINT8 *)SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmSendResponseEx (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT32                  *SessionId,
  IN     BOOLEAN                 IsAppMessage,
  IN OUT UINTN                   *ResponseSize,
     OUT VOID                    *Response
  )
{
  UINT8                             MyResponse[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                             MyResponseSize;
  RETURN_STATUS                     Status;
  SPDM_GET_SPDM_RESPONSE_FUNC       GetResponseFunc;
  SPDM_SESSION_INFO                 *SessionInfo;
  SPDM_MESSAGE_HEADER               *SpdmRequest;
  SPDM_MESSAGE_HEADER               *SpdmResponse;

  if (SessionId != NULL) {
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, *SessionId);
    if (SessionInfo == NULL) {
      ASSERT (FALSE);
      return RETURN_UNSUPPORTED;
    }
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

  DEBUG((DEBUG_INFO, "SpdmSendResponse[%x] ...\n", (SessionId != NULL) ? *SessionId : 0));

  SpdmRequest = (VOID *)SpdmContext->LastSpdmRequest;
  if (SpdmContext->LastSpdmRequestSize == 0) {
    return RETURN_NOT_READY;
  }

  MyResponseSize = sizeof(MyResponse);
  ZeroMem (MyResponse, sizeof(MyResponse));
  GetResponseFunc = NULL;
  if (!IsAppMessage) {
    GetResponseFunc = SpdmGetResponseFuncViaLastRequest (SpdmContext);
    if (GetResponseFunc != NULL) {
      Status = GetResponseFunc (SpdmContext, SpdmContext->LastSpdmRequestSize, SpdmContext->LastSpdmRequest, &MyResponseSize, MyResponse);
    }
  }
  if (IsAppMessage || (GetResponseFunc == NULL)) {
    if (SpdmContext->GetResponseFunc != 0) {
      Status = ((SPDM_GET_RESPONSE_FUNC)SpdmContext->GetResponseFunc) (SpdmContext, SessionId, IsAppMessage, SpdmContext->LastSpdmRequestSize, SpdmContext->LastSpdmRequest, &MyResponseSize, MyResponse);
    } else {
      Status = RETURN_NOT_FOUND;
    }
  }
  if (Status != RETURN_SUCCESS) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SpdmRequest->RequestResponseCode, &MyResponseSize, MyResponse);
  }

  DEBUG((DEBUG_INFO, "SpdmSendResponse[%x] (0x%x): \n", (SessionId != NULL) ? *SessionId : 0, MyResponseSize));
  InternalDumpHex (MyResponse, MyResponseSize);

  Status = SpdmContext->TransportEncodeMessage (SpdmContext, SessionId, IsAppMessage, FALSE, MyResponseSize, MyResponse, ResponseSize, Response);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "TransportEncodeMessage : %p\n", Status));
    return Status;
  }

  SpdmResponse = (VOID *)MyResponse;
  if (SessionId != NULL) {
    switch (SpdmResponse->RequestResponseCode) {
    case SPDM_FINISH_RSP:
      if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
        SessionInfo->SessionState = SpdmStateEstablished;
      }
      break;
    case SPDM_PSK_FINISH_RSP:
      SessionInfo->SessionState = SpdmStateEstablished;
      break;
    case SPDM_END_SESSION_ACK:
      SessionInfo->SessionState = SpdmStateNotStarted;
      SpdmFreeSessionId(SpdmContext, *SessionId);
      break;
    }
  } else {
    switch (SpdmResponse->RequestResponseCode) {
    case SPDM_FINISH_RSP:
      if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) != 0) {
        SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SpdmContext->LatestSessionId);
        if (SessionInfo == NULL) {
          ASSERT(FALSE);
          return RETURN_SUCCESS;
        }
        SessionInfo->SessionState = SpdmStateEstablished;
      }
      break;
    }
  }
  
  return RETURN_SUCCESS;
}

VOID
EFIAPI
SpdmRegisterGetResponseFunc (
  IN  VOID                    *Context,
  IN  SPDM_GET_RESPONSE_FUNC  GetResponseFunc
  )
{
  SPDM_DEVICE_CONTEXT      *SpdmContext;

  SpdmContext = Context;
  SpdmContext->GetResponseFunc = (UINTN)GetResponseFunc;

  return ;
}
