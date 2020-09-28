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
  {SPDM_CHALLENGE,              SpdmGetResponseChallengeAuth},
  {SPDM_GET_MEASUREMENTS,       SpdmGetResponseMeasurement},
  {SPDM_KEY_EXCHANGE,           SpdmGetResponseKeyExchange},
  {SPDM_PSK_EXCHANGE,           SpdmGetResponsePskExchange},
  {SPDM_RESPOND_IF_READY,       SpdmGetResponseRespondIfReady},
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

SPDM_GET_RESPONSE_FUNC
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
SpdmReceiveRequestSession (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT32                  SessionId,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request
  )
{
  RETURN_STATUS             Status;
  SPDM_SESSION_INFO         *SessionInfo;

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

  DEBUG((DEBUG_INFO, "SpdmReceiveRequestSession[%x] ...\n", SessionId));

  SpdmContext->LastSpdmRequestSize = sizeof(SpdmContext->LastSpdmRequest);
  Status = SpdmDecodeRequest (SpdmContext, &SessionId, RequestSize, Request, &SpdmContext->LastSpdmRequestSize, SpdmContext->LastSpdmRequest);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmDecodeRequest : %p\n", Status));
    return Status;
  }

  DEBUG((DEBUG_INFO, "SpdmReceiveRequestSession[%x] (0x%x): \n", SessionId, SpdmContext->LastSpdmRequestSize));
  InternalDumpHex ((UINT8 *)SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmReceiveRequest (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request
  )
{
  RETURN_STATUS             Status;

  if (Request == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  if (RequestSize == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  SpdmContext->LastSpdmRequestSize = sizeof(SpdmContext->LastSpdmRequest);
  Status = SpdmDecodeRequest (SpdmContext, NULL, RequestSize, Request, &SpdmContext->LastSpdmRequestSize, SpdmContext->LastSpdmRequest);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmDecodeRequest : %p\n", Status));
    return Status;
  }

  DEBUG((DEBUG_INFO, "SpdmReceiveRequest (0x%x): \n", SpdmContext->LastSpdmRequestSize));
  InternalDumpHex (SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);

  return Status;
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

  Status = SpdmEncodeResponse (SpdmContext, &SessionId, MyResponseSize, MyResponse, ResponseSize, Response);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmEncodeResponse : %p\n", Status));
    return Status;
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

  Status = SpdmEncodeResponse (SpdmContext, NULL, MyResponseSize, MyResponse, ResponseSize, Response);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmEncodeResponse : %p\n", Status));
    return Status;
  }

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
