/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Process the SPDM FINISH request and return the response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestSize                  Size in bytes of the request data.
  @param  Request                      A pointer to the request data.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  Response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetResponseFinish (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  UINT32                   SessionId;
  BOOLEAN                  Result;
  UINT32                   HmacSize;
  UINT32                   SignatureSize;
  UINT8                    SlotNum;
  SPDM_FINISH_REQUEST      *SpdmRequest;
  SPDM_FINISH_RESPONSE     *SpdmResponse;
  SPDM_DEVICE_CONTEXT      *SpdmContext;
  SPDM_SESSION_INFO        *SessionInfo;
  UINT8                    TH2HashData[64];
  RETURN_STATUS            Status;

  SpdmContext = Context;
  SpdmRequest = Request;
  if (((SpdmContext->SpdmCmdReceiveState & SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CAPABILITIES_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_KEY_EXCHANGE_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_DIGESTS_RECEIVE_FLAG) == 0)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  
  if (SpdmContext->LastSpdmRequestSessionIdValid) {
    SessionId = SpdmContext->LastSpdmRequestSessionId;
  } else {
    SessionId = SpdmContext->LatestSessionId;
  }
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (((SessionInfo->MutAuthRequested == 0) && (SpdmRequest->Header.Param1 != 0)) ||
      ((SessionInfo->MutAuthRequested != 0) && (SpdmRequest->Header.Param1 == 0)) ) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  HmacSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  if (SessionInfo->MutAuthRequested) {
    SignatureSize = GetSpdmReqAsymSize (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg);
  } else {
    SignatureSize = 0;
  }

  if (RequestSize != sizeof(SPDM_FINISH_REQUEST) + SignatureSize + HmacSize) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SlotNum = SpdmRequest->Header.Param2;
  if ((SlotNum != 0xFF) && (SlotNum >= SpdmContext->LocalContext.SlotCount)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SlotNum == 0xFF) {
    SlotNum = SpdmContext->EncapContext.SlotNum;
  }
  if (SlotNum != SpdmContext->EncapContext.SlotNum) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Status = SpdmAppendMessageF (SessionInfo, Request, sizeof(SPDM_FINISH_REQUEST));
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SessionInfo->MutAuthRequested) {
    Result = SpdmVerifyFinishReqSignature (SpdmContext, SessionInfo, (UINT8 *)Request + sizeof(SPDM_FINISH_REQUEST), SignatureSize);
    if (!Result) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    Status = SpdmAppendMessageF (SessionInfo, (UINT8 *)Request + sizeof(SPDM_FINISH_REQUEST), SignatureSize);
    if (RETURN_ERROR(Status)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  }

  Result = SpdmVerifyFinishReqHmac (SpdmContext, SessionInfo, (UINT8 *)Request + SignatureSize + sizeof(SPDM_FINISH_REQUEST), HmacSize);
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Status = SpdmAppendMessageF (SessionInfo, (UINT8 *)Request + SignatureSize + sizeof(SPDM_FINISH_REQUEST), HmacSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
    HmacSize = 0;
  }

  ASSERT (*ResponseSize >= sizeof(SPDM_FINISH_RESPONSE) + HmacSize);
  *ResponseSize = sizeof(SPDM_FINISH_RESPONSE) + HmacSize;
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_FINISH_RSP;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  Status = SpdmAppendMessageF (SessionInfo, SpdmResponse, sizeof(SPDM_FINISH_RESPONSE));
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) != 0) {
    Result = SpdmGenerateFinishRspHmac (SpdmContext, SessionInfo, (UINT8 *)SpdmResponse + sizeof(SPDM_FINISH_REQUEST));
    if (!Result) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_FINISH_RSP, ResponseSize, Response);
      return RETURN_SUCCESS;
    }

    Status = SpdmAppendMessageF (SessionInfo, (UINT8 *)SpdmResponse + sizeof(SPDM_FINISH_REQUEST), HmacSize);
    if (RETURN_ERROR(Status)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  }

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionDataKey[%x]\n", SessionId));
  Status = SpdmCalculateTH2Hash (SpdmContext, SessionInfo, FALSE, TH2HashData);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Status = SpdmGenerateSessionDataKey (SessionInfo->SecuredMessageContext, TH2HashData);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SpdmContext->SpdmCmdReceiveState |= SPDM_FINISH_RECEIVE_FLAG;

  return RETURN_SUCCESS;
}
