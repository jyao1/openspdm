/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Process the SPDM PSK_FINISH request and return the response.

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
SpdmGetResponsePskFinish (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  UINT32                       SessionId;
  BOOLEAN                      Result;
  UINT32                       HmacSize;
  SPDM_PSK_FINISH_RESPONSE     *SpdmResponse;
  SPDM_DEVICE_CONTEXT          *SpdmContext;
  SPDM_SESSION_INFO            *SessionInfo;
  UINT8                        TH2HashData[64];
  SPDM_PSK_FINISH_REQUEST      *SpdmRequest;
  RETURN_STATUS                Status;
  SPDM_SESSION_STATE           SessionState;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_PSK_EXCHANGE, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateNegotiated) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (!SpdmContext->LastSpdmRequestSessionIdValid) {
    SpdmGenerateErrorResponse (Context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SessionId = SpdmContext->LastSpdmRequestSessionId;
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SessionState = SpdmSecuredMessageGetSessionState (SessionInfo->SecuredMessageContext);
  if (SessionState != SpdmSessionStateHandshaking) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  // remove HMAC
  HmacSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (RequestSize != sizeof(SPDM_PSK_FINISH_REQUEST) + HmacSize) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Status = SpdmAppendMessageF (SessionInfo, Request, RequestSize - HmacSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  ASSERT (*ResponseSize >= sizeof(SPDM_PSK_FINISH_RESPONSE));
  *ResponseSize = sizeof(SPDM_PSK_FINISH_RESPONSE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_PSK_FINISH_RSP;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  Result = SpdmVerifyPskFinishReqHmac (SpdmContext, SessionInfo, (UINT8 *)Request + sizeof(SPDM_PSK_FINISH_REQUEST), HmacSize);
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_DECRYPT_ERROR, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Status = SpdmAppendMessageF (SessionInfo, (UINT8 *)Request + RequestSize - HmacSize, HmacSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Status = SpdmAppendMessageF (SessionInfo, SpdmResponse, *ResponseSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
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

  return RETURN_SUCCESS;
}
