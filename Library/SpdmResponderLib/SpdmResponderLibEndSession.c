/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Process the SPDM END_SESSION request and return the response.

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
SpdmGetResponseEndSession (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_END_SESSION_RESPONSE     *SpdmResponse;
  SPDM_END_SESSION_REQUEST      *SpdmRequest;
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  SPDM_SESSION_INFO             *SessionInfo;
  SPDM_SESSION_STATE            SessionState;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateNegotiated) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (!SpdmContext->LastSpdmRequestSessionIdValid) {
    SpdmGenerateErrorResponse (Context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SpdmContext->LastSpdmRequestSessionId);
  if (SessionInfo == NULL) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SessionState = SpdmSecuredMessageGetSessionState (SessionInfo->SecuredMessageContext);
  if (SessionState != SpdmSessionStateEstablished) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (RequestSize != sizeof(SPDM_END_SESSION_REQUEST)) {
    SpdmGenerateErrorResponse (Context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SessionInfo->EndSessionAttributes = SpdmRequest->Header.Param1;

  ASSERT (*ResponseSize >= sizeof(SPDM_END_SESSION_RESPONSE));
  *ResponseSize = sizeof(SPDM_END_SESSION_RESPONSE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_END_SESSION_ACK;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  return RETURN_SUCCESS;
}

