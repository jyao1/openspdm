/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

/**
  Process the SPDM encapsulated KEY_UPDATE request and return the response.

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
SpdmGetEncapResponseKeyUpdate (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  UINT32                       SessionId;
  SPDM_KEY_UPDATE_RESPONSE     *SpdmResponse;
  SPDM_KEY_UPDATE_REQUEST      *SpdmRequest;
  SPDM_DEVICE_CONTEXT          *SpdmContext;
  SPDM_SESSION_INFO            *SessionInfo;
  SPDM_SESSION_STATE           SessionState;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_KEY_UPDATE, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (!SpdmContext->LastSpdmRequestSessionIdValid) {
    SpdmGenerateEncapErrorResponse (Context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SessionId = SpdmContext->LastSpdmRequestSessionId;
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    SpdmGenerateEncapErrorResponse (Context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SessionState = SpdmSecuredMessageGetSessionState (SessionInfo->SecuredMessageContext);
  if (SessionState != SpdmSessionStateEstablished) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (RequestSize != sizeof(SPDM_KEY_UPDATE_REQUEST)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  switch (SpdmRequest->Header.Param1) {
  case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
    DEBUG ((DEBUG_INFO, "SpdmCreateUpdateSessionDataKey[%x] Responder\n", SessionId));
    SpdmCreateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, SpdmKeyUpdateActionResponder);
    break;
  case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    break;
  case SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY:
    DEBUG ((DEBUG_INFO, "SpdmActivateUpdateSessionDataKey[%x] Responder new\n", SessionId));
    SpdmActivateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, SpdmKeyUpdateActionResponder, TRUE);
    break;
  default:
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  ASSERT (*ResponseSize >= sizeof(SPDM_KEY_UPDATE_RESPONSE));
  *ResponseSize = sizeof(SPDM_KEY_UPDATE_RESPONSE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_KEY_UPDATE_ACK;
  SpdmResponse->Header.Param1 = SpdmRequest->Header.Param1;
  SpdmResponse->Header.Param2 = SpdmRequest->Header.Param2;

  return RETURN_SUCCESS;
}

