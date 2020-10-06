/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmGetResponseKeyUpdate (
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

  SpdmContext = Context;
  ASSERT (SpdmContext->LastSpdmRequestSessionIdValid);
  if (!SpdmContext->LastSpdmRequestSessionIdValid) {
    SpdmGenerateErrorResponse (Context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SessionId = SpdmContext->LastSpdmRequestSessionId;

  SpdmRequest = Request;
  if (RequestSize != sizeof(SPDM_KEY_UPDATE_REQUEST)) {
    SpdmGenerateErrorResponse (Context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  switch (SpdmRequest->Header.Param1) {
  case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
    SpdmCreateUpdateSessionDataKey (Context, SessionId, SpdmKeyUpdateActionRequester);
    break;
  case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
    SpdmCreateUpdateSessionDataKey (Context, SessionId, SpdmKeyUpdateActionAll);
    SpdmFinalizeUpdateSessionDataKey (Context, SessionId, TRUE, SpdmKeyUpdateActionResponder);
    break;
  case SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY:
    SpdmFinalizeUpdateSessionDataKey (Context, SessionId, TRUE, SpdmKeyUpdateActionRequester);
    break;
  default:
    SpdmGenerateErrorResponse (Context, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
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

