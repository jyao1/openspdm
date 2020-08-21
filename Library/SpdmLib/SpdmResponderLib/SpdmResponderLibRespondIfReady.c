/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmGetResponseRespondIfReady (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_MESSAGE_HEADER         *SpdmRequest;
  SPDM_DEVICE_CONTEXT         *SpdmContext;
  SPDM_GET_RESPONSE_FUNC       GetResponseFunc;
  RETURN_STATUS                Status;

  SpdmContext = Context;
  SpdmRequest = Request;
  if (RequestSize != sizeof(SPDM_MESSAGE_HEADER)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  ASSERT (SpdmRequest->RequestResponseCode == SPDM_RESPOND_IF_READY);
  if (SpdmRequest->Param1 != SpdmContext->ErrorData.RequestCode) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmRequest->Param1 == SPDM_RESPOND_IF_READY) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmRequest->Param2 != SpdmContext->ErrorData.Token) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  GetResponseFunc = NULL;
  GetResponseFunc = SpdmGetResponseFuncViaRequestCode(SpdmRequest->Param1);
  if (GetResponseFunc == NULL) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SpdmRequest->Param1, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Status = GetResponseFunc (SpdmContext, SpdmContext->CachSpdmRequestSize, SpdmContext->CachSpdmRequest, ResponseSize, Response);

  return Status;
}

