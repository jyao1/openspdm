/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Process the SPDM RESPONSE_IF_READY request and return the response.

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
SpdmGetResponseRespondIfReady (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_MESSAGE_HEADER                  *SpdmRequest;
  SPDM_DEVICE_CONTEXT                  *SpdmContext;
  SPDM_GET_SPDM_RESPONSE_FUNC          GetResponseFunc;
  RETURN_STATUS                        Status;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (SpdmContext->ResponseState == SpdmResponseStateNeedResync) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->RequestResponseCode, ResponseSize, Response);
  }

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

