/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Build the response when the response state is incorrect.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestCode                  The SPDM request code.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  Response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmResponderHandleResponseState (
  IN     VOID                 *Context,
  IN     UINT8                 RequestCode,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_DEVICE_CONTEXT         *SpdmContext;

  SpdmContext = Context;
  switch (SpdmContext->ResponseState) {
  case SpdmResponseStateBusy:
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_BUSY, 0, ResponseSize, Response);
    // NOTE: Need to reset status to Normal in up level
    return RETURN_SUCCESS;
  case SpdmResponseStateNeedResync:
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_REQUEST_RESYNCH, 0, ResponseSize, Response);
    // NOTE: Need to let SPDM_VERSION reset the State
    SpdmSetConnectionState (SpdmContext, SpdmConnectionStateNotStarted);
    return RETURN_SUCCESS;
  case SpdmResponseStateNotReady:
    SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
    CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
    SpdmContext->ErrorData.RDTExponent = 1;
    SpdmContext->ErrorData.RDTM        = 1;
    SpdmContext->ErrorData.RequestCode = RequestCode;
    SpdmContext->ErrorData.Token       = SpdmContext->CurrentToken++;
    SpdmGenerateExtendedErrorResponse (SpdmContext, SPDM_ERROR_CODE_RESPONSE_NOT_READY, 0, sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY), (UINT8*)(void*)&SpdmContext->ErrorData, ResponseSize, Response);
    // NOTE: Need to reset status to Normal in up level
    return RETURN_SUCCESS;
  case SpdmResponseStateProcessingEncap:
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_REQUEST_IN_FLIGHT, 0, ResponseSize, Response);
    // NOTE: Need let SPDM_ENCAPSULATED_RESPONSE_ACK reset the State
    return RETURN_SUCCESS;
  default:
    return RETURN_SUCCESS;
  }
}

