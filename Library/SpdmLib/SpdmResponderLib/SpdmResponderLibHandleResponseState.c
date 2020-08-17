/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

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
    //NOTE: Need to reset status to Normal in up level
    return RETURN_SUCCESS;
  case SpdmResponseStateNeedResync:
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_REQUEST_RESYNCH, 0, ResponseSize, Response);
    SpdmContext->ResponseState = SpdmResponseStateNormal;
    return RETURN_SUCCESS;
  case SpdmResponseStateNotReady:
    SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
    CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
    SpdmContext->ErrorData.RDTExponent = 1;
    SpdmContext->ErrorData.RDTM        = 1;
    SpdmContext->ErrorData.RequestCode = RequestCode;
    SpdmContext->ErrorData.Token       = SpdmContext->CurrentToken++;
    SpdmGenerateExtendedErrorResponse (SpdmContext, SPDM_ERROR_CODE_RESPONSE_NOT_READY, 0, sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY), (UINT8*)(void*)&SpdmContext->ErrorData, ResponseSize, Response);
    SpdmContext->ResponseState = SpdmResponseStateNormal;
    return RETURN_SUCCESS;
  default:
    return RETURN_SUCCESS;
  }
}

