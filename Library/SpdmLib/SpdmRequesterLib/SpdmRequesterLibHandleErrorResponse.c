/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

#pragma pack(1)
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1: OriginRequestCode
  // Param2: Token
} SPDM_RESPOND_IF_READY_REQUEST;
#pragma pack()

RETURN_STATUS
EFIAPI
SpdmRequesterRespondIfReady (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *ResponseSize,
  IN OUT VOID                 *Response,
  IN     UINT8                 ExpectResponseCode,
  IN     UINTN                 ExpectResponseSize
  )
{
  RETURN_STATUS                             Status;
  SPDM_RESPOND_IF_READY_REQUEST             SpdmRequest;

  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  SpdmRequest.Header.RequestResponseCode = SPDM_RESPOND_IF_READY;
  SpdmRequest.Header.Param1 = SpdmContext->ErrorData.RequestCode;
  SpdmRequest.Header.Param2 = SpdmContext->ErrorData.Token;
  Status = SpdmSendRequest (SpdmContext, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  *ResponseSize = ExpectResponseSize;
  ZeroMem (Response, ExpectResponseSize);
  Status = SpdmReceiveResponse (SpdmContext, ResponseSize, Response);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (((SPDM_MESSAGE_HEADER*)Response)->RequestResponseCode != ExpectResponseCode) {
    return RETURN_DEVICE_ERROR;
  }
  if (*ResponseSize != ExpectResponseSize) {
    return RETURN_DEVICE_ERROR;
  }
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmHandleSimpleErrorResponse (
  IN     VOID                 *Context,
  IN     UINT8                ErrorCode
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext = Context;

  ASSERT (ErrorCode != SPDM_ERROR_CODE_RESPONSE_NOT_READY);

  if (ErrorCode == SPDM_ERROR_CODE_BUSY) {
    return RETURN_NO_RESPONSE;
  }

  if (ErrorCode == SPDM_ERROR_CODE_REQUEST_RESYNCH) {
    SpdmContext->SpdmCmdReceiveState &= 0;
  }

  return RETURN_DEVICE_ERROR;
}

RETURN_STATUS
SpdmHandleResponseNotReady (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *ResponseSize,
  IN OUT VOID                 *Response,
  IN     UINT8                 OriginRequestCode,
  IN     UINT8                 ExpectResponseCode,
  IN     UINTN                 ExpectResponseSize
  )
{
  SPDM_ERROR_RESPONSE                  *SpdmResponse;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY   *ExtendErrorData;

  SpdmResponse = Response;
  ExtendErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(SpdmResponse + 1);
  ASSERT(SpdmResponse->Header.RequestResponseCode == SPDM_ERROR);
  ASSERT(SpdmResponse->Header.Param1 == SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  ASSERT(*ResponseSize == sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  ASSERT(ExtendErrorData->RequestCode == OriginRequestCode);

  SpdmContext->ErrorData.RDTExponent = ExtendErrorData->RDTExponent;
  SpdmContext->ErrorData.RequestCode = ExtendErrorData->RequestCode;
  SpdmContext->ErrorData.Token       = ExtendErrorData->Token;
  SpdmContext->ErrorData.RDTM        = ExtendErrorData->RDTM;

  return SpdmRequesterRespondIfReady(SpdmContext, ResponseSize, Response, ExpectResponseCode, ExpectResponseSize);
}

RETURN_STATUS
EFIAPI
SpdmHandleErrorResponseMain (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT VOID                 *MBuffer,
  IN     UINTN                 ShrinkBufferSize,
  IN OUT UINTN                *ResponseSize,
  IN OUT VOID                 *Response,
  IN     UINT8                 OriginRequestCode,
  IN     UINT8                 ExpectResponseCode,
  IN     UINTN                 ExpectResponseSize
  )
{
  ASSERT(((SPDM_MESSAGE_HEADER*)Response)->RequestResponseCode == SPDM_ERROR);
  if (((SPDM_MESSAGE_HEADER*)Response)->Param1 != SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
    ShrinkManagedBuffer(MBuffer, ShrinkBufferSize);
    return SpdmHandleSimpleErrorResponse(SpdmContext, ((SPDM_MESSAGE_HEADER*)Response)->Param1);
  } else {
    return SpdmHandleResponseNotReady(SpdmContext, ResponseSize, Response, OriginRequestCode, ExpectResponseCode, ExpectResponseSize);
  }
}

