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
  // Param1: OriginalRequestCode
  // Param2: Token
} SPDM_RESPOND_IF_READY_REQUEST;

#pragma pack()

/**
  This function sends RESPOND_IF_READY and receives an expected SPDM response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ResponseSize                 The size of the response.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
  @param  Response                     The SPDM response message.
  @param  ExpectedResponseCode         Indicate the expected response code.
  @param  ExpectedResponseSize         Indicate the expected response size.

  @retval RETURN_SUCCESS               The RESPOND_IF_READY is sent and an expected SPDM response is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmRequesterRespondIfReady (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               *SessionId,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response,
  IN     UINT8                 ExpectedResponseCode,
  IN     UINTN                 ExpectedResponseSize
  )
{
  RETURN_STATUS                             Status;
  SPDM_RESPOND_IF_READY_REQUEST             SpdmRequest;
  SPDM_MESSAGE_HEADER                       *SpdmResponse;

  SpdmResponse = Response;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmRequest.Header.RequestResponseCode = SPDM_RESPOND_IF_READY;
  SpdmRequest.Header.Param1 = SpdmContext->ErrorData.RequestCode;
  SpdmRequest.Header.Param2 = SpdmContext->ErrorData.Token;
  Status = SpdmSendSpdmRequest (SpdmContext, SessionId, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  *ResponseSize = ExpectedResponseSize;
  ZeroMem (Response, ExpectedResponseSize);
  Status = SpdmReceiveSpdmResponse (SpdmContext, SessionId, ResponseSize, Response);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (*ResponseSize < sizeof(SPDM_MESSAGE_HEADER)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse->RequestResponseCode != ExpectedResponseCode) {
    return RETURN_DEVICE_ERROR;
  }
  // For response like SPDM_ALGORITHMS, we just can expect the max response size
  if (*ResponseSize > ExpectedResponseSize) {
    return RETURN_DEVICE_ERROR;
  }
  return RETURN_SUCCESS;
}

/**
  This function handles simple error code.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ErrorCode                    Indicate the error code.

  @retval RETURN_NO_RESPONSE           If the error code is BUSY.
  @retval RETURN_DEVICE_ERROR          If the error code is REQUEST_RESYNCH or others.
**/
RETURN_STATUS
EFIAPI
SpdmHandleSimpleErrorResponse (
  IN     VOID                 *Context,
  IN     UINT8                ErrorCode
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmContext = Context;

  //
  // NOT_READY is treated as error here.
  // Use SpdmHandleErrorResponseMain to handle NOT_READY message in long latency command.
  //
  if (ErrorCode == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
    return RETURN_DEVICE_ERROR;
  }

  if (ErrorCode == SPDM_ERROR_CODE_BUSY) {
    return RETURN_NO_RESPONSE;
  }

  if (ErrorCode == SPDM_ERROR_CODE_REQUEST_RESYNCH) {
    SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  }

  return RETURN_DEVICE_ERROR;
}

/**
  This function handles RESPONSE_NOT_READY error code.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ResponseSize                 The size of the response.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
  @param  Response                     The SPDM response message.
  @param  OriginalRequestCode          Indicate the orginal request code.
  @param  ExpectedResponseCode         Indicate the expected response code.
  @param  ExpectedResponseSize         Indicate the expected response size.

  @retval RETURN_SUCCESS               The RESPOND_IF_READY is sent and an expected SPDM response is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmHandleResponseNotReady (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               *SessionId,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response,
  IN     UINT8                 OriginalRequestCode,
  IN     UINT8                 ExpectedResponseCode,
  IN     UINTN                 ExpectedResponseSize
  )
{
  SPDM_ERROR_RESPONSE                  *SpdmResponse;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY   *ExtendErrorData;

  SpdmResponse = Response;
  ExtendErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(SpdmResponse + 1);
  ASSERT(SpdmResponse->Header.RequestResponseCode == SPDM_ERROR);
  ASSERT(SpdmResponse->Header.Param1 == SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  ASSERT(*ResponseSize == sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  ASSERT(ExtendErrorData->RequestCode == OriginalRequestCode);

  SpdmContext->ErrorData.RDTExponent = ExtendErrorData->RDTExponent;
  SpdmContext->ErrorData.RequestCode = ExtendErrorData->RequestCode;
  SpdmContext->ErrorData.Token       = ExtendErrorData->Token;
  SpdmContext->ErrorData.RDTM        = ExtendErrorData->RDTM;

  return SpdmRequesterRespondIfReady(SpdmContext, SessionId, ResponseSize, Response, ExpectedResponseCode, ExpectedResponseSize);
}

/**
  This function handles the error response.

  The SPDM response code must be SPDM_ERROR.
  For error code RESPONSE_NOT_READY, this function sends RESPOND_IF_READY and receives an expected SPDM response.
  For error code BUSY, this function shrinks the managed buffer, and return RETURN_NO_RESPONSE.
  For error code REQUEST_RESYNCH, this function shrinks the managed buffer, clears ConnectionState, and return RETURN_DEVICE_ERROR.
  For any other error code, this function shrinks the managed buffer, and return RETURN_DEVICE_ERROR.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ManagedBuffer                The managed buffer to be shrinked.
  @param  ShrinkBufferSize             The size in bytes of the size of the buffer to be shrinked.
  @param  ResponseSize                 The size of the response.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
  @param  Response                     The SPDM response message.
  @param  OriginalRequestCode          Indicate the original request code.
  @param  ExpectedResponseCode         Indicate the expected response code.
  @param  ExpectedResponseSize         Indicate the expected response size.

  @retval RETURN_SUCCESS               The error code is RESPONSE_NOT_READY. The RESPOND_IF_READY is sent and an expected SPDM response is received.
  @retval RETURN_NO_RESPONSE           The error code is BUSY.
  @retval RETURN_DEVICE_ERROR          The error code is REQUEST_RESYNCH or others.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmHandleErrorResponseMain (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               *SessionId,
  IN OUT VOID                 *MBuffer,
  IN     UINTN                 ShrinkBufferSize,
  IN OUT UINTN                *ResponseSize,
  IN OUT VOID                 *Response,
  IN     UINT8                 OriginalRequestCode,
  IN     UINT8                 ExpectedResponseCode,
  IN     UINTN                 ExpectedResponseSize
  )
{
  SPDM_MESSAGE_HEADER  *SpdmResponse;

  SpdmResponse = Response;
  ASSERT(SpdmResponse->RequestResponseCode == SPDM_ERROR);
  if (SpdmResponse->Param1 != SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
    ShrinkManagedBuffer(MBuffer, ShrinkBufferSize);
    return SpdmHandleSimpleErrorResponse(SpdmContext, SpdmResponse->Param1);
  } else {
    return SpdmHandleResponseNotReady(SpdmContext, SessionId, ResponseSize, Response, OriginalRequestCode, ExpectedResponseCode, ExpectedResponseSize);
  }
}
