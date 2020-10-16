/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Generate ERROR message.

  This function can be called in SPDM_GET_RESPONSE_FUNC.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ErrorCode                    The error code of the message.
  @param  ErrorData                    The error data of the message.
  @param  SpdmResponseSize             Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  SpdmResponse                 A pointer to the response data.

  @retval RETURN_SUCCESS               The error message is generated.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmGenerateErrorResponse (
  IN     VOID                 *Context,
  IN     UINT8                ErrorCode,
  IN     UINT8                ErrorData,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_ERROR_RESPONSE     *SpdmResponse;

  ASSERT (*ResponseSize >= sizeof(SPDM_ERROR_RESPONSE));
  *ResponseSize = sizeof(SPDM_ERROR_RESPONSE);
  SpdmResponse = Response;

  if (SpdmIsVersionSupported (Context, SPDM_MESSAGE_VERSION_11)) {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
  SpdmResponse->Header.Param1 = ErrorCode;
  SpdmResponse->Header.Param2 = ErrorData;

  return RETURN_SUCCESS;
}

/**
  Generate ERROR message with extended error data.

  This function can be called in SPDM_GET_RESPONSE_FUNC.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ErrorCode                    The error code of the message.
  @param  ErrorData                    The error data of the message.
  @param  ExtendedErrorDataSize        The size in bytes of the extended error data.
  @param  ExtendedErrorData            A pointer to the extended error data.
  @param  SpdmResponseSize             Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  SpdmResponse                 A pointer to the response data.

  @retval RETURN_SUCCESS               The error message is generated.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmGenerateExtendedErrorResponse (
  IN     VOID                 *Context,
  IN     UINT8                ErrorCode,
  IN     UINT8                ErrorData,
  IN     UINTN                ExtendedErrorDataSize,
  IN     UINT8                *ExtendedErrorData,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_ERROR_RESPONSE     *SpdmResponse;

  ASSERT (*ResponseSize >= sizeof(SPDM_ERROR_RESPONSE) + ExtendedErrorDataSize);
  *ResponseSize = sizeof(SPDM_ERROR_RESPONSE) + ExtendedErrorDataSize;
  SpdmResponse = Response;

  if (SpdmIsVersionSupported (Context, SPDM_MESSAGE_VERSION_11)) {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
  SpdmResponse->Header.Param1 = ErrorCode;
  SpdmResponse->Header.Param2 = ErrorData;
  CopyMem (SpdmResponse + 1, ExtendedErrorData, ExtendedErrorDataSize);

  return RETURN_SUCCESS;
}
