/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

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
