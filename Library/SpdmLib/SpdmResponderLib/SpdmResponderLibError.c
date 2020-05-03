/** @file
  EDKII SpdmIo Stub

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

SPDM_ERROR_RESPONSE mSpdmError = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_ERROR,
    0, // ErrorCode
    0, // ErrorData
  },
};

RETURN_STATUS
EFIAPI
SpdmGenerateErrorResponse (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                ErrorCode,
  IN     UINT8                ErrorData,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_ERROR_RESPONSE     *SpdmResponse;

  ASSERT (*ResponseSize >= sizeof(mSpdmError));
  *ResponseSize = sizeof(mSpdmError);
  CopyMem (Response, &mSpdmError, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.Param1 = ErrorCode;
  SpdmResponse->Header.Param2 = ErrorData;

  return RETURN_SUCCESS;
}
