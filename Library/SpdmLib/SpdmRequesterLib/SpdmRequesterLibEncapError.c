/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmGenerateEncapErrorResponse (
  IN     VOID                 *Context,
  IN     UINT8                ErrorCode,
  IN     UINT8                ErrorData,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_ERROR_RESPONSE     *SpdmResponse;

  ASSERT (*ResponseSize >= sizeof(SPDM_ERROR_RESPONSE) - 1);
  *ResponseSize = sizeof(SPDM_ERROR_RESPONSE) - 1;
  SpdmResponse = (VOID *)((UINT8 *)Response - 1);

  SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
  SpdmResponse->Header.Param1 = ErrorCode;
  SpdmResponse->Header.Param2 = ErrorData;

  return RETURN_SUCCESS;
}
