/** @file
  EDKII SpdmIo Stub

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmGetResponseCapability (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_GET_CAPABILITIES_REQUEST  *SpdmRequest;
  SPDM_CAPABILITIES_RESPONSE     *SpdmResponse;

  ASSERT (*ResponseSize >= sizeof(SPDM_CAPABILITIES_RESPONSE));
  *ResponseSize = sizeof(SPDM_CAPABILITIES_RESPONSE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  SpdmResponse->Header.RequestResponseCode = SPDM_CAPABILITIES;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;
  SpdmResponse->CTExponent = SpdmContext->LocalContext.Capability.CTExponent;
  SpdmResponse->Flags = SpdmContext->LocalContext.Capability.Flags;
  
  SpdmRequest = Request;
  SpdmContext->ConnectionInfo.Capability.CTExponent = SpdmRequest->CTExponent;
  SpdmContext->ConnectionInfo.Capability.Flags = SpdmRequest->Flags;

  return RETURN_SUCCESS;
}

