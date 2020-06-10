/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmGetResponseCapability (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_GET_CAPABILITIES_REQUEST  *SpdmRequest;
  UINTN                          SpdmRequestSize;
  SPDM_CAPABILITIES_RESPONSE     *SpdmResponse;
  SPDM_DEVICE_CONTEXT            *SpdmContext;

  SpdmContext = Context;
  SpdmRequest = Request;
  if (RequestSize != sizeof(SPDM_GET_CAPABILITIES_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SpdmRequestSize = RequestSize;
  //
  // Cache
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, SpdmRequest, SpdmRequestSize);

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
  //
  // Cache
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, SpdmResponse, *ResponseSize);
  
  SpdmContext->ConnectionInfo.Capability.CTExponent = SpdmRequest->CTExponent;
  SpdmContext->ConnectionInfo.Capability.Flags = SpdmRequest->Flags;

  return RETURN_SUCCESS;
}

