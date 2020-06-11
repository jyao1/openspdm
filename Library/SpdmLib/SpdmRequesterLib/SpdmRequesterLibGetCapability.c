/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmGetCapabilities (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                RequesterCTExponent,
  IN     UINT32               RequesterFlags,
     OUT UINT8                *ResponderCTExponent,
     OUT UINT32               *ResponderFlags
  )
{
  RETURN_STATUS                             Status;
  SPDM_GET_CAPABILITIES_REQUEST             SpdmRequest;
  SPDM_CAPABILITIES_RESPONSE                SpdmResponse;
  UINTN                                     SpdmResponseSize;
  
  ZeroMem (&SpdmRequest, sizeof(SpdmRequest));
  SpdmRequest.Header.SPDMVersion = SpdmContext->SPDMVersion;
  SpdmRequest.Header.RequestResponseCode = SPDM_GET_CAPABILITIES;
  SpdmRequest.Header.Param1 = 0;
  SpdmRequest.Header.Param2 = 0;
  SpdmRequest.CTExponent = RequesterCTExponent;
  SpdmRequest.Flags = RequesterFlags;
  Status = SpdmSendRequest (SpdmContext, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, &SpdmRequest, sizeof(SpdmRequest));

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveResponse (SpdmContext, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_CAPABILITIES_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_CAPABILITIES) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SPDM_CAPABILITIES_RESPONSE);
  //
  // Cache data
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, &SpdmResponse, SpdmResponseSize);

  SpdmContext->ConnectionInfo.Capability.CTExponent = SpdmResponse.CTExponent;
  SpdmContext->ConnectionInfo.Capability.Flags = SpdmResponse.Flags;

  *ResponderCTExponent = SpdmResponse.CTExponent;
  *ResponderFlags = SpdmResponse.Flags;
  
  return RETURN_SUCCESS;
}
