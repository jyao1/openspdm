/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

RETURN_STATUS
TrySpdmGetCapabilities (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                RequesterCTExponent,
  IN     UINT32               RequesterFlags,
     OUT UINT8                *ResponderCTExponent,
     OUT UINT32               *ResponderFlags
  )
{
  RETURN_STATUS                             Status;
  SPDM_GET_CAPABILITIES_REQUEST             SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_CAPABILITIES_RESPONSE                SpdmResponse;
  UINTN                                     SpdmResponseSize;

  if ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_VERSION_RECEIVE_FLAG) == 0) {
    return RETURN_DEVICE_ERROR;
  }
  ZeroMem (&SpdmRequest, sizeof(SpdmRequest));
  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmRequestSize = sizeof(SpdmRequest);
  } else {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmRequestSize = sizeof(SpdmRequest.Header);
  }
  SpdmRequest.Header.RequestResponseCode = SPDM_GET_CAPABILITIES;
  SpdmRequest.Header.Param1 = 0;
  SpdmRequest.Header.Param2 = 0;
  SpdmRequest.CTExponent = RequesterCTExponent;
  SpdmRequest.Flags = RequesterFlags;
  Status = SpdmSendRequest (SpdmContext, SpdmRequestSize, &SpdmRequest);
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
  if (SpdmResponse.Header.RequestResponseCode == SPDM_ERROR) {
    Status = SpdmHandleErrorResponseMain(SpdmContext, &SpdmContext->Transcript.MessageA, sizeof(SpdmRequest), &SpdmResponseSize, &SpdmResponse, SPDM_GET_CAPABILITIES, SPDM_CAPABILITIES, sizeof(SPDM_CAPABILITIES_RESPONSE));
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else if (SpdmResponse.Header.RequestResponseCode != SPDM_CAPABILITIES) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_CAPABILITIES_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
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
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;

  return RETURN_SUCCESS;
}

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
  int retry = SpdmContext->RetryTimes;
  RETURN_STATUS Status;

  while(retry--) {
    Status = TrySpdmGetCapabilities(SpdmContext, RequesterCTExponent, RequesterFlags, ResponderCTExponent, ResponderFlags);
    if (RETURN_NO_RESPONSE != Status)
      return Status;
  }

  return Status;
}

