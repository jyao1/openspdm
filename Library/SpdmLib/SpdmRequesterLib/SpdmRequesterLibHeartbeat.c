/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmHeartbeat (
  IN     VOID                 *Context,
  IN     UINT32               SessionId
  )
{
  RETURN_STATUS                             Status;
  SPDM_HEARTBEAT_REQUEST                    SpdmRequest;
  SPDM_HEARTBEAT_RESPONSE                   SpdmResponse;
  UINTN                                     SpdmResponseSize;
  SPDM_DEVICE_CONTEXT                       *SpdmContext;

  SpdmContext = Context;

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_HEARTBEAT;
  SpdmRequest.Header.Param1 = 0;
  SpdmRequest.Header.Param2 = 0;
  Status = SpdmSendRequestSession (SpdmContext, SessionId, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveResponseSession (SpdmContext, SessionId, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize != sizeof(SPDM_HEARTBEAT_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_HEARTBEAT_ACK) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}
