/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

/**
  This function executes SPDM EndSession.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceiveEndSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINT8                EndSessionAttributes
  )
{
  RETURN_STATUS                             Status;
  SPDM_END_SESSION_REQUEST                  SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_END_SESSION_RESPONSE                 SpdmResponse;
  UINTN                                     SpdmResponseSize;
  SPDM_SESSION_INFO                         *SessionInfo;
  
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;
   
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_END_SESSION;
  SpdmRequest.Header.Param1 = EndSessionAttributes;
  SpdmRequest.Header.Param2 = 0;
  
  SpdmRequestSize = sizeof(SPDM_END_SESSION_REQUEST);
  Status = SpdmSendRequestSession (SpdmContext, SessionId, SpdmRequestSize, &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveResponseSession (SpdmContext, SessionId, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize != sizeof(SPDM_END_SESSION_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_END_SESSION_ACK) {
    return RETURN_DEVICE_ERROR;
  }
  
  SessionInfo->SessionState = SpdmStateNotStarted;
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  
  return RETURN_SUCCESS;
}

