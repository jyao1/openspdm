/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

/**
  This function sends END_SESSION and receives END_SESSION_ACK for SPDM session end.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    SessionId to the END_SESSION request.
  @param  EndSessionAttributes         EndSessionAttributes to the END_SESSION_ACK request.

  @retval RETURN_SUCCESS               The END_SESSION is sent and the END_SESSION_ACK is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmSendReceiveEndSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                EndSessionAttributes
  )
{
  RETURN_STATUS                             Status;
  SPDM_END_SESSION_REQUEST                  SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_END_SESSION_RESPONSE                 SpdmResponse;
  UINTN                                     SpdmResponseSize;
  SPDM_SESSION_INFO                         *SessionInfo;
  
  if (((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) == 0) &&
      ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) == 0)) {
    return RETURN_DEVICE_ERROR;
  }

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;
   
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_END_SESSION;
  SpdmRequest.Header.Param1 = EndSessionAttributes;
  SpdmRequest.Header.Param2 = 0;
  
  SpdmRequestSize = sizeof(SPDM_END_SESSION_REQUEST);
  Status = SpdmSendSpdmRequest (SpdmContext, &SessionId, SpdmRequestSize, &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, &SessionId, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize != sizeof(SPDM_END_SESSION_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_END_SESSION_ACK) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmFreeSessionId (SpdmContext, SessionId);
 
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateNotStarted);
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  
  return RETURN_SUCCESS;
}

