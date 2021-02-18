/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

#pragma pack(1)

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                DummyData[sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY)];
} SPDM_END_SESSION_RESPONSE_MINE;

#pragma pack()

/**
  This function sends END_SESSION and receives END_SESSION_ACK for SPDM session end.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    SessionId to the END_SESSION request.
  @param  EndSessionAttributes         EndSessionAttributes to the END_SESSION_ACK request.

  @retval RETURN_SUCCESS               The END_SESSION is sent and the END_SESSION_ACK is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
TrySpdmSendReceiveEndSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                EndSessionAttributes
  )
{
  RETURN_STATUS                             Status;
  SPDM_END_SESSION_REQUEST                  SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_END_SESSION_RESPONSE_MINE            SpdmResponse;
  UINTN                                     SpdmResponseSize;
  SPDM_SESSION_INFO                         *SessionInfo;

  if (((SpdmContext->SpdmCmdReceiveState & SPDM_FINISH_RECEIVE_FLAG) == 0) &&
      ((SpdmContext->SpdmCmdReceiveState & SPDM_PSK_FINISH_RECEIVE_FLAG) == 0)) {
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
  if (SpdmResponseSize < sizeof(SPDM_MESSAGE_HEADER)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode == SPDM_ERROR) {
    Status = SpdmHandleErrorResponseMain(SpdmContext, &SessionId, NULL, 0, &SpdmResponseSize, &SpdmResponse, SPDM_END_SESSION, SPDM_END_SESSION_ACK, sizeof(SPDM_END_SESSION_RESPONSE_MINE));
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else if (SpdmResponse.Header.RequestResponseCode != SPDM_END_SESSION_ACK) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize != sizeof(SPDM_END_SESSION_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmFreeSessionId (SpdmContext, SessionId);
 
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateNotStarted);
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;

  SpdmContext->SpdmCmdReceiveState |= SPDM_END_SESSION_RECEIVE_FLAG;
  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmSendReceiveEndSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                EndSessionAttributes
  )
{
  UINTN                   Retry;
  RETURN_STATUS           Status;

  Retry = SpdmContext->RetryTimes;
  do {
    Status = TrySpdmSendReceiveEndSession(SpdmContext, SessionId, EndSessionAttributes);
    if (RETURN_NO_RESPONSE != Status) {
      return Status;
    }
  } while (Retry-- != 0);

  return Status;
}

