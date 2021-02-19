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
} SPDM_HEARTBEAT_RESPONSE_MINE;

#pragma pack()

/**
  This function sends HEARTBEAT
  to an SPDM Session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The session ID of the session.

  @retval RETURN_SUCCESS               The heartbeat is sent and received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
TrySpdmHeartbeat (
  IN     VOID                 *Context,
  IN     UINT32               SessionId
  )
{
  RETURN_STATUS                             Status;
  SPDM_HEARTBEAT_REQUEST                    SpdmRequest;
  SPDM_HEARTBEAT_RESPONSE_MINE              SpdmResponse;
  UINTN                                     SpdmResponseSize;
  SPDM_DEVICE_CONTEXT                       *SpdmContext;
  SPDM_SESSION_INFO                         *SessionInfo;
  SPDM_SESSION_STATE                        SessionState;

  SpdmContext = Context;
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP)) {
    return RETURN_UNSUPPORTED;
  }
  if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateNegotiated) {
    return RETURN_UNSUPPORTED;
  }
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }
  SessionState = SpdmSecuredMessageGetSessionState (SessionInfo->SecuredMessageContext);
  if (SessionState != SpdmSessionStateEstablished) {
    return RETURN_UNSUPPORTED;
  }

  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_HEARTBEAT;
  SpdmRequest.Header.Param1 = 0;
  SpdmRequest.Header.Param2 = 0;
  Status = SpdmSendSpdmRequest (SpdmContext, &SessionId, sizeof(SpdmRequest), &SpdmRequest);
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
    Status = SpdmHandleErrorResponseMain(SpdmContext, &SessionId, NULL, 0, &SpdmResponseSize, &SpdmResponse, SPDM_HEARTBEAT, SPDM_HEARTBEAT_ACK, sizeof(SPDM_HEARTBEAT_RESPONSE_MINE));
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else if (SpdmResponse.Header.RequestResponseCode != SPDM_HEARTBEAT_ACK) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize != sizeof(SPDM_HEARTBEAT_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmHeartbeat (
  IN     VOID                 *Context,
  IN     UINT32               SessionId
  )
{
  UINTN                   Retry;
  RETURN_STATUS           Status;
  SPDM_DEVICE_CONTEXT     *SpdmContext;

  SpdmContext = Context;
  Retry = SpdmContext->RetryTimes;
  do {
    Status = TrySpdmHeartbeat(SpdmContext, SessionId);
    if (RETURN_NO_RESPONSE != Status) {
      return Status;
    }
  } while (Retry-- != 0);

  return Status;
}

