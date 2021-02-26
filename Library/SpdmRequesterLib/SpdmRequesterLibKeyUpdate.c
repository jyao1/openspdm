/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

/**
  This function sends KEY_UPDATE
  to update keys for an SPDM Session.

  After keys are updated, this function also uses VERIFY_NEW_KEY to verify the key.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The session ID of the session.
  @param  SingleDirection              TRUE means the operation is UPDATE_KEY.
                                       FALSE means the operation is UPDATE_ALL_KEYS.

  @retval RETURN_SUCCESS               The keys of the session are updated.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmKeyUpdate (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     BOOLEAN              SingleDirection
  )
{
  RETURN_STATUS                      Status;
  SPDM_KEY_UPDATE_REQUEST            SpdmRequest;
  SPDM_KEY_UPDATE_RESPONSE           SpdmResponse;
  UINTN                              SpdmResponseSize;
  SPDM_KEY_UPDATE_ACTION             Action;
  SPDM_DEVICE_CONTEXT                *SpdmContext;
  SPDM_SESSION_INFO                  *SessionInfo;
  SPDM_SESSION_STATE                 SessionState;

  SpdmContext = Context;
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP)) {
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

  if (SingleDirection) {
    Action = SpdmKeyUpdateActionRequester;
  } else {
    Action = SpdmKeyUpdateActionAll;
  }

  //
  // Update Key
  //
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_KEY_UPDATE;
  if (SingleDirection) {
    SpdmRequest.Header.Param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
  } else {
    SpdmRequest.Header.Param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS;
  }
  SpdmRequest.Header.Param2 = 0;
  SpdmGetRandomNumber (sizeof(SpdmRequest.Header.Param2), &SpdmRequest.Header.Param2);

  // Create new key
  if ((Action & SpdmKeyUpdateActionResponder) != 0) {
    DEBUG ((DEBUG_INFO, "SpdmCreateUpdateSessionDataKey[%x] Responder\n", SessionId));
    SpdmCreateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, SpdmKeyUpdateActionResponder);
  }

  Status = SpdmSendSpdmRequest (SpdmContext, &SessionId, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, &SessionId, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status) ||
     (SpdmResponseSize != sizeof(SPDM_KEY_UPDATE_RESPONSE)) ||
     (SpdmResponse.Header.RequestResponseCode != SPDM_KEY_UPDATE_ACK) ||
     (SpdmResponse.Header.Param1 != SpdmRequest.Header.Param1) ||
     (SpdmResponse.Header.Param2 != SpdmRequest.Header.Param2) ) {
    if ((Action & SpdmKeyUpdateActionResponder) != 0) {
      DEBUG ((DEBUG_INFO, "SpdmActivateUpdateSessionDataKey[%x] Responder old\n", SessionId));
      SpdmActivateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, SpdmKeyUpdateActionResponder, FALSE);
    }
    return RETURN_DEVICE_ERROR;
  }

  if ((Action & SpdmKeyUpdateActionResponder) != 0) {
    DEBUG ((DEBUG_INFO, "SpdmActivateUpdateSessionDataKey[%x] Responder new\n", SessionId, SpdmKeyUpdateActionResponder));
    SpdmActivateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, SpdmKeyUpdateActionResponder, TRUE);
  }

  DEBUG ((DEBUG_INFO, "SpdmCreateUpdateSessionDataKey[%x] Requester\n", SessionId));
  SpdmCreateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, SpdmKeyUpdateActionRequester);
  DEBUG ((DEBUG_INFO, "SpdmActivateUpdateSessionDataKey[%x] Requester new\n", SessionId));
  SpdmActivateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, SpdmKeyUpdateActionRequester, TRUE);

  //
  // Verify Key
  //
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_KEY_UPDATE;
  SpdmRequest.Header.Param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
  SpdmRequest.Header.Param2 = 1;
  SpdmGetRandomNumber (sizeof(SpdmRequest.Header.Param2), &SpdmRequest.Header.Param2);

  Status = SpdmSendSpdmRequest (SpdmContext, &SessionId, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, &SessionId, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status) ||
     (SpdmResponseSize != sizeof(SPDM_KEY_UPDATE_RESPONSE)) ||
     (SpdmResponse.Header.RequestResponseCode != SPDM_KEY_UPDATE_ACK) ||
     (SpdmResponse.Header.Param1 != SpdmRequest.Header.Param1) ||
     (SpdmResponse.Header.Param2 != SpdmRequest.Header.Param2) ) {
    DEBUG ((DEBUG_INFO, "SpdmVerifyKey[%x] Failed\n", SessionId));
    return RETURN_DEVICE_ERROR;
  }
  DEBUG ((DEBUG_INFO, "SpdmVerifyKey[%x] Success\n", SessionId));

  return RETURN_SUCCESS;
}

