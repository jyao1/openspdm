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

  SpdmContext = Context;
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    return RETURN_UNSUPPORTED;
  }

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP)) {
    return RETURN_DEVICE_ERROR;
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
  SpdmGetRandomNumber (sizeof(SpdmRequest.Header.Param2), &SpdmRequest.Header.Param2);

  Status = SpdmSendSpdmRequest (SpdmContext, &SessionId, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  // Create new key
  DEBUG ((DEBUG_INFO, "SpdmCreateUpdateSessionDataKey[%x]\n", SessionId));
  SpdmCreateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, Action);

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, &SessionId, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status) ||
     (SpdmResponseSize != sizeof(SPDM_KEY_UPDATE_RESPONSE)) ||
     (SpdmResponse.Header.RequestResponseCode != SPDM_KEY_UPDATE_ACK) ||
     (SpdmResponse.Header.Param1 != SpdmRequest.Header.Param1) ||
     (SpdmResponse.Header.Param2 != SpdmRequest.Header.Param2) ) {
    DEBUG ((DEBUG_INFO, "SpdmActivateUpdateSessionDataKey[%x]\n", SessionId));
    SpdmActivateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, Action, FALSE);
    return RETURN_DEVICE_ERROR;
  }

  DEBUG ((DEBUG_INFO, "SpdmActivateUpdateSessionDataKey[%x]\n", SessionInfo->SessionId));
  SpdmActivateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, Action, TRUE);

  //
  // Verify Key
  //
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_KEY_UPDATE;
  SpdmRequest.Header.Param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
  SpdmGetRandomNumber (sizeof(SpdmRequest.Header.Param2), &SpdmRequest.Header.Param2);

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
  if (SpdmResponseSize != sizeof(SPDM_KEY_UPDATE_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_KEY_UPDATE_ACK) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.Param1 != SpdmRequest.Header.Param1) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.Param2 != SpdmRequest.Header.Param2) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}

