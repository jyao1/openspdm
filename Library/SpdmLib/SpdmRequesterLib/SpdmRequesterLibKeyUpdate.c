/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

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

  SpdmContext = Context;

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP) == 0) {
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
  GetRandomNumber (sizeof(SpdmRequest.Header.Param2), &SpdmRequest.Header.Param2);

  Status = SpdmSendRequestSession (SpdmContext, SessionId, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  // Create new key
  SpdmCreateUpdateSessionDataKey (SpdmContext, SessionId, Action);

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveResponseSession (SpdmContext, SessionId, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    SpdmFinalizeUpdateSessionDataKey (SpdmContext, SessionId, Action, FALSE);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize != sizeof(SPDM_KEY_UPDATE_RESPONSE)) {
    SpdmFinalizeUpdateSessionDataKey (SpdmContext, SessionId, Action, FALSE);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_KEY_UPDATE_ACK) {
    SpdmFinalizeUpdateSessionDataKey (SpdmContext, SessionId, Action, FALSE);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.Param1 != SpdmRequest.Header.Param1) {
    SpdmFinalizeUpdateSessionDataKey (SpdmContext, SessionId, Action, FALSE);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.Param2 != SpdmRequest.Header.Param2) {
    SpdmFinalizeUpdateSessionDataKey (SpdmContext, SessionId, Action, FALSE);
    return RETURN_DEVICE_ERROR;
  }

  SpdmFinalizeUpdateSessionDataKey (SpdmContext, SessionId, Action, TRUE);

  //
  // Verify Key
  //
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_KEY_UPDATE;
  SpdmRequest.Header.Param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
  GetRandomNumber (sizeof(SpdmRequest.Header.Param2), &SpdmRequest.Header.Param2);

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

