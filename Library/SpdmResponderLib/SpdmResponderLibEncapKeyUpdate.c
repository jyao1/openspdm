/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Get the SPDM encapsulated KEY_UPDATE request.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  EncapRequestSize             Size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  EncapRequest                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmGetEncapReqestKeyUpdate (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  )
{
  SPDM_KEY_UPDATE_REQUEST      *SpdmRequest;
  UINT32                       SessionId;
  SPDM_SESSION_INFO            *SessionInfo;
  SPDM_SESSION_STATE           SessionState;

  SpdmContext->EncapContext.LastEncapRequestSize = 0;

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP)) {
    return RETURN_UNSUPPORTED;
  }

  if (!SpdmContext->LastSpdmRequestSessionIdValid) {
    return RETURN_UNSUPPORTED;
  }
  SessionId = SpdmContext->LastSpdmRequestSessionId;
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    return RETURN_UNSUPPORTED;
  }
  SessionState = SpdmSecuredMessageGetSessionState (SessionInfo->SecuredMessageContext);
  if (SessionState != SpdmSessionStateEstablished) {
    return RETURN_UNSUPPORTED;
  }

  ASSERT (*EncapRequestSize >= sizeof(SPDM_KEY_UPDATE_REQUEST));
  *EncapRequestSize = sizeof(SPDM_KEY_UPDATE_REQUEST);

  SpdmRequest = EncapRequest;

  SpdmRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest->Header.RequestResponseCode = SPDM_KEY_UPDATE;
  if (SpdmContext->EncapContext.LastEncapRequestHeader.RequestResponseCode != SPDM_KEY_UPDATE) {
    SpdmRequest->Header.Param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY;
    SpdmRequest->Header.Param2 = 0;
    SpdmGetRandomNumber (sizeof(SpdmRequest->Header.Param2), &SpdmRequest->Header.Param2);
  } else {
    SpdmRequest->Header.Param1 = SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY;
    SpdmRequest->Header.Param2 = 1;
    SpdmGetRandomNumber (sizeof(SpdmRequest->Header.Param2), &SpdmRequest->Header.Param2);

    // Create new key
    DEBUG ((DEBUG_INFO, "SpdmCreateUpdateSessionDataKey[%x] Responder\n", SessionId));
    SpdmCreateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, SpdmKeyUpdateActionResponder);
    DEBUG ((DEBUG_INFO, "SpdmActivateUpdateSessionDataKey[%x] Responder new\n", SessionId));
    SpdmActivateUpdateSessionDataKey (SessionInfo->SecuredMessageContext, SpdmKeyUpdateActionResponder, TRUE);
  }

  CopyMem (&SpdmContext->EncapContext.LastEncapRequestHeader, &SpdmRequest->Header, sizeof(SPDM_MESSAGE_HEADER));
  SpdmContext->EncapContext.LastEncapRequestSize = *EncapRequestSize;

  return RETURN_SUCCESS;
}

/**
  Process the SPDM encapsulated KEY_UPDATE response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  EncapResponseSize            Size in bytes of the encapsulated response data.
  @param  EncapResponse                A pointer to the encapsulated response data.
  @param  Continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmProcessEncapResponseKeyUpdate (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapResponseSize,
  IN     VOID                 *EncapResponse,
  OUT    BOOLEAN              *Continue
  )
{
  SPDM_KEY_UPDATE_REQUEST      *SpdmRequest;
  SPDM_KEY_UPDATE_RESPONSE     *SpdmResponse;
  UINTN                        SpdmResponseSize;
  UINT32                       SessionId;
  SPDM_SESSION_INFO            *SessionInfo;
  SPDM_SESSION_STATE           SessionState;

  if (!SpdmContext->LastSpdmRequestSessionIdValid) {
    return RETURN_UNSUPPORTED;
  }
  SessionId = SpdmContext->LastSpdmRequestSessionId;
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    return RETURN_UNSUPPORTED;
  }
  SessionState = SpdmSecuredMessageGetSessionState (SessionInfo->SecuredMessageContext);
  if (SessionState != SpdmSessionStateEstablished) {
    return RETURN_UNSUPPORTED;
  }

  SpdmRequest = (VOID *)&SpdmContext->EncapContext.LastEncapRequestHeader;
  SpdmResponse = EncapResponse;
  SpdmResponseSize = EncapResponseSize;

  if ((SpdmResponseSize != sizeof(SPDM_KEY_UPDATE_RESPONSE)) ||
      (SpdmResponse->Header.RequestResponseCode != SPDM_KEY_UPDATE_ACK) ||
      (SpdmResponse->Header.Param1 != SpdmRequest->Header.Param1) ||
      (SpdmResponse->Header.Param2 != SpdmRequest->Header.Param2) ) {
    if (SpdmRequest->Header.Param1 != SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY) {
      DEBUG ((DEBUG_INFO, "SpdmKeyUpdate[%x] failed\n", SessionId));
    } else {
      DEBUG ((DEBUG_INFO, "SpdmVerifyKey[%x] failed\n", SessionId));
    }
    return RETURN_DEVICE_ERROR;
  }

  if (SpdmRequest->Header.Param1 != SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY) {
    DEBUG ((DEBUG_INFO, "SpdmKeyUpdate[%x] success\n", SessionId));
    *Continue = TRUE;
  } else {
    DEBUG ((DEBUG_INFO, "SpdmVerifyKey[%x] Success\n", SessionId));
    *Continue = FALSE;
  }


  return RETURN_SUCCESS;
}
