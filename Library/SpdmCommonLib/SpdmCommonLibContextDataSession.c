/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

/**
  This function initializes the session info.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
**/
VOID
SpdmSessionInfoInit (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     SPDM_SESSION_INFO       *SessionInfo,
  IN     UINT32                  SessionId,
  IN     BOOLEAN                 UsePsk
  )
{
  SPDM_SESSION_TYPE          SessionType;
  UINT32                     CapabilitiesFlag;

  CapabilitiesFlag = SpdmContext->ConnectionInfo.Capability.Flags & SpdmContext->LocalContext.Capability.Flags;
  switch (CapabilitiesFlag &
          (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP)) {
  case 0:
    SessionType = SpdmSessionTypeNone;
    break;
  case (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP) :
    SessionType = SpdmSessionTypeEncMac;
    break;
  case SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP :
    SessionType = SpdmSessionTypeMacOnly;
    break;
  default:
    ASSERT(FALSE);
    SessionType = SpdmSessionTypeMax;
    break;
  }

  ZeroMem (SessionInfo, OFFSET_OF(SPDM_SESSION_INFO, SecuredMessageContext));
  SpdmSecuredMessageInitContext (SessionInfo->SecuredMessageContext);
  SessionInfo->SessionId = SessionId;
  SessionInfo->UsePsk    = UsePsk;
  SpdmSecuredMessageSetUsePsk (SessionInfo->SecuredMessageContext, UsePsk);
  SpdmSecuredMessageSetSessionType (SessionInfo->SecuredMessageContext, SessionType);
  SpdmSecuredMessageSetAlgorithms (
    SessionInfo->SecuredMessageContext,
    SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
    SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup,
    SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite,
    SpdmContext->ConnectionInfo.Algorithm.KeySchedule
    );
  SpdmSecuredMessageSetPskHint (
    SessionInfo->SecuredMessageContext,
    SpdmContext->LocalContext.PskHint,
    SpdmContext->LocalContext.PskHintSize
    );
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

/**
  This function gets the session info via session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return session info.
**/
VOID *
EFIAPI
SpdmGetSessionInfoViaSessionId (
  IN     VOID                      *Context,
  IN     UINT32                    SessionId
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;
  SPDM_SESSION_INFO          *SessionInfo;
  UINTN                      Index;

  if (SessionId == INVALID_SESSION_ID) {
    DEBUG ((DEBUG_ERROR, "SpdmGetSessionInfoViaSessionId - Invalid SessionId\n"));
    ASSERT(FALSE);
    return NULL;
  }

  SpdmContext = Context;

  SessionInfo = SpdmContext->SessionInfo;
  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if (SessionInfo[Index].SessionId == SessionId) {
      return &SessionInfo[Index];
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmGetSessionInfoViaSessionId - not found SessionId\n"));
  return NULL;
}

/**
  This function gets the secured message context via session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return secured message context.
**/
VOID *
EFIAPI
SpdmGetSecuredMessageContextViaSessionId (
  IN     VOID                      *SpdmContext,
  IN     UINT32                    SessionId
  )
{
  SPDM_SESSION_INFO          *SessionInfo;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    return NULL;
  } else {
    return SessionInfo->SecuredMessageContext;
  }
}

/**
  This function gets the secured message context via session ID.

  @param  SpdmSessionInfo              A pointer to the SPDM context.

  @return secured message context.
**/
VOID *
EFIAPI
SpdmGetSecuredMessageContextViaSessionInfo (
  IN     VOID                      *SpdmSessionInfo
  )
{
  SPDM_SESSION_INFO          *SessionInfo;

  SessionInfo = SpdmSessionInfo;
  if (SessionInfo == NULL) {
    return NULL;
  } else {
    return SessionInfo->SecuredMessageContext;
  }
}

/**
  This function assigns a new session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return session info associated with this new session ID.
**/
VOID *
EFIAPI
SpdmAssignSessionId (
  IN     VOID                      *Context,
  IN     UINT32                    SessionId,
  IN     BOOLEAN                   UsePsk
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;
  SPDM_SESSION_INFO          *SessionInfo;
  UINTN                      Index;

  SpdmContext = Context;

  if (SessionId == INVALID_SESSION_ID) {
    DEBUG ((DEBUG_ERROR, "SpdmAssignSessionId - Invalid SessionId\n"));
    ASSERT(FALSE);
    return NULL;
  }

  SessionInfo = SpdmContext->SessionInfo;

  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if (SessionInfo[Index].SessionId == SessionId) {
      DEBUG ((DEBUG_ERROR, "SpdmAssignSessionId - Duplicated SessionId\n"));
      ASSERT(FALSE);
      return NULL;
    }
  }

  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if (SessionInfo[Index].SessionId == INVALID_SESSION_ID) {
      SpdmSessionInfoInit (SpdmContext, &SessionInfo[Index], SessionId, UsePsk);
      SpdmContext->LatestSessionId = SessionId;
      return &SessionInfo[Index];
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmAssignSessionId - MAX SessionId\n"));
  return NULL;
}

/**
  This function allocates half of session ID for a requester.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return half of session ID for a requester.
**/
UINT16
SpdmAllocateReqSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext
  )
{
  UINT16                     ReqSessionId;
  SPDM_SESSION_INFO          *SessionInfo;
  UINTN                      Index;

  SessionInfo = SpdmContext->SessionInfo;
  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if ((SessionInfo[Index].SessionId & 0xFFFF0000) == (INVALID_SESSION_ID & 0xFFFF0000)) {
      ReqSessionId = (UINT16)(0xFFFF - Index);
      return ReqSessionId;
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmAllocateReqSessionId - MAX SessionId\n"));
  return (INVALID_SESSION_ID & 0xFFFF0000) >> 16;
}

/**
  This function allocates half of session ID for a responder.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return half of session ID for a responder.
**/
UINT16
SpdmAllocateRspSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext
  )
{
  UINT16                     RspSessionId;
  SPDM_SESSION_INFO          *SessionInfo;
  UINTN                      Index;

  SessionInfo = SpdmContext->SessionInfo;
  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if ((SessionInfo[Index].SessionId & 0xFFFF) == (INVALID_SESSION_ID & 0xFFFF)) {
      RspSessionId = (UINT16)(0xFFFF - Index);
      return RspSessionId;
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmAllocateRspSessionId - MAX SessionId\n"));
  return (INVALID_SESSION_ID & 0xFFFF);
}

/**
  This function frees a session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return freed session info assicated with this session ID.
**/
VOID *
EFIAPI
SpdmFreeSessionId (
  IN     VOID                      *Context,
  IN     UINT32                    SessionId
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;
  SPDM_SESSION_INFO          *SessionInfo;
  UINTN                      Index;

  SpdmContext = Context;

  if (SessionId == INVALID_SESSION_ID) {
    DEBUG ((DEBUG_ERROR, "SpdmFreeSessionId - Invalid SessionId\n"));
    ASSERT(FALSE);
    return NULL;
  }

  SessionInfo = SpdmContext->SessionInfo;
  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if (SessionInfo[Index].SessionId == SessionId) {
      SpdmSessionInfoInit (SpdmContext, &SessionInfo[Index], INVALID_SESSION_ID, FALSE);
      return &SessionInfo[Index];
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmFreeSessionId - MAX SessionId\n"));
  ASSERT(FALSE);
  return NULL;
}

