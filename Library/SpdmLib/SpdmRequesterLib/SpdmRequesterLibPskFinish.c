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
  UINT8                VerifyData[MAX_HASH_SIZE];
} SPDM_PSK_FINISH_REQUEST_MINE;

#pragma pack()

RETURN_STATUS
GeneratePskFinishHmac(
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        SessionId,
  OUT VOID                        *Hmac
  )
{
  HMAC_ALL                                  HmacAll;
  UINTN                                     HashSize;
  UINT8                                     CalcHmacData[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER                      THCurr = {MAX_SPDM_MESSAGE_BUFFER_SIZE};
  SPDM_SESSION_INFO                         *SessionInfo;
  
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  HmacAll = GetSpdmHmacFunc (SpdmContext);
  ASSERT(HmacAll != NULL);
  HashSize = GetSpdmHashSize (SpdmContext);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "MessagePK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessagePK), GetManagedBufferSize(&SpdmContext->Transcript.MessagePK));

  DEBUG((DEBUG_INFO, "MessagePF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessagePF), GetManagedBufferSize(&SpdmContext->Transcript.MessagePF));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessagePK), GetManagedBufferSize(&SpdmContext->Transcript.MessagePK));
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessagePF), GetManagedBufferSize(&SpdmContext->Transcript.MessagePF));

  ASSERT(SessionInfo->HashSize != 0);
  HmacAll (GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->RequestFinishedKey, SessionInfo->HashSize, CalcHmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (CalcHmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  CopyMem (Hmac, CalcHmacData, HashSize);

  return RETURN_SUCCESS;
}

/**
  This function executes SPDM finish.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceivePskFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId
  )
{
  RETURN_STATUS                             Status;
  SPDM_PSK_FINISH_REQUEST_MINE              SpdmRequest;
  UINTN                                     SpdmRequestSize;
  UINTN                                     HmacSize;
  SPDM_PSK_FINISH_RESPONSE                  SpdmResponse;
  UINTN                                     SpdmResponseSize;
  SPDM_SESSION_INFO                         *SessionInfo;
  
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }
  
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;
   
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_PSK_FINISH;
  SpdmRequest.Header.Param1 = 0;
  SpdmRequest.Header.Param2 = 0;
  
  HmacSize = GetSpdmHashSize (SpdmContext);
  SpdmRequestSize = sizeof(SPDM_FINISH_REQUEST) + HmacSize;
  
  AppendManagedBuffer (&SpdmContext->Transcript.MessagePF, (UINT8 *)&SpdmRequest, SpdmRequestSize - HmacSize);
  
  // Need regenerate the finishedkey
  SpdmGenerateSessionHandshakeKey (SpdmContext, SessionId);
  GeneratePskFinishHmac (SpdmContext, SessionId, SpdmRequest.VerifyData);
  
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
  if (SpdmResponseSize != sizeof(SPDM_PSK_FINISH_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_PSK_FINISH_RSP) {
    return RETURN_DEVICE_ERROR;
  }
  
  Status = SpdmGenerateSessionDataKey (SpdmContext, SessionId);
  if (RETURN_ERROR(Status)) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return Status;
  }

  SessionInfo->SessionState = SpdmStateEstablished;
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  
  return RETURN_SUCCESS;
}

