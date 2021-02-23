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
  UINT8                Signature[MAX_ASYM_KEY_SIZE];
  UINT8                VerifyData[MAX_HASH_SIZE];
} SPDM_FINISH_REQUEST_MINE;

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                VerifyData[MAX_HASH_SIZE];
} SPDM_FINISH_RESPONSE_MINE;

#pragma pack()

/**
  This function sends FINISH and receives FINISH_RSP for SPDM finish.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    SessionId to the FINISH request.
  @param  ReqSlotIdParam               ReqSlotIdParam to the FINISH request.

  @retval RETURN_SUCCESS               The FINISH is sent and the FINISH_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
TrySpdmSendReceiveFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                ReqSlotIdParam
  )
{
  RETURN_STATUS                             Status;
  SPDM_FINISH_REQUEST_MINE                  SpdmRequest;
  UINTN                                     SpdmRequestSize;
  UINTN                                     SignatureSize;
  UINTN                                     HmacSize;
  SPDM_FINISH_RESPONSE_MINE                 SpdmResponse;
  UINTN                                     SpdmResponseSize;
  SPDM_SESSION_INFO                         *SessionInfo;
  UINT8                                     *Ptr;
  BOOLEAN                                   Result;
  UINT8                                     TH2HashData[64];
  SPDM_SESSION_STATE                        SessionState;

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
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
  if (SessionState != SpdmSessionStateHandshaking) {
    return RETURN_UNSUPPORTED;
  }

  if (SessionInfo->MutAuthRequested != 0) {
    if ((ReqSlotIdParam >= SpdmContext->LocalContext.SlotCount) && (ReqSlotIdParam != 0xFF)) {
      return RETURN_INVALID_PARAMETER;
    }
  } else {
    if (ReqSlotIdParam != 0) {
      return RETURN_INVALID_PARAMETER;
    }
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;
   
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_FINISH;
  if (SessionInfo->MutAuthRequested) {
    SpdmRequest.Header.Param1 = SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED;
    SpdmRequest.Header.Param2 = ReqSlotIdParam;
    SignatureSize = GetSpdmReqAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg);
  } else {
    SpdmRequest.Header.Param1 = 0;
    SpdmRequest.Header.Param2 = 0;
    SignatureSize = 0;
  }
  
  if (ReqSlotIdParam == 0xFF) {
    ReqSlotIdParam = SpdmContext->LocalContext.ProvisionedSlotNum;
  }

  if (SessionInfo->MutAuthRequested) {
    SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = SpdmContext->LocalContext.LocalCertChainProvision[ReqSlotIdParam];
    SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = SpdmContext->LocalContext.LocalCertChainProvisionSize[ReqSlotIdParam];
  }

  HmacSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  SpdmRequestSize = sizeof(SPDM_FINISH_REQUEST) + SignatureSize + HmacSize;
  Ptr = SpdmRequest.Signature;
  
  Status = SpdmAppendMessageF (SessionInfo, (UINT8 *)&SpdmRequest, sizeof(SPDM_FINISH_REQUEST));
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }
  if (SessionInfo->MutAuthRequested) {
    Result = SpdmGenerateFinishReqSignature (SpdmContext, SessionInfo, Ptr);
    if (!Result) {
      return RETURN_SECURITY_VIOLATION;
    }
    Status = SpdmAppendMessageF (SessionInfo, Ptr, SignatureSize);
    if (RETURN_ERROR(Status)) {
      return RETURN_SECURITY_VIOLATION;
    }
    Ptr += SignatureSize;
  }

  Result = SpdmGenerateFinishReqHmac (SpdmContext, SessionInfo, Ptr);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }

  Status = SpdmAppendMessageF (SessionInfo, Ptr, HmacSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

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
    Status = SpdmHandleErrorResponseMain(SpdmContext, &SessionId, &SessionInfo->SessionTranscript.MessageF, SpdmRequestSize, &SpdmResponseSize, &SpdmResponse, SPDM_FINISH, SPDM_FINISH_RSP, sizeof(SPDM_FINISH_RESPONSE_MINE));
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else if (SpdmResponse.Header.RequestResponseCode != SPDM_FINISH_RSP) {
    return RETURN_DEVICE_ERROR;
  }

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
    HmacSize = 0;
  }

  if (SpdmResponseSize != sizeof(SPDM_FINISH_RESPONSE) + HmacSize) {
    return RETURN_DEVICE_ERROR;
  }

  Status = SpdmAppendMessageF (SessionInfo, &SpdmResponse, sizeof(SPDM_FINISH_RESPONSE));
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
    DEBUG((DEBUG_INFO, "VerifyData (0x%x):\n", HmacSize));
    InternalDumpHex (SpdmResponse.VerifyData, HmacSize);
    Result = SpdmVerifyFinishRspHmac (SpdmContext, SessionInfo, SpdmResponse.VerifyData, HmacSize);
    if (!Result) {
      return RETURN_SECURITY_VIOLATION;
    }

    Status = SpdmAppendMessageF (SessionInfo, (UINT8 *)&SpdmResponse + sizeof(SPDM_FINISH_RESPONSE), HmacSize);
    if (RETURN_ERROR(Status)) {
      return RETURN_SECURITY_VIOLATION;
    }
  }

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionDataKey[%x]\n", SessionId));
  Status = SpdmCalculateTH2Hash (SpdmContext, SessionInfo, TRUE, TH2HashData);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }
  Status = SpdmGenerateSessionDataKey (SessionInfo->SecuredMessageContext, TH2HashData);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  
  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmSendReceiveFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                ReqSlotIdParam
  )
{
  UINTN                   Retry;
  RETURN_STATUS           Status;

  Retry = SpdmContext->RetryTimes;
  do {
    Status = TrySpdmSendReceiveFinish(SpdmContext, SessionId, ReqSlotIdParam);
    if (RETURN_NO_RESPONSE != Status) {
      return Status;
    }
  } while (Retry-- != 0);

  return Status;
}

