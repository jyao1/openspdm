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
  @param  SlotIdParam                  SlotIdParam to the FINISH request.

  @retval RETURN_SUCCESS               The FINISH is sent and the FINISH_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
TrySpdmSendReceiveFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                SlotIdParam
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

  if (((SpdmContext->SpdmCmdReceiveState & SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CAPABILITIES_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_KEY_EXCHANGE_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_DIGESTS_RECEIVE_FLAG) == 0)) {
    return RETURN_DEVICE_ERROR;
  }
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  if (SessionInfo->MutAuthRequested != 0) {
    if ((SlotIdParam >= SpdmContext->LocalContext.SlotCount) && (SlotIdParam != 0xFF)) {
      return RETURN_INVALID_PARAMETER;
    }
  } else {
    if (SlotIdParam != 0) {
      return RETURN_INVALID_PARAMETER;
    }
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;
   
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_FINISH;
  if (SessionInfo->MutAuthRequested) {
    SpdmRequest.Header.Param1 = SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED;
    SpdmRequest.Header.Param2 = SlotIdParam;
    SignatureSize = GetSpdmReqAsymSize (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg);
  } else {
    SpdmRequest.Header.Param1 = 0;
    SpdmRequest.Header.Param2 = 0;
    SignatureSize = 0;
  }
  
  if (SlotIdParam == 0xFF) {
    SlotIdParam = SpdmContext->LocalContext.ProvisionedSlotNum;
  }

  if (SessionInfo->MutAuthRequested) {
    SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = SpdmContext->LocalContext.CertificateChain[SlotIdParam];
    SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = SpdmContext->LocalContext.CertificateChainSize[SlotIdParam];
  }

  HmacSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  SpdmRequestSize = sizeof(SPDM_FINISH_REQUEST) + SignatureSize + HmacSize;
  Ptr = SpdmRequest.Signature;
  
  Status = AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, (UINT8 *)&SpdmRequest, sizeof(SPDM_FINISH_REQUEST));
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }
  if (SessionInfo->MutAuthRequested) {
    Result = SpdmGenerateFinishReqSignature (SpdmContext, SessionInfo, Ptr);
    if (!Result) {
      return RETURN_SECURITY_VIOLATION;
    }
    Status = AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, Ptr, SignatureSize);
    if (RETURN_ERROR(Status)) {
      return RETURN_SECURITY_VIOLATION;
    }
    Ptr += SignatureSize;
  }

  Result = SpdmGenerateFinishReqHmac (SpdmContext, SessionInfo, Ptr);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }

  Status = AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, Ptr, HmacSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) != 0) {
    Status = SpdmSendSpdmRequest (SpdmContext, NULL, SpdmRequestSize, &SpdmRequest);
  } else {
    Status = SpdmSendSpdmRequest (SpdmContext, &SessionId, SpdmRequestSize, &SpdmRequest);
  }
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) != 0) {
    Status = SpdmReceiveSpdmResponse (SpdmContext, NULL, &SpdmResponseSize, &SpdmResponse);
  } else {
    Status = SpdmReceiveSpdmResponse (SpdmContext, &SessionId, &SpdmResponseSize, &SpdmResponse);
  }
  if (RETURN_ERROR(Status)) {
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

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
    HmacSize = 0;
  }

  if (SpdmResponseSize != sizeof(SPDM_FINISH_RESPONSE) + HmacSize) {
    return RETURN_DEVICE_ERROR;
  }

  Status = AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, &SpdmResponse, sizeof(SPDM_FINISH_RESPONSE));
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) != 0) {
    DEBUG((DEBUG_INFO, "VerifyData (0x%x):\n", HmacSize));
    InternalDumpHex (SpdmResponse.VerifyData, HmacSize);
    Result = SpdmVerifyFinishRspHmac (SpdmContext, SessionInfo, SpdmResponse.VerifyData, HmacSize);
    if (!Result) {
      return RETURN_SECURITY_VIOLATION;
    }

    Status = AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, (UINT8 *)&SpdmResponse + sizeof(SPDM_FINISH_RESPONSE), HmacSize);
    if (RETURN_ERROR(Status)) {
      return RETURN_SECURITY_VIOLATION;
    }
  }

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionDataKey[%x]\n", SessionId));
  Status = SpdmCalculateTh2 (SpdmContext, SessionInfo, TRUE, TH2HashData);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }
  Status = SpdmGenerateSessionDataKey (SessionInfo->SecuredMessageContext, TH2HashData);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateEstablished);
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  SpdmContext->SpdmCmdReceiveState |= SPDM_FINISH_RECEIVE_FLAG;
  
  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmSendReceiveFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                SlotIdParam
  )
{
  UINTN                   Retry;
  RETURN_STATUS           Status;

  Retry = SpdmContext->RetryTimes;
  do {
    Status = TrySpdmSendReceiveFinish(SpdmContext, SessionId, SlotIdParam);
    if (RETURN_NO_RESPONSE != Status) {
      return Status;
    }
  } while (Retry-- != 0);

  return Status;
}

