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
  UINT16               ReqSessionID;
  UINT16               Reserved;
  UINT8                RandomData[SPDM_RANDOM_DATA_SIZE];
  UINT8                ExchangeData[MAX_DHE_KEY_SIZE];
  UINT16               OpaqueLength;
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
} SPDM_KEY_EXCHANGE_REQUEST_MINE;

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               RspSessionID;
  UINT8                MutAuthRequested;
  UINT8                ReqSlotIDParam;
  UINT8                RandomData[SPDM_RANDOM_DATA_SIZE];
  UINT8                ExchangeData[MAX_DHE_KEY_SIZE];
  UINT8                MeasurementSummaryHash[MAX_HASH_SIZE];
  UINT16               OpaqueLength;
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
  UINT8                Signature[MAX_ASYM_KEY_SIZE];
  UINT8                ResponderVer[MAX_HASH_SIZE];
} SPDM_KEY_EXCHANGE_RESPONSE_MAX;

#pragma pack()

/**
  This function sends KEY_EXCHANGE and receives KEY_EXCHANGE_RSP for SPDM key exchange.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MeasurementHashType          MeasurementHashType to the KEY_EXCHANGE request.
  @param  SlotNum                      SlotNum to the KEY_EXCHANGE request.
  @param  HeartbeatPeriod              HeartbeatPeriod from the KEY_EXCHANGE_RSP response.
  @param  SessionId                    SessionId from the KEY_EXCHANGE_RSP response.
  @param  ReqSlotIdParam               ReqSlotIdParam from the KEY_EXCHANGE_RSP response.
  @param  MeasurementHash              MeasurementHash from the KEY_EXCHANGE_RSP response.

  @retval RETURN_SUCCESS               The KEY_EXCHANGE is sent and the KEY_EXCHANGE_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
TrySpdmSendReceiveKeyExchange (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT32               *SessionId,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT8                *ReqSlotIdParam,
     OUT VOID                 *MeasurementHash
  )
{
  BOOLEAN                                   Result;
  RETURN_STATUS                             Status;
  SPDM_KEY_EXCHANGE_REQUEST_MINE            SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_KEY_EXCHANGE_RESPONSE_MAX            SpdmResponse;
  UINTN                                     SpdmResponseSize;
  UINTN                                     DheKeySize;
  UINT32                                    MeasurementSummaryHashSize;
  UINT32                                    SignatureSize;
  UINT32                                    HmacSize;
  UINT8                                     *Ptr;
  VOID                                      *MeasurementSummaryHash;
  UINT16                                    OpaqueLength;
  UINT8                                     *Signature;
  UINT8                                     *VerifyData;
  VOID                                      *DHEContext;
  UINT16                                    ReqSessionId;
  UINT16                                    RspSessionId;
  SPDM_SESSION_INFO                         *SessionInfo;
  UINTN                                     OpaqueKeyExchangeReqSize;
  UINT8                                     TH1HashData[64];

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
    return RETURN_UNSUPPORTED;
  }
  if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateNegotiated) {
    return RETURN_UNSUPPORTED;
  }

  if ((SlotNum >= MAX_SPDM_SLOT_COUNT) && (SlotNum != 0xFF)) {
    return RETURN_INVALID_PARAMETER;
  }
  if ((SlotNum == 0xFF) && (SpdmContext->LocalContext.PeerCertChainProvisionSize == 0)) {
    return RETURN_INVALID_PARAMETER;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_KEY_EXCHANGE;
  SpdmRequest.Header.Param1 = MeasurementHashType;
  SpdmRequest.Header.Param2 = SlotNum;
  SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmRequest.RandomData);
  DEBUG((DEBUG_INFO, "ClientRandomData (0x%x) - ", SPDM_RANDOM_DATA_SIZE));
  InternalDumpData (SpdmRequest.RandomData, SPDM_RANDOM_DATA_SIZE);
  DEBUG((DEBUG_INFO, "\n"));

  ReqSessionId = SpdmAllocateReqSessionId (SpdmContext);
  SpdmRequest.ReqSessionID = ReqSessionId;
  SpdmRequest.Reserved = 0;

  Ptr = SpdmRequest.ExchangeData;
  DheKeySize = GetSpdmDhePubKeySize (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup);
  DHEContext = SpdmSecuredMessageDheNew (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup);
  SpdmSecuredMessageDheGenerateKey (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext, Ptr, &DheKeySize);
  DEBUG((DEBUG_INFO, "ClientKey (0x%x):\n", DheKeySize));
  InternalDumpHex (Ptr, DheKeySize);
  Ptr += DheKeySize;

  OpaqueKeyExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeReqSize;
  Ptr += sizeof(UINT16);
  Status = SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaqueKeyExchangeReqSize, Ptr);
  ASSERT_RETURN_ERROR(Status);
  Ptr += OpaqueKeyExchangeReqSize;

  SpdmRequestSize = (UINTN)Ptr - (UINTN)&SpdmRequest;
  Status = SpdmSendSpdmRequest (SpdmContext, NULL, SpdmRequestSize, &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, NULL, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_MESSAGE_HEADER)) {
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode == SPDM_ERROR) {
    Status = SpdmHandleErrorResponseMain(SpdmContext, NULL, NULL, 0, &SpdmResponseSize, &SpdmResponse, SPDM_KEY_EXCHANGE, SPDM_KEY_EXCHANGE_RSP, sizeof(SPDM_KEY_EXCHANGE_RESPONSE_MAX));
    if (RETURN_ERROR(Status)) {
      SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
      return Status;
    }
  } else if (SpdmResponse.Header.RequestResponseCode != SPDM_KEY_EXCHANGE_RSP) {
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_KEY_EXCHANGE_RESPONSE)) {
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_DEVICE_ERROR;
  }

  if (HeartbeatPeriod != NULL) {
    *HeartbeatPeriod = SpdmResponse.Header.Param1;
  }
  *ReqSlotIdParam = SpdmResponse.ReqSlotIDParam;
  if (SpdmResponse.MutAuthRequested != 0) {
    if ((*ReqSlotIdParam != 0xF) && (*ReqSlotIdParam >= SpdmContext->LocalContext.SlotCount)) {
      SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
      return RETURN_DEVICE_ERROR;
    }
  } else {
    if (*ReqSlotIdParam != 0) {
      SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
      return RETURN_DEVICE_ERROR;
    }
  }
  RspSessionId = SpdmResponse.RspSessionID;
  *SessionId = (ReqSessionId << 16) | RspSessionId;
  SessionInfo = SpdmAssignSessionId (SpdmContext, *SessionId, FALSE);
  if (SessionInfo == NULL) {
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache session data
  //
  Status = SpdmAppendMessageK (SessionInfo, &SpdmRequest, SpdmRequestSize);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_SECURITY_VIOLATION;
  }

  SignatureSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
  MeasurementSummaryHashSize = SpdmGetMeasurementSummaryHashSize (SpdmContext, TRUE, MeasurementHashType);
  HmacSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
    HmacSize = 0;
  }

  if (SpdmResponseSize <  sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
                          DheKeySize +
                          MeasurementSummaryHashSize +
                          sizeof(UINT16) +
                          SignatureSize +
                          HmacSize) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_DEVICE_ERROR;
  }

  DEBUG((DEBUG_INFO, "ServerRandomData (0x%x) - ", SPDM_RANDOM_DATA_SIZE));
  InternalDumpData (SpdmResponse.RandomData, SPDM_RANDOM_DATA_SIZE);
  DEBUG((DEBUG_INFO, "\n"));

  DEBUG((DEBUG_INFO, "ServerKey (0x%x):\n", DheKeySize));
  InternalDumpHex (SpdmResponse.ExchangeData, DheKeySize);

  Ptr = SpdmResponse.ExchangeData;
  Ptr += DheKeySize;

  MeasurementSummaryHash = Ptr;
  DEBUG((DEBUG_INFO, "MeasurementSummaryHash (0x%x) - ", MeasurementSummaryHashSize));
  InternalDumpData (MeasurementSummaryHash, MeasurementSummaryHashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Ptr += MeasurementSummaryHashSize;

  OpaqueLength = *(UINT16 *)Ptr;
  if (OpaqueLength > MAX_SPDM_OPAQUE_DATA_SIZE) {
    return RETURN_SECURITY_VIOLATION;
  }
  Ptr += sizeof(UINT16);
  if (SpdmResponseSize < sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
                         DheKeySize +
                         MeasurementSummaryHashSize +
                         sizeof(UINT16) +
                         OpaqueLength +
                         SignatureSize +
                         HmacSize) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_DEVICE_ERROR;
  }
  Status = SpdmProcessOpaqueDataVersionSelectionData (SpdmContext, OpaqueLength, Ptr);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_UNSUPPORTED;
  }

  Ptr += OpaqueLength;

  SpdmResponseSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
                     DheKeySize +
                     MeasurementSummaryHashSize +
                     sizeof(UINT16) +
                     OpaqueLength +
                     SignatureSize +
                     HmacSize;

  Status = SpdmAppendMessageK (SessionInfo, &SpdmResponse, SpdmResponseSize - SignatureSize - HmacSize);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_SECURITY_VIOLATION;
  }

  Signature = Ptr;
  DEBUG((DEBUG_INFO, "Signature (0x%x):\n", SignatureSize));
  InternalDumpHex (Signature, SignatureSize);
  Ptr += SignatureSize;
  Result = SpdmVerifyKeyExchangeRspSignature (SpdmContext, SessionInfo, Signature, SignatureSize);
  if (!Result) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  Status = SpdmAppendMessageK (SessionInfo, Signature, SignatureSize);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
    return RETURN_SECURITY_VIOLATION;
  }

  //
  // Fill data to calc Secret for HMAC verification
  //
  Result = SpdmSecuredMessageDheComputeKey (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext, SpdmResponse.ExchangeData, DheKeySize, SessionInfo->SecuredMessageContext);
  SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
  if (!Result) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    return RETURN_SECURITY_VIOLATION;
  }

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionHandshakeKey[%x]\n", *SessionId));
  Status = SpdmCalculateTH1Hash (SpdmContext, SessionInfo, TRUE, TH1HashData);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    return RETURN_SECURITY_VIOLATION;
  }
  Status = SpdmGenerateSessionHandshakeKey (SessionInfo->SecuredMessageContext, TH1HashData);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    return RETURN_SECURITY_VIOLATION;
  }

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
    VerifyData = Ptr;
    DEBUG((DEBUG_INFO, "VerifyData (0x%x):\n", HmacSize));
    InternalDumpHex (VerifyData, HmacSize);
    Result = SpdmVerifyKeyExchangeRspHmac (SpdmContext, SessionInfo, VerifyData, HmacSize);
    if (!Result) {
      SpdmFreeSessionId (SpdmContext, *SessionId);
      SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
      return RETURN_SECURITY_VIOLATION;
    }
    Ptr += HmacSize;

    Status = SpdmAppendMessageK (SessionInfo, VerifyData, HmacSize);
    if (RETURN_ERROR(Status)) {
      SpdmFreeSessionId (SpdmContext, *SessionId);
      return RETURN_SECURITY_VIOLATION;
    }
  }

  if (MeasurementHash != NULL) {
    CopyMem (MeasurementHash, MeasurementSummaryHash, MeasurementSummaryHashSize);
  }
  SessionInfo->MutAuthRequested = SpdmResponse.MutAuthRequested;

  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateHandshaking);
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmSendReceiveKeyExchange (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT32               *SessionId,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT8                *ReqSlotIdParam,
     OUT VOID                 *MeasurementHash
  )
{
  UINTN                   Retry;
  RETURN_STATUS           Status;

  Retry = SpdmContext->RetryTimes;
  do {
    Status = TrySpdmSendReceiveKeyExchange(SpdmContext, MeasurementHashType, SlotNum, SessionId, HeartbeatPeriod, ReqSlotIdParam, MeasurementHash);
    if (RETURN_NO_RESPONSE != Status) {
      return Status;
    }
  } while (Retry-- != 0);

  return Status;
}

