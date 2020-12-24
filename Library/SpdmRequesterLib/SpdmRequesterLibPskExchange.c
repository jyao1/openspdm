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
  UINT16               PSKHintLength;
  UINT16               RequesterContextLength;
  UINT16               OpaqueLength;
  UINT8                PSKHint[MAX_SPDM_PSK_HINT_LENGTH];
  UINT8                RequesterContext[DEFAULT_CONTEXT_LENGTH];
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
} SPDM_PSK_EXCHANGE_REQUEST_MINE;

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               RspSessionID;
  UINT16               Reserved;
  UINT16               ResponderContextLength;
  UINT16               OpaqueLength;
  UINT8                MeasurementSummaryHash[MAX_HASH_SIZE];
  UINT8                ResponderContext[DEFAULT_CONTEXT_LENGTH];
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
  UINT8                VerifyData[MAX_HASH_SIZE];
} SPDM_PSK_EXCHANGE_RESPONSE_MAX;

#pragma pack()

/**
  This function sends PSK_EXCHANGE and receives PSK_EXCHANGE_RSP for SPDM PSK exchange.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MeasurementHashType          MeasurementHashType to the PSK_EXCHANGE request.
  @param  HeartbeatPeriod              HeartbeatPeriod from the PSK_EXCHANGE_RSP response.
  @param  SessionId                    SessionId from the PSK_EXCHANGE_RSP response.
  @param  MeasurementHash              MeasurementHash from the PSK_EXCHANGE_RSP response.

  @retval RETURN_SUCCESS               The PSK_EXCHANGE is sent and the PSK_EXCHANGE_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmSendReceivePskExchange (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementHashType,
     OUT UINT32               *SessionId,
     OUT UINT8                *HeartbeatPeriod,
     OUT VOID                 *MeasurementHash
  )
{
  BOOLEAN                                   Result;
  RETURN_STATUS                             Status;
  SPDM_PSK_EXCHANGE_REQUEST_MINE            SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_PSK_EXCHANGE_RESPONSE_MAX            SpdmResponse;
  UINTN                                     SpdmResponseSize;
  UINT32                                    HashSize;
  UINT32                                    HmacSize;
  UINT8                                     *Ptr;
  VOID                                      *MeasurementSummaryHash;
  UINT8                                     *VerifyData;
  UINT16                                    ReqSessionId;
  UINT16                                    RspSessionId;
  SPDM_SESSION_INFO                         *SessionInfo;
  UINTN                                     OpaquePskExchangeReqSize;

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_PSK_EXCHANGE;
  SpdmRequest.Header.Param1 = MeasurementHashType;
  SpdmRequest.Header.Param2 = 0;
  SpdmRequest.PSKHintLength = (UINT16)SpdmContext->LocalContext.PskHintSize;
  SpdmRequest.RequesterContextLength = DEFAULT_CONTEXT_LENGTH;
  OpaquePskExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  SpdmRequest.OpaqueLength = (UINT16)OpaquePskExchangeReqSize;

  ReqSessionId = SpdmAllocateReqSessionId (SpdmContext);
  SpdmRequest.ReqSessionID = ReqSessionId;

  Ptr = SpdmRequest.PSKHint;
  CopyMem (Ptr, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize);
  DEBUG((DEBUG_INFO, "PskHint (0x%x) - ", SpdmRequest.PSKHintLength));
  InternalDumpData (Ptr, SpdmRequest.PSKHintLength);
  DEBUG((DEBUG_INFO, "\n"));
  Ptr += SpdmRequest.PSKHintLength;

  SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
  DEBUG((DEBUG_INFO, "ClientRandomData (0x%x) - ", SpdmRequest.RequesterContextLength));
  InternalDumpData (Ptr, SpdmRequest.RequesterContextLength);
  DEBUG((DEBUG_INFO, "\n"));
  Ptr += SpdmRequest.RequesterContextLength;

  Status = SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaquePskExchangeReqSize, Ptr);
  ASSERT_RETURN_ERROR(Status);
  Ptr += OpaquePskExchangeReqSize;

  SpdmRequestSize = (UINTN)Ptr - (UINTN)&SpdmRequest;
  Status = SpdmSendSpdmRequest (SpdmContext, NULL, SpdmRequestSize, &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, NULL, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_PSK_EXCHANGE_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_PSK_EXCHANGE_RSP) {
    return RETURN_DEVICE_ERROR;
  }
  if (HeartbeatPeriod != NULL) {
    *HeartbeatPeriod = SpdmResponse.Header.Param1;
  }
  RspSessionId = SpdmResponse.RspSessionID;
  *SessionId = (ReqSessionId << 16) | RspSessionId;
  SessionInfo = SpdmAssignSessionId (SpdmContext, *SessionId);
  if (SessionInfo == NULL) {
    return RETURN_DEVICE_ERROR;
  }
  SessionInfo->UsePsk = TRUE;

  //
  // Cache session data
  //
  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageK, &SpdmRequest, SpdmRequestSize);

  HashSize = GetSpdmHashSize (SpdmContext);
  HmacSize = GetSpdmHashSize (SpdmContext);

  if (SpdmResponseSize < sizeof(SPDM_PSK_EXCHANGE_RESPONSE) +
                         SpdmResponse.ResponderContextLength +
                         SpdmResponse.OpaqueLength +
                         HashSize +
                         HmacSize) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    return RETURN_DEVICE_ERROR;
  }

  Ptr = (UINT8 *)&SpdmResponse + sizeof(SPDM_PSK_EXCHANGE_RESPONSE) + HashSize + SpdmResponse.ResponderContextLength;
  Status = SpdmProcessOpaqueDataVersionSelectionData (SpdmContext, SpdmResponse.OpaqueLength, Ptr);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    return RETURN_UNSUPPORTED;
  }

  SpdmResponseSize = sizeof(SPDM_PSK_EXCHANGE_RESPONSE) +
                     SpdmResponse.ResponderContextLength +
                     SpdmResponse.OpaqueLength +
                     HashSize +
                     HmacSize;

  Ptr = (UINT8 *)(SpdmResponse.MeasurementSummaryHash);
  MeasurementSummaryHash = Ptr;
  DEBUG((DEBUG_INFO, "MeasurementSummaryHash (0x%x) - ", HashSize));
  InternalDumpData (MeasurementSummaryHash, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Ptr += HashSize;

  DEBUG((DEBUG_INFO, "ServerRandomData (0x%x) - ", SpdmResponse.ResponderContextLength));
  InternalDumpData (Ptr, SpdmResponse.ResponderContextLength);
  DEBUG((DEBUG_INFO, "\n"));

  Ptr += SpdmResponse.ResponderContextLength;

  Ptr += SpdmResponse.OpaqueLength;

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageK, &SpdmResponse, SpdmResponseSize - HmacSize);

  Status = SpdmGenerateSessionHandshakeKey (SpdmContext, *SessionId, TRUE);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return Status;
  }

  VerifyData = Ptr;
  DEBUG((DEBUG_INFO, "VerifyData (0x%x):\n", HmacSize));
  InternalDumpHex (VerifyData, HmacSize);
  Result = SpdmVerifyPskExchangeRspHmac (SpdmContext, SessionInfo, VerifyData, HmacSize);
  if (!Result) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageK, VerifyData, HmacSize);

  if (MeasurementHash != NULL) {
    CopyMem (MeasurementHash, MeasurementSummaryHash, HashSize);
  }

  SessionInfo->SessionState = SpdmSessionStateHandshaking;
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  
  return RETURN_SUCCESS;
}

