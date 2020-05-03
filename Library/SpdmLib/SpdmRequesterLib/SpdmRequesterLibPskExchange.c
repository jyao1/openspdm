/** @file
  EDKII Device Security library for SPDM device.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

#pragma pack(1)

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               OpaqueLength;
  UINT8                RequesterContextLength;
  UINT8                Reserved;
  UINT8                RequesterContext[DEFAULT_CONTEXT_LENGTH];
  UINT8                OpaqueData[DEFAULT_OPAQUE_LENGTH];
} SPDM_PSK_EXCHANGE_REQUEST_MINE;

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                ResponderContextLength;
  UINT8                Reserved[3];
  UINT8                ResponderContext[DEFAULT_CONTEXT_LENGTH];
  UINT8                MeasurementSummaryHash[MAX_HASH_SIZE];
  UINT8                VerifyData[MAX_HASH_SIZE];
} SPDM_PSK_EXCHANGE_RESPONSE_MAX;

#pragma pack()

RETURN_STATUS
VerifyPskExchangeHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     VOID                 *HmacData,
  IN     UINTN                HmacDataSize
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
  ASSERT(HashSize == HmacDataSize);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "MessagePK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessagePK), GetManagedBufferSize(&SpdmContext->Transcript.MessagePK));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessagePK), GetManagedBufferSize(&SpdmContext->Transcript.MessagePK));

  ASSERT(SessionInfo->HashSize != 0);
  HmacAll (GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->ResponseFinishedKey, SessionInfo->HashSize, CalcHmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (CalcHmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (CompareMem (CalcHmacData, HmacData, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyPskExchangeHmac - FAIL !!!\n"));
    return RETURN_SECURITY_VIOLATION;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyPskExchangeHmac - PASS !!!\n"));

  return RETURN_SUCCESS;
}

/**
  This function executes SPDM psk change.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceivePskExchange (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementHashType,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT8                *SessionId,
     OUT VOID                 *MeasurementHash
  )
{
  RETURN_STATUS                             Status;
  SPDM_PSK_EXCHANGE_REQUEST_MINE            SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_PSK_EXCHANGE_RESPONSE_MAX            SpdmResponse;
  UINTN                                     SpdmResponseSize;
  UINT32                                    HashSize;
  UINT32                                    SignatureSize;
  UINT32                                    HmacSize;
  UINT8                                     *Ptr;
  VOID                                      *MeasurementSummaryHash;
  UINT8                                     *VerifyData;
  SPDM_SESSION_INFO                         *SessionInfo;

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmContext->ErrorState = EDKII_SPDM_ERROR_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_PSK_EXCHANGE;
  SpdmRequest.Header.Param1 = MeasurementHashType;
  SpdmRequest.Header.Param2 = 0;
  SpdmRequest.OpaqueLength = DEFAULT_OPAQUE_LENGTH;
  SpdmRequest.RequesterContextLength = DEFAULT_CONTEXT_LENGTH;
  SpdmRequest.Reserved = 0;
  GetRandomNumber (DEFAULT_CONTEXT_LENGTH, SpdmRequest.RequesterContext);
  DEBUG((DEBUG_INFO, "ClientRandomData (0x%x) - ", SpdmRequest.RequesterContextLength));
  InternalDumpData (SpdmRequest.RequesterContext, SpdmRequest.RequesterContextLength);
  DEBUG((DEBUG_INFO, "\n"));

  SetMem (SpdmRequest.OpaqueData, DEFAULT_OPAQUE_LENGTH, DEFAULT_OPAQUE_DATA);

  SpdmRequestSize = sizeof(SPDM_PSK_EXCHANGE_REQUEST_MINE);
  Status = SpdmSendRequest (SpdmContext, SpdmRequestSize, &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveResponse (SpdmContext, &SpdmResponseSize, &SpdmResponse);
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
  *SessionId = SpdmResponse.Header.Param2;
  SessionInfo = SpdmAssignSessionId (SpdmContext, *SessionId);
  SessionInfo->UsePsk = TRUE;

  SignatureSize = GetSpdmAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);
  HmacSize = GetSpdmHashSize (SpdmContext);

  if (SpdmResponseSize != sizeof(SPDM_PSK_EXCHANGE_RESPONSE) +
                          SpdmResponse.ResponderContextLength +
                          HashSize +
                          HmacSize) {
    return RETURN_DEVICE_ERROR;
  }

  Ptr = (UINT8 *)(SpdmResponse.ResponderContext);
  DEBUG((DEBUG_INFO, "ServerRandomData (0x%x) - ", SpdmResponse.ResponderContextLength));
  InternalDumpData (Ptr, SpdmResponse.ResponderContextLength);
  DEBUG((DEBUG_INFO, "\n"));

  Ptr += SpdmResponse.ResponderContextLength;
  
  MeasurementSummaryHash = Ptr;
  DEBUG((DEBUG_INFO, "MeasurementSummaryHash (0x%x) - ", HashSize));
  InternalDumpData (MeasurementSummaryHash, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Ptr += HashSize;

  Status = SpdmGenerateSessionHandshakeKey (SpdmContext, *SessionId);
  if (RETURN_ERROR(Status)) {
    SpdmContext->ErrorState = EDKII_SPDM_ERROR_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return Status;
  }

  VerifyData = Ptr;
  DEBUG((DEBUG_INFO, "VerifyData (0x%x):\n", HmacSize));
  InternalDumpHex (VerifyData, HmacSize);
  Status = VerifyPskExchangeHmac (SpdmContext, *SessionId, VerifyData, HmacSize);
  if (RETURN_ERROR(Status)) {
    SpdmContext->ErrorState = EDKII_SPDM_ERROR_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return Status;
  }

  if (MeasurementHash != NULL) {
    CopyMem (MeasurementHash, MeasurementSummaryHash, HashSize);
  }

  SessionInfo->SessionState = EdkiiSpdmStateHandshaking;
  SpdmContext->ErrorState = EDKII_SPDM_ERROR_STATUS_SUCCESS;
  
  return RETURN_SUCCESS;
}

