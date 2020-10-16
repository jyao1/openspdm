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
  UINT8                SlotIDParam;
  UINT8                RandomData[SPDM_RANDOM_DATA_SIZE];
  UINT8                ExchangeData[MAX_DHE_KEY_SIZE];
  UINT8                MeasurementSummaryHash[MAX_HASH_SIZE];
  UINT16               OpaqueLength;
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
  UINT8                Signature[MAX_ASYM_KEY_SIZE];
  UINT8                ResponderVer[MAX_HASH_SIZE];
} SPDM_KEY_EXCHANGE_RESPONSE_MAX;

#pragma pack()

BOOLEAN
SpdmRequesterVerifyKeyExchangeSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN SPDM_SESSION_INFO            *SessionInfo,
  IN VOID                         *SignData,
  IN INTN                         SignDataSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     HashData[MAX_HASH_SIZE];
  BOOLEAN                                   Result;
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  UINT8                                     CertBufferHash[MAX_HASH_SIZE];
  VOID                                      *Context;
  LARGE_MANAGED_BUFFER                      THCurr;
  UINT8                                     *CertChainBuffer;
  UINTN                                     CertChainBufferSize;

  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  HashSize = GetSpdmHashSize (SpdmContext);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize == 0) {
    return FALSE;
  }

  CertChainBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertChainBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  SpdmHashAll (SpdmContext, CertChainBuffer, CertChainBufferSize, CertBufferHash);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
  InternalDumpHex (CertChainBuffer, CertChainBufferSize);

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  SpdmHashAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
  DEBUG((DEBUG_INFO, "THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  //
  // Get leaf cert from cert chain
  //
  Result = X509GetCertFromCertChain (CertChainBuffer, CertChainBufferSize, -1,  &CertBuffer, &CertBufferSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymGetPublicKeyFromX509 (SpdmContext, CertBuffer, CertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymVerify (
             SpdmContext,
             Context,
             HashData,
             HashSize,
             SignData,
             SignDataSize
             );
  SpdmAsymFree (SpdmContext, Context);
  if (!Result) {
    DEBUG((DEBUG_INFO, "!!! VerifyKeyExchangeSignature - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyKeyExchangeSignature - PASS !!!\n"));

  return TRUE;
}

BOOLEAN
SpdmRequesterVerifyKeyExchangeHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
  IN     VOID                 *HmacData,
  IN     UINTN                HmacDataSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     CalcHmacData[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  UINT8                                     CertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER                      THCurr;

  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  HashSize = GetSpdmHashSize (SpdmContext);
  ASSERT(HashSize == HmacDataSize);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize == 0) {
    return FALSE;
  }
  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  ASSERT(SessionInfo->HashSize != 0);
  SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->HandshakeSecret.ResponseHandshakeSecret, SessionInfo->HashSize, CalcHmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (CalcHmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (CompareMem (CalcHmacData, HmacData, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyKeyExchangeHmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyKeyExchangeHmac - PASS !!!\n"));

  return TRUE;
}

/**
  This function sends KEY_EXCHANGE and receives KEY_EXCHANGE_RSP for SPDM key exchange.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MeasurementHashType          MeasurementHashType to the KEY_EXCHANGE request.
  @param  SlotNum                      SlotNum to the KEY_EXCHANGE request.
  @param  HeartbeatPeriod              HeartbeatPeriod from the KEY_EXCHANGE_RSP response.
  @param  SessionId                    SessionId from the KEY_EXCHANGE_RSP response.
  @param  SlotIdParam                  SlotIdParam from the KEY_EXCHANGE_RSP response.
  @param  MeasurementHash              MeasurementHash from the KEY_EXCHANGE_RSP response.

  @retval RETURN_SUCCESS               The KEY_EXCHANGE is sent and the KEY_EXCHANGE_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmSendReceiveKeyExchange (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT32               *SessionId,
     OUT UINT8                *SlotIdParam,
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
  UINT32                                    HashSize;
  UINT32                                    SignatureSize;
  UINT32                                    HmacSize;
  UINT8                                     *Ptr;
  VOID                                      *MeasurementSummaryHash;
  UINT16                                    OpaqueLength;
  UINT8                                     *Signature;
  UINT8                                     *VerifyData;
  VOID                                      *DHEContext;
  UINT8                                     FinalKey[MAX_DHE_KEY_SIZE];
  UINTN                                     FinalKeySize;
  UINT16                                    ReqSessionId;
  UINT16                                    RspSessionId;
  SPDM_SESSION_INFO                         *SessionInfo;
  UINTN                                     OpaqueKeyExchangeReqSize;

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
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
  DheKeySize = GetSpdmDheKeySize (SpdmContext);
  DHEContext = SpdmDheNew (SpdmContext);
  SpdmDheGenerateKey (SpdmContext, DHEContext, Ptr, &DheKeySize);
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
    SpdmDheFree (SpdmContext, DHEContext);
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, NULL, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    SpdmDheFree (SpdmContext, DHEContext);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_KEY_EXCHANGE_RESPONSE)) {
    SpdmDheFree (SpdmContext, DHEContext);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    SpdmDheFree (SpdmContext, DHEContext);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_KEY_EXCHANGE_RSP) {
    SpdmDheFree (SpdmContext, DHEContext);
    return RETURN_DEVICE_ERROR;
  }

  if (HeartbeatPeriod != NULL) {
    *HeartbeatPeriod = SpdmResponse.Header.Param1;
  }
  *SlotIdParam = SpdmResponse.SlotIDParam;
  if (SpdmResponse.MutAuthRequested != 0) {
    if ((*SlotIdParam != 0xF) && (*SlotIdParam >= SpdmContext->LocalContext.SlotCount)) {
      SpdmDheFree (SpdmContext, DHEContext);
      return RETURN_DEVICE_ERROR;
    }
  } else {
    if (*SlotIdParam != 0) {
      SpdmDheFree (SpdmContext, DHEContext);
      return RETURN_DEVICE_ERROR;
    }
  }
  RspSessionId = SpdmResponse.RspSessionID;
  *SessionId = (ReqSessionId << 16) | RspSessionId;
  SessionInfo = SpdmAssignSessionId (SpdmContext, *SessionId);
  if (SessionInfo == NULL) {
    SpdmDheFree (SpdmContext, DHEContext);
    return RETURN_DEVICE_ERROR;
  }
  SessionInfo->UsePsk = FALSE;

  //
  // Cache session data
  //
  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageK, &SpdmRequest, SpdmRequestSize);

  SignatureSize = GetSpdmAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);
  HmacSize = GetSpdmHashSize (SpdmContext);

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) != 0) {
    HmacSize = 0;
  }

  if (SpdmResponseSize <  sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
                          DheKeySize +
                          HashSize +
                          sizeof(UINT16) +
                          SignatureSize +
                          HmacSize) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmDheFree (SpdmContext, DHEContext);
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
  DEBUG((DEBUG_INFO, "MeasurementSummaryHash (0x%x) - ", HashSize));
  InternalDumpData (MeasurementSummaryHash, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Ptr += HashSize;

  OpaqueLength = *(UINT16 *)Ptr;
  Ptr += sizeof(UINT16);
  if (SpdmResponseSize < sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
                         DheKeySize +
                         HashSize +
                         sizeof(UINT16) +
                         OpaqueLength +
                         SignatureSize +
                         HmacSize) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmDheFree (SpdmContext, DHEContext);
    return RETURN_DEVICE_ERROR;
  }
  Status = SpdmProcessOpaqueDataVersionSelectionData (SpdmContext, OpaqueLength, Ptr);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmDheFree (SpdmContext, DHEContext);
    return RETURN_UNSUPPORTED;
  }

  Ptr += OpaqueLength;

  SpdmResponseSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
                     DheKeySize +
                     HashSize +
                     sizeof(UINT16) +
                     OpaqueLength +
                     SignatureSize +
                     HmacSize;

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageK, &SpdmResponse, SpdmResponseSize - SignatureSize - HmacSize);

  Signature = Ptr;
  DEBUG((DEBUG_INFO, "Signature (0x%x):\n", SignatureSize));
  InternalDumpHex (Signature, SignatureSize);
  Ptr += SignatureSize;
  Result = SpdmRequesterVerifyKeyExchangeSignature (SpdmContext, SessionInfo, Signature, SignatureSize);
  if (!Result) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmDheFree (SpdmContext, DHEContext);
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageK, Signature, SignatureSize);

  //
  // Fill data to calc Secret for HMAC verification
  //
  FinalKeySize = sizeof(FinalKey);
  SpdmDheComputeKey (SpdmContext, DHEContext, SpdmResponse.ExchangeData, DheKeySize, FinalKey, &FinalKeySize);
  SpdmDheFree (SpdmContext, DHEContext);
  DEBUG((DEBUG_INFO, "FinalKey (0x%x):\n", FinalKeySize));
  InternalDumpHex (FinalKey, FinalKeySize);

  ASSERT (FinalKeySize <= sizeof(SessionInfo->HandshakeSecret.DheSecret));
  SessionInfo->DheKeySize = FinalKeySize;
  CopyMem (SessionInfo->HandshakeSecret.DheSecret, FinalKey, FinalKeySize);

  Status = SpdmGenerateSessionHandshakeKey (SpdmContext, *SessionId, TRUE);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, *SessionId);
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return Status;
  }

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
    VerifyData = Ptr;
    DEBUG((DEBUG_INFO, "VerifyData (0x%x):\n", HmacSize));
    InternalDumpHex (VerifyData, HmacSize);
    Result = SpdmRequesterVerifyKeyExchangeHmac (SpdmContext, SessionInfo, VerifyData, HmacSize);
    if (!Result) {
      SpdmFreeSessionId (SpdmContext, *SessionId);
      SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
      return RETURN_SECURITY_VIOLATION;
    }
    Ptr += HmacSize;

    AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageK, VerifyData, HmacSize);
  }

  if (MeasurementHash != NULL) {
    CopyMem (MeasurementHash, MeasurementSummaryHash, HashSize);
  }
  SessionInfo->MutAuthRequested = SpdmResponse.MutAuthRequested;

  SessionInfo->SessionState = SpdmStateHandshaking;
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;

  return RETURN_SUCCESS;
}

