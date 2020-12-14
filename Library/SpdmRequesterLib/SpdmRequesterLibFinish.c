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
  This function verifies the finish HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  HmacData                     The HMAC data buffer.
  @param  HmacDataSize                 Size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
BOOLEAN
SpdmRequesterVerifyFinishHmac (
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
  UINT8                                     *MutCertBuffer;
  UINTN                                     MutCertBufferSize;
  UINT8                                     MutCertBufferHash[MAX_HASH_SIZE];
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

  if (SessionInfo->MutAuthRequested) {
    if (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0) {
      return FALSE;
    }
    MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    MutCertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (SpdmContext, MutCertBuffer, MutCertBufferSize, MutCertBufferHash);
  }

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  if (SessionInfo->MutAuthRequested) {
    DEBUG((DEBUG_INFO, "THMessageCM Data :\n"));
    InternalDumpHex (MutCertBuffer, MutCertBufferSize);
  }

  DEBUG((DEBUG_INFO, "MessageF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  if (SessionInfo->MutAuthRequested) {
    AppendManagedBuffer (&THCurr, MutCertBufferHash, HashSize);
  }
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  ASSERT(SessionInfo->HashSize != 0);
  SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->HandshakeSecret.ResponseFinishedKey, SessionInfo->HashSize, CalcHmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (CalcHmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (CompareMem (CalcHmacData, HmacData, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyFinishRspHmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyFinishRspHmac - PASS !!!\n"));

  return TRUE;
}

/**
  This function generates the finish signature based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Signature                    The buffer to store the finish signature.

  @retval TRUE  finish signature is generated.
  @retval FALSE finish signature is not generated.
**/
BOOLEAN
SpdmRequesterGenerateFinishSignature (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN  SPDM_SESSION_INFO         *SessionInfo,
  OUT UINT8                     *Signature
  )
{
  UINT8                         HashData[MAX_HASH_SIZE];
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  UINT8                         CertBufferHash[MAX_HASH_SIZE];
  UINT8                         *MutCertBuffer;
  UINTN                         MutCertBufferSize;
  UINT8                         MutCertBufferHash[MAX_HASH_SIZE];
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT32                        HashSize;
  LARGE_MANAGED_BUFFER          THCurr;

  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  if (SpdmContext->LocalContext.SpdmRequesterDataSignFunc == NULL) {
    return FALSE;
  }
  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize == 0) {
    return FALSE;
  }
  if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
    return FALSE;
  }

  SignatureSize = GetSpdmReqAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  MutCertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (SpdmContext, MutCertBuffer, MutCertBufferSize, MutCertBufferHash);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  DEBUG((DEBUG_INFO, "THMessageCM Data :\n"));
  InternalDumpHex (MutCertBuffer, MutCertBufferSize);

  DEBUG((DEBUG_INFO, "MessageF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  AppendManagedBuffer (&THCurr, MutCertBufferHash, HashSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  SpdmHashAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
  DEBUG((DEBUG_INFO, "THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Result = SpdmContext->LocalContext.SpdmRequesterDataSignFunc (
             SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg,
             HashData,
             HashSize,
             Signature,
             &SignatureSize
             );

  return Result;
}

/**
  This function generates the finish HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
BOOLEAN
SpdmRequesterGenerateFinishHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
  OUT    VOID                 *Hmac
  )
{
  UINTN                                     HashSize;
  UINT8                                     CalcHmacData[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  UINT8                                     CertBufferHash[MAX_HASH_SIZE];
  UINT8                                     *MutCertBuffer;
  UINTN                                     MutCertBufferSize;
  UINT8                                     MutCertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER                      THCurr;

  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  HashSize = GetSpdmHashSize (SpdmContext);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize == 0) {
    return FALSE;
  }
  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  if (SessionInfo->MutAuthRequested) {
    if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
      return FALSE;
    }
    MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    MutCertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (SpdmContext, MutCertBuffer, MutCertBufferSize, MutCertBufferHash);
  }

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  if (SessionInfo->MutAuthRequested) {
    DEBUG((DEBUG_INFO, "THMessageMyCM Data :\n"));
    InternalDumpHex (MutCertBuffer, MutCertBufferSize);
  }

  DEBUG((DEBUG_INFO, "MessageF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  if (SessionInfo->MutAuthRequested) {
    AppendManagedBuffer (&THCurr, MutCertBufferHash, HashSize);
  }
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  ASSERT(SessionInfo->HashSize != 0);
  SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->HandshakeSecret.RequestFinishedKey, SessionInfo->HashSize, CalcHmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (CalcHmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  CopyMem (Hmac, CalcHmacData, HashSize);

  return TRUE;
}

/**
  This function sends FINISH and receives FINISH_RSP for SPDM finish.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    SessionId to the FINISH request.
  @param  SlotIdParam                  SlotIdParam to the FINISH request.

  @retval RETURN_SUCCESS               The FINISH is sent and the FINISH_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmSendReceiveFinish (
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

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  if (SessionInfo->MutAuthRequested != 0) {
    if ((SlotIdParam >= SpdmContext->LocalContext.SlotCount) && (SlotIdParam != 0xF)) {
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
    SignatureSize = GetSpdmReqAsymSize (SpdmContext);
  } else {
    SpdmRequest.Header.Param1 = 0;
    SpdmRequest.Header.Param2 = 0;
    SignatureSize = 0;
  }
  
  if (SlotIdParam == 0xF) {
    SlotIdParam = SpdmContext->LocalContext.ProvisionedSlotNum;
  }

  if (SessionInfo->MutAuthRequested) {
    SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = SpdmContext->LocalContext.CertificateChain[SlotIdParam];
    SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = SpdmContext->LocalContext.CertificateChainSize[SlotIdParam];
  }

  HmacSize = GetSpdmHashSize (SpdmContext);
  SpdmRequestSize = sizeof(SPDM_FINISH_REQUEST) + SignatureSize + HmacSize;
  Ptr = SpdmRequest.Signature;
  
  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, (UINT8 *)&SpdmRequest, sizeof(SPDM_FINISH_REQUEST));
  if (SessionInfo->MutAuthRequested) {
    Result = SpdmRequesterGenerateFinishSignature (SpdmContext, SessionInfo, Ptr);
    if (!Result) {
      return RETURN_SECURITY_VIOLATION;
    }
    AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, Ptr, SignatureSize);
    Ptr += SignatureSize;
  }

  Result = SpdmRequesterGenerateFinishHmac (SpdmContext, SessionInfo, Ptr);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, Ptr, HmacSize);
  
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

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
    HmacSize = 0;
  }

  if (SpdmResponseSize != sizeof(SPDM_FINISH_RESPONSE) + HmacSize) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_FINISH_RSP) {
    return RETURN_DEVICE_ERROR;
  }

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, &SpdmResponse, sizeof(SPDM_FINISH_RESPONSE));

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) != 0) {
    DEBUG((DEBUG_INFO, "VerifyData (0x%x):\n", HmacSize));
    InternalDumpHex (SpdmResponse.VerifyData, HmacSize);
    Result = SpdmRequesterVerifyFinishHmac (SpdmContext, SessionInfo, SpdmResponse.VerifyData, HmacSize);
    if (!Result) {
      return RETURN_SECURITY_VIOLATION;
    }

    AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, (UINT8 *)&SpdmResponse + sizeof(SPDM_FINISH_RESPONSE), HmacSize);
  }

  Status = SpdmGenerateSessionDataKey (SpdmContext, SessionId, TRUE);
  if (RETURN_ERROR(Status)) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return Status;
  }

  SessionInfo->SessionState = SpdmStateEstablished;
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  
  return RETURN_SUCCESS;
}

