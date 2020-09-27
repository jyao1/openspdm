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

#pragma pack()

BOOLEAN
SpdmRequesterGenerateFinishSignature (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN  SPDM_SESSION_INFO         *SessionInfo,
  IN  UINT8                     SlotNum,
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

  if (SpdmContext->LocalContext.SpdmDataSignFunc == NULL) {
    return FALSE;
  }
  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize == 0) {
    return FALSE;
  }
  if ((SpdmContext->LocalContext.CertificateChain[SlotNum] == NULL) || (SpdmContext->LocalContext.CertificateChainSize[SlotNum] == 0)) {
    return FALSE;
  }

  SignatureSize = GetSpdmReqAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  HashFunc (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  MutCertBuffer = (UINT8 *)SpdmContext->LocalContext.CertificateChain[SlotNum] + sizeof(SPDM_CERT_CHAIN) + HashSize;
  MutCertBufferSize = SpdmContext->LocalContext.CertificateChainSize[SlotNum] - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  HashFunc (SpdmContext, MutCertBuffer, MutCertBufferSize, MutCertBufferHash);

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

  HashFunc (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
  DEBUG((DEBUG_INFO, "THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Result = SpdmContext->LocalContext.SpdmDataSignFunc (
             SpdmContext,
             FALSE,
             SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg,
             HashData,
             HashSize,
             Signature,
             &SignatureSize
             );

  return Result;
}

BOOLEAN
SpdmRequesterGenerateFinishHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
  IN     UINT8                SlotNum,
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
  HashFunc (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  if (SessionInfo->MutAuthRequested) {
    if ((SpdmContext->LocalContext.CertificateChain[SlotNum] == NULL) || (SpdmContext->LocalContext.CertificateChainSize[SlotNum] == 0)) {
      return FALSE;
    }
    MutCertBuffer = (UINT8 *)SpdmContext->LocalContext.CertificateChain[SlotNum] + sizeof(SPDM_CERT_CHAIN) + HashSize;
    MutCertBufferSize = SpdmContext->LocalContext.CertificateChainSize[SlotNum] - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    HashFunc (SpdmContext, MutCertBuffer, MutCertBufferSize, MutCertBufferHash);
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
  HmacFunc (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->HandshakeSecret.RequestHandshakeSecret, SessionInfo->HashSize, CalcHmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (CalcHmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  CopyMem (Hmac, CalcHmacData, HashSize);

  return TRUE;
}

/**
  This function executes SPDM finish.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceiveFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                SlotNum
  )
{
  RETURN_STATUS                             Status;
  SPDM_FINISH_REQUEST_MINE                  SpdmRequest;
  UINTN                                     SpdmRequestSize;
  UINTN                                     SignatureSize;
  UINTN                                     HmacSize;
  SPDM_FINISH_RESPONSE                      SpdmResponse;
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

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;
   
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_FINISH;
  if (SessionInfo->MutAuthRequested) {
    SpdmRequest.Header.Param1 = SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED;
    SignatureSize = GetSpdmReqAsymSize (SpdmContext);
  } else {
    SpdmRequest.Header.Param1 = 0;
    SignatureSize = 0;
  }
  SpdmRequest.Header.Param2 = SlotNum;
  
  HmacSize = GetSpdmHashSize (SpdmContext);
  SpdmRequestSize = sizeof(SPDM_FINISH_REQUEST) + SignatureSize + HmacSize;
  Ptr = SpdmRequest.Signature;
  
  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, (UINT8 *)&SpdmRequest, sizeof(SPDM_FINISH_REQUEST));
  if (SessionInfo->MutAuthRequested) {
    Result = SpdmRequesterGenerateFinishSignature (SpdmContext, SessionInfo, SlotNum, Ptr);
    if (!Result) {
      return RETURN_SECURITY_VIOLATION;
    }
    AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, Ptr, SignatureSize);
    Ptr += SignatureSize;
  }

  Result = SpdmRequesterGenerateFinishHmac (SpdmContext, SessionInfo, SlotNum, Ptr);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }
  
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
  if (SpdmResponseSize != sizeof(SPDM_FINISH_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_FINISH_RSP) {
    return RETURN_DEVICE_ERROR;
  }

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, &SpdmResponse, SpdmResponseSize);
  
  Status = SpdmGenerateSessionDataKey (SpdmContext, SessionId, TRUE);
  if (RETURN_ERROR(Status)) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return Status;
  }

  SessionInfo->SessionState = SpdmStateEstablished;
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  
  return RETURN_SUCCESS;
}

