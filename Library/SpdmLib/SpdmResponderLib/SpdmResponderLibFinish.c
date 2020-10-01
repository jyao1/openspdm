/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

BOOLEAN
SpdmResponderVerifyFinishSignature (
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
  UINT8                                     *MutCertBuffer;
  UINTN                                     MutCertBufferSize;
  UINT8                                     *MutCertChainBuffer;
  UINTN                                     MutCertChainBufferSize;
  UINT8                                     MutCertBufferHash[MAX_HASH_SIZE];
  VOID                                      *Context;
  LARGE_MANAGED_BUFFER                      THCurr;

  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  HashSize = GetSpdmHashSize (SpdmContext);

  if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
    return FALSE;
  }
  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize == 0) {
    return FALSE;
  }
  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  MutCertChainBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  MutCertChainBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  SpdmHashAll (SpdmContext, MutCertChainBuffer, MutCertChainBufferSize, MutCertBufferHash);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  DEBUG((DEBUG_INFO, "THMessageCM Data :\n"));
  InternalDumpHex (MutCertChainBuffer, MutCertChainBufferSize);

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

  //
  // Get leaf cert from cert chain
  //
  Result = X509GetCertFromCertChain (MutCertChainBuffer, MutCertChainBufferSize, -1,  &MutCertBuffer, &MutCertBufferSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmReqAsymGetPublicKeyFromX509 (SpdmContext, MutCertBuffer, MutCertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmReqAsymVerify (
             SpdmContext,
             Context,
             HashData,
             HashSize,
             SignData,
             SignDataSize
             );
  SpdmReqAsymFree (SpdmContext, Context);
  if (!Result) {
    DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature - PASS !!!\n"));

  return TRUE;
}

BOOLEAN
SpdmVerifyFinishHmac (
  IN  SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN  SPDM_SESSION_INFO    *SessionInfo,
  OUT UINT8                *Hmac
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  UINT8                         CertBufferHash[MAX_HASH_SIZE];
  UINT8                         *MutCertBuffer;
  UINTN                         MutCertBufferSize;
  UINT8                         MutCertBufferHash[MAX_HASH_SIZE];
  UINTN                         HashSize;
  LARGE_MANAGED_BUFFER          THCurr;

  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  HashSize = GetSpdmHashSize (SpdmContext);

  if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
    return FALSE;
  }
  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  if (SessionInfo->MutAuthRequested) {
    if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize == 0) {
      return FALSE;
    }
    MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    MutCertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (SpdmContext, MutCertBuffer, MutCertBufferSize, MutCertBufferHash);
  }

  DEBUG((DEBUG_INFO, "Calc MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "Calc THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "Calc MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  if (SessionInfo->MutAuthRequested) {
    DEBUG((DEBUG_INFO, "THMessageMyCM Data :\n"));
    InternalDumpHex (MutCertBuffer, MutCertBufferSize);
  }

  DEBUG((DEBUG_INFO, "Calc MessageF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  if (SessionInfo->MutAuthRequested) {
    AppendManagedBuffer (&THCurr, MutCertBufferHash, HashSize);
  }
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  ASSERT(SessionInfo->HashSize != 0);
  SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->HandshakeSecret.RequestFinishedKey, SessionInfo->HashSize, HmacData);
  DEBUG((DEBUG_INFO, "Calc THCurr Hmac - "));
  InternalDumpData (HmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (CompareMem(Hmac, HmacData, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyFinishHmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyFinishHmac - PASS !!!\n"));
  return TRUE;
}

BOOLEAN
SpdmResponderGenerateFinishHmac (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN  SPDM_SESSION_INFO         *SessionInfo,
  OUT UINT8                     *Hmac
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  UINT8                         CertBufferHash[MAX_HASH_SIZE];
  UINT8                         *MutCertBuffer;
  UINTN                         MutCertBufferSize;
  UINT8                         MutCertBufferHash[MAX_HASH_SIZE];
  UINT32                        HashSize;
  LARGE_MANAGED_BUFFER          THCurr;

  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext);

  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  if (SessionInfo->MutAuthRequested) {
    if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize == 0) {
      return FALSE;
    }
    MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    MutCertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (SpdmContext, MutCertBuffer, MutCertBufferSize, MutCertBufferHash);
  }

  DEBUG((DEBUG_INFO, "Calc MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "Calc THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "Calc MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  if (SessionInfo->MutAuthRequested) {
    DEBUG((DEBUG_INFO, "THMessageMyCM Data :\n"));
    InternalDumpHex (MutCertBuffer, MutCertBufferSize);
  }

  DEBUG((DEBUG_INFO, "Calc MessageF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  if (SessionInfo->MutAuthRequested) {
    AppendManagedBuffer (&THCurr, MutCertBufferHash, HashSize);
  }
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  ASSERT(SessionInfo->HashSize != 0);
  SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->HandshakeSecret.ResponseFinishedKey, SessionInfo->HashSize, HmacData);
  DEBUG((DEBUG_INFO, "Calc THCurr Hmac - "));
  InternalDumpData (HmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  CopyMem (Hmac, HmacData, HashSize);

  return TRUE;
}

RETURN_STATUS
EFIAPI
SpdmGetResponseFinish (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  BOOLEAN                  Result;
  UINT32                   HmacSize;
  UINT32                   SignatureSize;
  UINT8                    SlotNum;
  SPDM_FINISH_REQUEST      *SpdmRequest;
  SPDM_FINISH_RESPONSE     *SpdmResponse;
  SPDM_DEVICE_CONTEXT      *SpdmContext;
  SPDM_SESSION_INFO        *SessionInfo;

  SpdmContext = Context;
  SpdmRequest = Request;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (((SessionInfo->MutAuthRequested == 0) && (SpdmRequest->Header.Param1 != 0)) ||
      ((SessionInfo->MutAuthRequested != 0) && (SpdmRequest->Header.Param1 == 0)) ) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  HmacSize = GetSpdmHashSize (SpdmContext);
  if (SessionInfo->MutAuthRequested) {
    SignatureSize = GetSpdmReqAsymSize (SpdmContext);
  } else {
    SignatureSize = 0;
  }

  if (RequestSize != sizeof(SPDM_FINISH_REQUEST) + SignatureSize + HmacSize) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SlotNum = SpdmRequest->Header.Param2;
  if ((SlotNum != 0xFF) && (SlotNum >= SpdmContext->LocalContext.SlotCount)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SlotNum == 0xFF) {
    SlotNum = SpdmContext->EncapContext.SlotNum;
  }
  if (SlotNum != SpdmContext->EncapContext.SlotNum) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, Request, sizeof(SPDM_FINISH_REQUEST));
  if (SessionInfo->MutAuthRequested) {
    Result = SpdmResponderVerifyFinishSignature (SpdmContext, SessionInfo, (UINT8 *)Request + sizeof(SPDM_FINISH_REQUEST), SignatureSize);
    if (!Result) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, (UINT8 *)Request + sizeof(SPDM_FINISH_REQUEST), SignatureSize);
  }

  Result = SpdmVerifyFinishHmac (SpdmContext, SessionInfo, (UINT8 *)Request + SignatureSize + sizeof(SPDM_FINISH_REQUEST));
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, (UINT8 *)Request + SignatureSize + sizeof(SPDM_FINISH_REQUEST), HmacSize);

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
    HmacSize = 0;
  }

  ASSERT (*ResponseSize >= sizeof(SPDM_FINISH_RESPONSE) + HmacSize);
  *ResponseSize = sizeof(SPDM_FINISH_RESPONSE) + HmacSize;
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_FINISH_RSP;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, SpdmResponse, sizeof(SPDM_FINISH_RESPONSE));

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) != 0) {
    Result = SpdmResponderGenerateFinishHmac (SpdmContext, SessionInfo, (UINT8 *)SpdmResponse + sizeof(SPDM_FINISH_REQUEST));
    if (!Result) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_FINISH_RSP, ResponseSize, Response);
      return RETURN_SUCCESS;
    }

    AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, (UINT8 *)SpdmResponse + sizeof(SPDM_FINISH_REQUEST), HmacSize);
  }

  SpdmGenerateSessionDataKey (SpdmContext, SessionId, FALSE);

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmGetResponseFinishInClear (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_DEVICE_CONTEXT          *SpdmContext;

  SpdmContext = Context;
  return SpdmGetResponseFinish (
           Context,
           SpdmContext->LatestSessionId,
           RequestSize,
           Request,
           ResponseSize,
           Response
           );
}