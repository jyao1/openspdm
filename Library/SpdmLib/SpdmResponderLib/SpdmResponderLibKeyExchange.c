/** @file
  EDKII SpdmIo Stub

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

BOOLEAN
CalculateMeasurementSummaryHash (
  IN  SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN  UINT8                MeasurementSummaryHashType,
  OUT UINT8                *MeasurementSummaryHash
  );

BOOLEAN
SpdmGenerateKeyExchangeSignature (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN  UINT8                     SlotNum,
  OUT UINT8                     *Signature
  )
{
  VOID                          *RsaContext;
  UINT8                         HashData[MAX_HASH_SIZE];
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT32                        HashSize;
  HASH_ALL                      HashFunc;
  LARGE_MANAGED_BUFFER          THCurr = {MAX_SPDM_MESSAGE_BUFFER_SIZE};

  if (SpdmContext->LocalContext.PrivatePem == NULL) {
    return FALSE;
  }

  SignatureSize = GetSpdmAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);
  HashFunc = GetSpdmHashFunc (SpdmContext);

  Result = RsaGetPrivateKeyFromPem (SpdmContext->LocalContext.PrivatePem, SpdmContext->LocalContext.PrivatePemSize, NULL, &RsaContext);
  if (!Result) {
    return FALSE;
  }

  if ((SpdmContext->LocalContext.CertificateChain[SlotNum] == NULL) || (SpdmContext->LocalContext.CertificateChainSize[SlotNum] == 0)) {
    return FALSE;
  }
  CertBuffer = (UINT8 *)SpdmContext->LocalContext.CertificateChain[SlotNum] + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->LocalContext.CertificateChainSize[SlotNum] - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  DEBUG((DEBUG_INFO, "Calc MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "Calc THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "Calc MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBuffer, CertBufferSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK));

  HashFunc (GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
  DEBUG((DEBUG_INFO, "Calc THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Result = RsaPkcs1Sign (
             RsaContext,
             HashData,
             HashSize,
             Signature,
             &SignatureSize
             );
  RsaFree (RsaContext);

  return Result;
}

BOOLEAN
SpdmGenerateKeyExchangeHmac (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN  UINT8                     SessionId,
  IN  UINT8                     SlotNum,
  OUT UINT8                     *Hmac
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  HMAC_ALL                      HmacFunc;
  UINT32                        HashSize;
  LARGE_MANAGED_BUFFER          THCurr = {MAX_SPDM_MESSAGE_BUFFER_SIZE};
  SPDM_SESSION_INFO             *SessionInfo;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return FALSE;
  }

  if ((SpdmContext->LocalContext.CertificateChain[SlotNum] == NULL) || (SpdmContext->LocalContext.CertificateChainSize[SlotNum] == 0)) {
    return FALSE;
  }
  
  HmacFunc = GetSpdmHmacFunc (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  CertBuffer = (UINT8 *)SpdmContext->LocalContext.CertificateChain[SlotNum] + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->LocalContext.CertificateChainSize[SlotNum] - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  DEBUG((DEBUG_INFO, "Calc MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "Calc THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "Calc MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBuffer, CertBufferSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK));

  ASSERT(SessionInfo->HashSize != 0);
  HmacFunc (GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->ResponseHandshakeSecret, SessionInfo->HashSize, HmacData);
  DEBUG((DEBUG_INFO, "Calc THCurr Hmac - "));
  InternalDumpData (HmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  CopyMem (Hmac, HmacData, HashSize);

  return TRUE;
}

RETURN_STATUS
EFIAPI
SpdmGetResponseKeyExchange (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_KEY_EXCHANGE_REQUEST     *SpdmRequest;
  SPDM_KEY_EXCHANGE_RESPONSE    *SpdmResponse;
  UINT32                        DHEKeySize;
  UINT32                        HashSize;
  UINT32                        SignatureSize;
  UINT32                        HmacSize;
  UINT8                         *Ptr;
  BOOLEAN                       Result;
  UINT8                         SlotNum;
  UINT8                         SessionId;
  VOID                          *DHEContext;
  UINT8                         FinalKey[MAX_DHE_KEY_SIZE];
  UINTN                         FinalKeySize;
  SPDM_SESSION_INFO             *SessionInfo;
  UINTN                         TotalSize;
  SPDM_DEVICE_CONTEXT           *SpdmContext;

  SpdmContext = Context;

  SpdmRequest = Request;
  SlotNum = SpdmRequest->Header.Param2;

  if (SlotNum > SpdmContext->LocalContext.SlotCount) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (SpdmRequest->DHE_Named_Group != SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SignatureSize = GetSpdmAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);
  HmacSize = GetSpdmHashSize (SpdmContext);
  DHEKeySize = GetSpdmDHEKeySize (SpdmContext);

  TotalSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
              DHEKeySize +
              HashSize +
              SignatureSize +
              HmacSize;

  ASSERT (*ResponseSize >= TotalSize);
  *ResponseSize = TotalSize;
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_KEY_EXCHANGE_RSP;
  SpdmResponse->Header.Param1 = 0;

  SessionInfo = SpdmAllocateSessionId (SpdmContext, &SessionId);
  SessionInfo->UsePsk = FALSE;
  SpdmResponse->Header.Param2 = SessionId;

  SpdmResponse->Length = (UINT16)*ResponseSize;
  SpdmResponse->Mut_Auth_Requested = 0;

  GetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmResponse->RandomData);
  
  Ptr = (VOID *)(SpdmResponse + 1);
  GenerateDHESelfKey (SpdmContext, DHEKeySize, Ptr, &DHEContext);
  DEBUG((DEBUG_INFO, "Calc SelfKey (0x%x):\n", DHEKeySize));
  InternalDumpHex (Ptr, DHEKeySize);

  DEBUG((DEBUG_INFO, "Calc PeerKey (0x%x):\n", DHEKeySize));
  InternalDumpHex ((UINT8 *)Request + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DHEKeySize);

  FinalKeySize = sizeof(FinalKey);
  ComputeDHEFinalKey (SpdmContext, DHEContext, DHEKeySize, (UINT8 *)Request + sizeof(SPDM_KEY_EXCHANGE_REQUEST), &FinalKeySize, FinalKey);
  DEBUG((DEBUG_INFO, "Calc FinalKey (0x%x):\n", FinalKeySize));
  InternalDumpHex (FinalKey, FinalKeySize);

  ASSERT (FinalKeySize <= sizeof(SessionInfo->DheSecret));
  SessionInfo->DheKeySize = FinalKeySize;
  CopyMem (SessionInfo->DheSecret, FinalKey, FinalKeySize);

  Ptr += DHEKeySize;

  Result = CalculateMeasurementSummaryHash (SpdmContext, SpdmRequest->Header.Param1, Ptr);
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += HashSize;

  AppendManagedBuffer (&SpdmContext->Transcript.MessageK, SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
  Result = SpdmGenerateKeyExchangeSignature (SpdmContext, SlotNum, Ptr);
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_KEY_EXCHANGE_RSP, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  AppendManagedBuffer (&SpdmContext->Transcript.MessageK, Ptr, SignatureSize);
  SpdmGenerateSessionHandshakeKey (SpdmContext, SessionId);
  Ptr += SignatureSize;
  
  Result = SpdmGenerateKeyExchangeHmac (SpdmContext, SessionId, SlotNum, Ptr);
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_KEY_EXCHANGE_RSP, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += HmacSize;

  SessionInfo->SessionState = EdkiiSpdmStateHandshaking;

  return RETURN_SUCCESS;
}

