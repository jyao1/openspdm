/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

/*
  This function calculates current TH data with Message A and Message K.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The SPDM session ID.
  @param  CertChainData                Certitiface chain data without SPDM_CERT_CHAIN header.
  @param  CertChainDataSize            Size in bytes of the certitiface chain data.
  @param  THDataBufferSize             Size in bytes of the THDataBuffer
  @param  THDataBuffer                 The buffer to store the THDataBuffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
BOOLEAN
EFIAPI
SpdmCalculateTHForExchange (
  IN     VOID                      *Context,
  IN     VOID                      *SpdmSessionInfo,
  IN     UINT8                     *CertChainData, OPTIONAL
  IN     UINTN                     CertChainDataSize, OPTIONAL
  IN OUT UINTN                     *THDataBufferSize,
     OUT VOID                      *THDataBuffer
  )
{
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  SPDM_SESSION_INFO             *SessionInfo;
  UINT8                         CertChainDataHash[MAX_HASH_SIZE];
  UINT32                        HashSize;
  RETURN_STATUS                 Status;
  LARGE_MANAGED_BUFFER          THCurr;

  SpdmContext = Context;
  SessionInfo = SpdmSessionInfo;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  ASSERT (*THDataBufferSize >= MAX_SPDM_MESSAGE_BUFFER_SIZE);
  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  Status = AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  if (CertChainData != NULL) {
    DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
    InternalDumpHex (CertChainData, CertChainDataSize);
    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, CertChainData, CertChainDataSize, CertChainDataHash);
    Status = AppendManagedBuffer (&THCurr, CertChainDataHash, HashSize);
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  Status = AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  *THDataBufferSize = GetManagedBufferSize(&THCurr);
  CopyMem (THDataBuffer, GetManagedBuffer(&THCurr), *THDataBufferSize);

  return TRUE;
}

/*
  This function calculates current TH data with Message A, Message K and Message F.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The SPDM session ID.
  @param  CertChainData                Certitiface chain data without SPDM_CERT_CHAIN header.
  @param  CertChainDataSize            Size in bytes of the certitiface chain data.
  @param  MutCertChainData             Certitiface chain data without SPDM_CERT_CHAIN header in mutual authentication.
  @param  MutCertChainDataSize         Size in bytes of the certitiface chain data in mutual authentication.
  @param  THDataBufferSize             Size in bytes of the THDataBuffer
  @param  THDataBuffer                 The buffer to store the THDataBuffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
BOOLEAN
EFIAPI
SpdmCalculateTHForFinish (
  IN     VOID                      *Context,
  IN     VOID                      *SpdmSessionInfo,
  IN     UINT8                     *CertChainData, OPTIONAL
  IN     UINTN                     CertChainDataSize, OPTIONAL
  IN     UINT8                     *MutCertChainData, OPTIONAL
  IN     UINTN                     MutCertChainDataSize, OPTIONAL
  IN OUT UINTN                     *THDataBufferSize,
     OUT VOID                      *THDataBuffer
  )
{
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  SPDM_SESSION_INFO             *SessionInfo;
  UINT8                         CertChainDataHash[MAX_HASH_SIZE];
  UINT8                         MutCertChainDataHash[MAX_HASH_SIZE];
  UINT32                        HashSize;
  RETURN_STATUS                 Status;
  LARGE_MANAGED_BUFFER          THCurr;

  SpdmContext = Context;
  SessionInfo = SpdmSessionInfo;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  ASSERT (*THDataBufferSize >= MAX_SPDM_MESSAGE_BUFFER_SIZE);
  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  Status = AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  if (CertChainData != NULL) {
    DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
    InternalDumpHex (CertChainData, CertChainDataSize);
    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, CertChainData, CertChainDataSize, CertChainDataHash);
    Status = AppendManagedBuffer (&THCurr, CertChainDataHash, HashSize);
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  Status = AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  if (MutCertChainData != NULL) {
    DEBUG((DEBUG_INFO, "THMessageCM Data :\n"));
    InternalDumpHex (MutCertChainData, MutCertChainDataSize);
    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, MutCertChainData, MutCertChainDataSize, MutCertChainDataHash);
    Status = AppendManagedBuffer (&THCurr, MutCertChainDataHash, HashSize);
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "MessageF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));
  Status = AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  *THDataBufferSize = GetManagedBufferSize(&THCurr);
  CopyMem (THDataBuffer, GetManagedBuffer(&THCurr), *THDataBufferSize);

  return TRUE;
}

/**
  This function generates the key exchange signature based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Signature                    The buffer to store the key exchange signature.

  @retval TRUE  key exchange signature is generated.
  @retval FALSE key exchange signature is not generated.
**/
BOOLEAN
SpdmGenerateKeyExchangeRspSignature (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
     OUT UINT8                     *Signature
  )
{
  UINT8                         HashData[MAX_HASH_SIZE];
  UINT8                         *CertChainData;
  UINTN                         CertChainDataSize;
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT32                        HashSize;
  UINT8                         THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                         THCurrDataSize;

  SignatureSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForExchange (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  // debug only
  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, THCurrData, THCurrDataSize, HashData);
  DEBUG((DEBUG_INFO, "THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Result = SpdmResponderDataSignFunc (
             SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
             SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
             THCurrData,
             THCurrDataSize,
             Signature,
             &SignatureSize
             );
  if (Result) {
    DEBUG((DEBUG_INFO, "Signature - "));
    InternalDumpData (Signature, SignatureSize);
    DEBUG((DEBUG_INFO, "\n"));
  }
  return Result;
}

/**
  This function generates the key exchange HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Hmac                         The buffer to store the key exchange HMAC.

  @retval TRUE  key exchange HMAC is generated.
  @retval FALSE key exchange HMAC is not generated.
**/
BOOLEAN
SpdmGenerateKeyExchangeRspHmac (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
     OUT UINT8                     *Hmac
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  UINT8                         *CertChainData;
  UINTN                         CertChainDataSize;
  UINT32                        HashSize;
  UINT8                         THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                         THCurrDataSize;
  BOOLEAN                       Result;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForExchange (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, THCurrData, THCurrDataSize, HmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (HmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  CopyMem (Hmac, HmacData, HashSize);

  return TRUE;
}

/**
  This function verifies the key exchange signature based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  SignData                     The signature data buffer.
  @param  SignDataSize                 Size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
BOOLEAN
SpdmVerifyKeyExchangeRspSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN SPDM_SESSION_INFO            *SessionInfo,
  IN VOID                         *SignData,
  IN INTN                         SignDataSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     HashData[MAX_HASH_SIZE];
  BOOLEAN                                   Result;
  UINT8                                     *CertChainData;
  UINTN                                     CertChainDataSize;
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  VOID                                      *Context;
  UINT8                                     THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                     THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForExchange (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  // debug only
  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, THCurrData, THCurrDataSize, HashData);
  DEBUG((DEBUG_INFO, "THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  DEBUG((DEBUG_INFO, "Signature - "));
  InternalDumpData (SignData, SignDataSize);
  DEBUG((DEBUG_INFO, "\n"));

  //
  // Get leaf cert from cert chain
  //
  Result = X509GetCertFromCertChain (CertChainData, CertChainDataSize, -1,  &CertBuffer, &CertBufferSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymGetPublicKeyFromX509 (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo, CertBuffer, CertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymVerify (
             SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
             SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
             Context,
             THCurrData,
             THCurrDataSize,
             SignData,
             SignDataSize
             );
  SpdmAsymFree (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo, Context);
  if (!Result) {
    DEBUG((DEBUG_INFO, "!!! VerifyKeyExchangeSignature - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyKeyExchangeSignature - PASS !!!\n"));

  return TRUE;
}

/**
  This function verifies the key exchange HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  HmacData                     The HMAC data buffer.
  @param  HmacDataSize                 Size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
BOOLEAN
SpdmVerifyKeyExchangeRspHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
  IN     VOID                 *HmacData,
  IN     UINTN                HmacDataSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     CalcHmacData[MAX_HASH_SIZE];
  UINT8                                     *CertChainData;
  UINTN                                     CertChainDataSize;
  BOOLEAN                                   Result;
  UINT8                                     THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                     THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  ASSERT(HashSize == HmacDataSize);

  Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForExchange (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, THCurrData, THCurrDataSize, CalcHmacData);
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
  This function generates the finish signature based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Signature                    The buffer to store the finish signature.

  @retval TRUE  finish signature is generated.
  @retval FALSE finish signature is not generated.
**/
BOOLEAN
SpdmGenerateFinishReqSignature (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
     OUT UINT8                     *Signature
  )
{
  UINT8                         HashData[MAX_HASH_SIZE];
  UINT8                         *CertChainData;
  UINTN                         CertChainDataSize;
  UINT8                         *MutCertChainData;
  UINTN                         MutCertChainDataSize;
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT32                        HashSize;
  UINT8                         THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                         THCurrDataSize;

  SignatureSize = GetSpdmReqAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg);
  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&MutCertChainData, &MutCertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForFinish (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, MutCertChainData, MutCertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  // debug only
  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, THCurrData, THCurrDataSize, HashData);
  DEBUG((DEBUG_INFO, "THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Result = SpdmRequesterDataSignFunc (
             SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg,
             SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
             THCurrData,
             THCurrDataSize,
             Signature,
             &SignatureSize
             );
  if (Result) {
    DEBUG((DEBUG_INFO, "Signature - "));
    InternalDumpData (Signature, SignatureSize);
    DEBUG((DEBUG_INFO, "\n"));
  }

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
SpdmGenerateFinishReqHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
     OUT VOID                 *Hmac
  )
{
  UINTN                                     HashSize;
  UINT8                                     CalcHmacData[MAX_HASH_SIZE];
  UINT8                                     *CertChainData;
  UINTN                                     CertChainDataSize;
  UINT8                                     *MutCertChainData;
  UINTN                                     MutCertChainDataSize;
  BOOLEAN                                   Result;
  UINT8                                     THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                     THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  if (SessionInfo->MutAuthRequested) {
    Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&MutCertChainData, &MutCertChainDataSize);
    if (!Result) {
      return FALSE;
    }
  } else {
    MutCertChainData = NULL;
    MutCertChainDataSize = 0;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForFinish (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, MutCertChainData, MutCertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithRequestFinishedKey (SessionInfo->SecuredMessageContext, THCurrData, THCurrDataSize, CalcHmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (CalcHmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  CopyMem (Hmac, CalcHmacData, HashSize);

  return TRUE;
}

/**
  This function verifies the finish signature based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  SignData                     The signature data buffer.
  @param  SignDataSize                 Size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
BOOLEAN
SpdmVerifyFinishReqSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN SPDM_SESSION_INFO            *SessionInfo,
  IN VOID                         *SignData,
  IN INTN                         SignDataSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     HashData[MAX_HASH_SIZE];
  BOOLEAN                                   Result;
  UINT8                                     *CertChainData;
  UINTN                                     CertChainDataSize;
  UINT8                                     *MutCertChainData;
  UINTN                                     MutCertChainDataSize;
  UINT8                                     *MutCertBuffer;
  UINTN                                     MutCertBufferSize;
  VOID                                      *Context;
  UINT8                                     THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                     THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&MutCertChainData, &MutCertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForFinish (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, MutCertChainData, MutCertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  // debug only
  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, THCurrData, THCurrDataSize, HashData);
  DEBUG((DEBUG_INFO, "THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  DEBUG((DEBUG_INFO, "Signature - "));
  InternalDumpData (SignData, SignDataSize);
  DEBUG((DEBUG_INFO, "\n"));

  //
  // Get leaf cert from cert chain
  //
  Result = X509GetCertFromCertChain (MutCertChainData, MutCertChainDataSize, -1,  &MutCertBuffer, &MutCertBufferSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmReqAsymGetPublicKeyFromX509 (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg, MutCertBuffer, MutCertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmReqAsymVerify (
             SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg,
             SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
             Context,
             THCurrData,
             THCurrDataSize,
             SignData,
             SignDataSize
             );
  SpdmReqAsymFree (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg, Context);
  if (!Result) {
    DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyFinishSignature - PASS !!!\n"));

  return TRUE;
}

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
SpdmVerifyFinishReqHmac (
  IN  SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN  SPDM_SESSION_INFO    *SessionInfo,
  IN  UINT8                *Hmac,
  IN  UINTN                HmacSize
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  UINT8                         *CertChainData;
  UINTN                         CertChainDataSize;
  UINT8                         *MutCertChainData;
  UINTN                         MutCertChainDataSize;
  UINTN                         HashSize;
  BOOLEAN                       Result;
  UINT8                         THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                         THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  ASSERT (HmacSize == HashSize);

  Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  if (SessionInfo->MutAuthRequested) {
    Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&MutCertChainData, &MutCertChainDataSize);
    if (!Result) {
      return FALSE;
    }
  } else {
    MutCertChainData = NULL;
    MutCertChainDataSize = 0;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForFinish (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, MutCertChainData, MutCertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithRequestFinishedKey (SessionInfo->SecuredMessageContext, THCurrData, THCurrDataSize, HmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (HmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (CompareMem(Hmac, HmacData, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyFinishHmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyFinishHmac - PASS !!!\n"));
  return TRUE;
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
SpdmGenerateFinishRspHmac (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
     OUT UINT8                     *Hmac
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  UINT8                         *CertChainData;
  UINTN                         CertChainDataSize;
  UINT8                         *MutCertChainData;
  UINTN                         MutCertChainDataSize;
  UINT32                        HashSize;
  BOOLEAN                       Result;
  UINT8                         THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                         THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  if (SessionInfo->MutAuthRequested) {
    Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&MutCertChainData, &MutCertChainDataSize);
    if (!Result) {
      return FALSE;
    }
  } else {
    MutCertChainData = NULL;
    MutCertChainDataSize = 0;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForFinish (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, MutCertChainData, MutCertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, THCurrData, THCurrDataSize, HmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (HmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  CopyMem (Hmac, HmacData, HashSize);

  return TRUE;
}

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
SpdmVerifyFinishRspHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
  IN     VOID                 *HmacData,
  IN     UINTN                HmacDataSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     CalcHmacData[MAX_HASH_SIZE];
  UINT8                                     *CertChainData;
  UINTN                                     CertChainDataSize;
  UINT8                                     *MutCertChainData;
  UINTN                                     MutCertChainDataSize;
  BOOLEAN                                   Result;
  UINT8                                     THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                     THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  ASSERT(HashSize == HmacDataSize);

  Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  if (SessionInfo->MutAuthRequested) {
    Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&MutCertChainData, &MutCertChainDataSize);
    if (!Result) {
      return FALSE;
    }
  } else {
    MutCertChainData = NULL;
    MutCertChainDataSize = 0;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForFinish (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, MutCertChainData, MutCertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, THCurrData, THCurrDataSize, CalcHmacData);
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
  This function generates the PSK exchange HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Hmac                         The buffer to store the PSK exchange HMAC.

  @retval TRUE  PSK exchange HMAC is generated.
  @retval FALSE PSK exchange HMAC is not generated.
**/
BOOLEAN
SpdmGeneratePskExchangeRspHmac (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
     OUT UINT8                     *Hmac
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  UINT32                        HashSize;
  BOOLEAN                       Result;
  UINT8                         THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                         THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForExchange (SpdmContext, SessionInfo, NULL, 0, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, THCurrData, THCurrDataSize, HmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (HmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  CopyMem (Hmac, HmacData, HashSize);

  return TRUE;
}

/**
  This function verifies the PSK exchange HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  HmacData                     The HMAC data buffer.
  @param  HmacDataSize                 Size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
BOOLEAN
SpdmVerifyPskExchangeRspHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
  IN     VOID                 *HmacData,
  IN     UINTN                HmacDataSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     CalcHmacData[MAX_HASH_SIZE];
  BOOLEAN                                   Result;
  UINT8                                     THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                     THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  ASSERT(HashSize == HmacDataSize);

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForExchange (SpdmContext, SessionInfo, NULL, 0, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, THCurrData, THCurrDataSize, CalcHmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (CalcHmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (CompareMem (CalcHmacData, HmacData, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyPskExchangeHmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyPskExchangeHmac - PASS !!!\n"));

  return TRUE;
}

/**
  This function generates the PSK finish HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Hmac                         The buffer to store the finish HMAC.

  @retval TRUE  PSK finish HMAC is generated.
  @retval FALSE PSK finish HMAC is not generated.
**/
BOOLEAN
SpdmGeneratePskFinishReqHmac (
  IN     SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN     SPDM_SESSION_INFO            *SessionInfo,
     OUT VOID                         *Hmac
  )
{
  UINTN                                     HashSize;
  UINT8                                     CalcHmacData[MAX_HASH_SIZE];
  BOOLEAN                                   Result;
  UINT8                                     THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                     THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForFinish (SpdmContext, SessionInfo, NULL, 0, NULL, 0, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithRequestFinishedKey (SessionInfo->SecuredMessageContext, THCurrData, THCurrDataSize, CalcHmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (CalcHmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  CopyMem (Hmac, CalcHmacData, HashSize);

  return TRUE;
}

/**
  This function verifies the PSK finish HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  HmacData                     The HMAC data buffer.
  @param  HmacDataSize                 Size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
BOOLEAN
SpdmVerifyPskFinishReqHmac (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN  SPDM_SESSION_INFO         *SessionInfo,
  IN  UINT8                     *Hmac,
  IN  UINTN                     HmacSize
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  UINT32                        HashSize;
  BOOLEAN                       Result;
  UINT8                         THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                         THCurrDataSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  ASSERT (HmacSize == HashSize);

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForFinish (SpdmContext, SessionInfo, NULL, 0, NULL, 0, &THCurrDataSize, THCurrData);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithRequestFinishedKey (SessionInfo->SecuredMessageContext, THCurrData, THCurrDataSize, HmacData);
  DEBUG((DEBUG_INFO, "Calc THCurr Hmac - "));
  InternalDumpData (HmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (CompareMem(Hmac, HmacData, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyPskFinishHmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyPskFinishHmac - PASS !!!\n"));
  return TRUE;
}

/*
  This function calculates TH1 hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.
  @param  TH1HashData                  TH1 hash

  @retval RETURN_SUCCESS  TH1 hash is calculated.
*/
RETURN_STATUS
EFIAPI
SpdmCalculateTH1Hash (
  IN VOID                         *Context,
  IN VOID                         *SpdmSessionInfo,
  IN BOOLEAN                      IsRequester,
  OUT UINT8                       *TH1HashData
  )
{
  SPDM_DEVICE_CONTEXT            *SpdmContext;
  UINTN                          HashSize;
  UINT8                          *CertChainData;
  UINTN                          CertChainDataSize;
  SPDM_SESSION_INFO              *SessionInfo;
  BOOLEAN                        Result;
  UINT8                          THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                          THCurrDataSize;

  SpdmContext = Context;

  DEBUG((DEBUG_INFO, "Calc TH1 Hash ...\n"));

  SessionInfo = SpdmSessionInfo;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (!SessionInfo->UsePsk) {
    if (IsRequester) {
      Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
    } else {
      Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
    }
    if (!Result) {
      return RETURN_UNSUPPORTED;
    }
  } else {
    CertChainData = NULL;
    CertChainDataSize = 0;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForExchange (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, THCurrData, THCurrDataSize, TH1HashData);
  DEBUG((DEBUG_INFO, "TH1 Hash - "));
  InternalDumpData (TH1HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}

/*
  This function calculates TH2 hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.
  @param  TH1HashData                  TH2 hash

  @retval RETURN_SUCCESS  TH2 hash is calculated.
*/
RETURN_STATUS
EFIAPI
SpdmCalculateTH2Hash (
  IN VOID                         *Context,
  IN VOID                         *SpdmSessionInfo,
  IN BOOLEAN                      IsRequester,
  OUT UINT8                       *TH2HashData
  )
{
  SPDM_DEVICE_CONTEXT            *SpdmContext;
  UINTN                          HashSize;
  UINT8                          *CertChainData;
  UINTN                          CertChainDataSize;
  UINT8                          *MutCertChainData;
  UINTN                          MutCertChainDataSize;
  SPDM_SESSION_INFO              *SessionInfo;
  BOOLEAN                        Result;
  UINT8                          THCurrData[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                          THCurrDataSize;

  SpdmContext = Context;

  DEBUG((DEBUG_INFO, "Calc TH2 Hash ...\n"));

  SessionInfo = SpdmSessionInfo;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (!SessionInfo->UsePsk) {
    if (IsRequester) {
      Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
    } else {
      Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
    }
    if (!Result) {
      return RETURN_UNSUPPORTED;
    }
    if (SessionInfo->MutAuthRequested) {
      if (IsRequester) {
        Result = SpdmGetLocalCertChainData (SpdmContext, (VOID **)&MutCertChainData, &MutCertChainDataSize);
      } else {
        Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&MutCertChainData, &MutCertChainDataSize);
      }
      if (!Result) {
        return RETURN_UNSUPPORTED;
      }
    } else {
      MutCertChainData = NULL;
      MutCertChainDataSize = 0;
    }
  } else {
    CertChainData = NULL;
    CertChainDataSize = 0;
    MutCertChainData = NULL;
    MutCertChainDataSize = 0;
  }

  THCurrDataSize = sizeof(THCurrData);
  Result = SpdmCalculateTHForFinish (SpdmContext, SessionInfo, CertChainData, CertChainDataSize, MutCertChainData, MutCertChainDataSize, &THCurrDataSize, THCurrData);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, THCurrData, THCurrDataSize, TH2HashData);
  DEBUG((DEBUG_INFO, "TH2 Hash - "));
  InternalDumpData (TH2HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}
