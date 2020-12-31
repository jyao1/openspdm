/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

BOOLEAN
SpdmCalculateTHCurrAK (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
  IN     UINT8                     *CertBuffer, OPTIONAL
  IN     UINTN                     CertBufferSize, OPTIONAL
     OUT LARGE_MANAGED_BUFFER      *THCurr
  )
{
  UINT8                         CertBufferHash[MAX_HASH_SIZE];
  UINT32                        HashSize;
  RETURN_STATUS                 Status;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  InitManagedBuffer (THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  Status = AppendManagedBuffer (THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  if (CertBuffer != NULL) {
    DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
    InternalDumpHex (CertBuffer, CertBufferSize);
    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
    Status = AppendManagedBuffer (THCurr, CertBufferHash, HashSize);
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  Status = AppendManagedBuffer (THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  return TRUE;
}

BOOLEAN
SpdmCalculateTHCurrAKF (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
  IN     UINT8                     *CertBuffer, OPTIONAL
  IN     UINTN                     CertBufferSize, OPTIONAL
  IN     UINT8                     *MutCertBuffer, OPTIONAL
  IN     UINTN                     MutCertBufferSize, OPTIONAL
     OUT LARGE_MANAGED_BUFFER      *THCurr
  )
{
  UINT8                         CertBufferHash[MAX_HASH_SIZE];
  UINT8                         MutCertBufferHash[MAX_HASH_SIZE];
  UINT32                        HashSize;
  RETURN_STATUS                 Status;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  InitManagedBuffer (THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  Status = AppendManagedBuffer (THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  if (CertBuffer != NULL) {
    DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
    InternalDumpHex (CertBuffer, CertBufferSize);
    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
    Status = AppendManagedBuffer (THCurr, CertBufferHash, HashSize);
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  Status = AppendManagedBuffer (THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  if (MutCertBuffer != NULL) {
    DEBUG((DEBUG_INFO, "THMessageCM Data :\n"));
    InternalDumpHex (MutCertBuffer, MutCertBufferSize);
    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, MutCertBuffer, MutCertBufferSize, MutCertBufferHash);
    Status = AppendManagedBuffer (THCurr, MutCertBufferHash, HashSize);
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "MessageF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));
  Status = AppendManagedBuffer (THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

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
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT32                        HashSize;
  LARGE_MANAGED_BUFFER          THCurr;

  SignatureSize = GetSpdmAsymSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
    return FALSE;
  }
  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  Result = SpdmCalculateTHCurrAK (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
  DEBUG((DEBUG_INFO, "THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Result = SpdmResponderDataSignFunc (
             SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
             HashData,
             HashSize,
             Signature,
             &SignatureSize
             );

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
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  UINT32                        HashSize;
  LARGE_MANAGED_BUFFER          THCurr;
  BOOLEAN                       Result;

  if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  Result = SpdmCalculateTHCurrAK (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HmacData);
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
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  VOID                                      *Context;
  LARGE_MANAGED_BUFFER                      THCurr;
  UINT8                                     *CertChainBuffer;
  UINTN                                     CertChainBufferSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
    CertChainBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertChainBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
    CertChainBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertChainBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    return FALSE;
  }

  Result = SpdmCalculateTHCurrAK (SpdmContext, SessionInfo, CertChainBuffer, CertChainBufferSize, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
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

  Result = SpdmAsymGetPublicKeyFromX509 (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo, CertBuffer, CertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymVerify (
             SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
             Context,
             HashData,
             HashSize,
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
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  LARGE_MANAGED_BUFFER                      THCurr;
  BOOLEAN                                   Result;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  ASSERT(HashSize == HmacDataSize);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
    CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
    CertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    return FALSE;
  }

  Result = SpdmCalculateTHCurrAK (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), CalcHmacData);
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
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  UINT8                         *MutCertBuffer;
  UINTN                         MutCertBufferSize;
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT32                        HashSize;
  LARGE_MANAGED_BUFFER          THCurr;

  if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
    return FALSE;
  }

  SignatureSize = GetSpdmReqAsymSize (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg);
  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
    CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
    CertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    return FALSE;
  }

  MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  MutCertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  Result = SpdmCalculateTHCurrAKF (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, MutCertBuffer, MutCertBufferSize, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
  DEBUG((DEBUG_INFO, "THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Result = SpdmRequesterDataSignFunc (
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
SpdmGenerateFinishReqHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
     OUT VOID                 *Hmac
  )
{
  UINTN                                     HashSize;
  UINT8                                     CalcHmacData[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  UINT8                                     *MutCertBuffer;
  UINTN                                     MutCertBufferSize;
  LARGE_MANAGED_BUFFER                      THCurr;
  BOOLEAN                                   Result;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
    CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
    CertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    return FALSE;
  }

  if (SessionInfo->MutAuthRequested) {
    if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
      return FALSE;
    }
    MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    MutCertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    MutCertBuffer = NULL;
    MutCertBufferSize = 0;
  }

  Result = SpdmCalculateTHCurrAKF (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, MutCertBuffer, MutCertBufferSize, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithRequestFinishedKey (SessionInfo->SecuredMessageContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), CalcHmacData);
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
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  UINT8                                     *MutCertBuffer;
  UINTN                                     MutCertBufferSize;
  UINT8                                     *MutCertChainBuffer;
  UINTN                                     MutCertChainBufferSize;
  VOID                                      *Context;
  LARGE_MANAGED_BUFFER                      THCurr;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
    return FALSE;
  }
  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
    MutCertChainBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    MutCertChainBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
    MutCertChainBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
    MutCertChainBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    return FALSE;
  }

  Result = SpdmCalculateTHCurrAKF (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, MutCertChainBuffer, MutCertChainBufferSize, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
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

  Result = SpdmReqAsymGetPublicKeyFromX509 (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg, MutCertBuffer, MutCertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmReqAsymVerify (
             SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg,
             Context,
             HashData,
             HashSize,
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
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  UINT8                         *MutCertBuffer;
  UINTN                         MutCertBufferSize;
  UINTN                         HashSize;
  LARGE_MANAGED_BUFFER          THCurr;
  BOOLEAN                       Result;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  ASSERT (HmacSize == HashSize);

  if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
    return FALSE;
  }
  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  if (SessionInfo->MutAuthRequested) {
    if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
      MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
      MutCertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
      MutCertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
      MutCertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    } else {
      return FALSE;
    }
  } else {
    MutCertBuffer = NULL;
    MutCertBufferSize = 0;
  }

  Result = SpdmCalculateTHCurrAKF (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, MutCertBuffer, MutCertBufferSize, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithRequestFinishedKey (SessionInfo->SecuredMessageContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HmacData);
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
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  UINT8                         *MutCertBuffer;
  UINTN                         MutCertBufferSize;
  UINT32                        HashSize;
  LARGE_MANAGED_BUFFER          THCurr;
  BOOLEAN                       Result;

  if ((SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) || (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0)) {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  if (SessionInfo->MutAuthRequested) {
    if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
      MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
      MutCertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
      MutCertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
      MutCertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    } else {
      return FALSE;
    }
  } else {
    MutCertBuffer = NULL;
    MutCertBufferSize = 0;
  }

  Result = SpdmCalculateTHCurrAKF (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, MutCertBuffer, MutCertBufferSize, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HmacData);
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
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  UINT8                                     *MutCertBuffer;
  UINTN                                     MutCertBufferSize;
  LARGE_MANAGED_BUFFER                      THCurr;
  BOOLEAN                                   Result;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  ASSERT(HashSize == HmacDataSize);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
    CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
    CertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    return FALSE;
  }

  if (SessionInfo->MutAuthRequested) {
    if (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize == 0) {
      return FALSE;
    }
    MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    MutCertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    MutCertBuffer = NULL;
    MutCertBufferSize = 0;
  }

  Result = SpdmCalculateTHCurrAKF (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, MutCertBuffer, MutCertBufferSize, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), CalcHmacData);
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
  LARGE_MANAGED_BUFFER          THCurr;
  BOOLEAN                       Result;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  Result = SpdmCalculateTHCurrAK (SpdmContext, SessionInfo, NULL, 0, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HmacData);
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
  LARGE_MANAGED_BUFFER                      THCurr;
  BOOLEAN                                   Result;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  ASSERT(HashSize == HmacDataSize);

  Result = SpdmCalculateTHCurrAK (SpdmContext, SessionInfo, NULL, 0, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithResponseFinishedKey (SessionInfo->SecuredMessageContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), CalcHmacData);
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
  LARGE_MANAGED_BUFFER                      THCurr;
  BOOLEAN                                   Result;

  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  Result = SpdmCalculateTHCurrAKF (SpdmContext, SessionInfo, NULL, 0, NULL, 0, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithRequestFinishedKey (SessionInfo->SecuredMessageContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), CalcHmacData);
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
  LARGE_MANAGED_BUFFER          THCurr;
  BOOLEAN                       Result;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  ASSERT (HmacSize == HashSize);

  Result = SpdmCalculateTHCurrAKF (SpdmContext, SessionInfo, NULL, 0, NULL, 0, &THCurr);
  if (!Result) {
    return FALSE;
  }

  SpdmHmacAllWithRequestFinishedKey (SessionInfo->SecuredMessageContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HmacData);
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
SpdmCalculateTH1 (
  IN VOID                         *Context,
  IN VOID                         *SpdmSessionInfo,
  IN BOOLEAN                      IsRequester,
  OUT UINT8                       *TH1HashData
  )
{
  SPDM_DEVICE_CONTEXT            *SpdmContext;
  UINTN                          HashSize;
  UINT8                          *CertBuffer;
  UINTN                          CertBufferSize;
  LARGE_MANAGED_BUFFER           TH1;
  SPDM_SESSION_INFO              *SessionInfo;
  BOOLEAN                        Result;

  SpdmContext = Context;

  DEBUG((DEBUG_INFO, "Calc TH1 Hash ...\n"));

  SessionInfo = SpdmSessionInfo;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (!SessionInfo->UsePsk) {
    if (IsRequester) {
      if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
        CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
        CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
        CertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
        CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      } else {
        ASSERT (FALSE);
        return RETURN_UNSUPPORTED;
      }
    } else {
      ASSERT (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize != 0);
      CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    }
  } else {
    CertBuffer = NULL;
    CertBufferSize = 0;
  }

  Result = SpdmCalculateTHCurrAK (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, &TH1);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&TH1), GetManagedBufferSize(&TH1), TH1HashData);
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
SpdmCalculateTH2 (
  IN VOID                         *Context,
  IN VOID                         *SpdmSessionInfo,
  IN BOOLEAN                      IsRequester,
  OUT UINT8                       *TH2HashData
  )
{
  SPDM_DEVICE_CONTEXT            *SpdmContext;
  UINTN                          HashSize;
  UINT8                          *CertBuffer;
  UINTN                          CertBufferSize;
  UINT8                          *MutCertBuffer;
  UINTN                          MutCertBufferSize;
  LARGE_MANAGED_BUFFER           TH2;
  SPDM_SESSION_INFO              *SessionInfo;
  BOOLEAN                        Result;

  SpdmContext = Context;

  DEBUG((DEBUG_INFO, "Calc TH2 Hash ...\n"));

  InitManagedBuffer (&TH2, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  SessionInfo = SpdmSessionInfo;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (SessionInfo->UsePsk) {
    if (IsRequester) {
      if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
        CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
        CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
        CertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
        CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      } else {
        ASSERT (FALSE);
        return RETURN_UNSUPPORTED;
      }
    } else {
      ASSERT (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize != 0);
      CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    }
    if (SessionInfo->MutAuthRequested) {
      if (IsRequester) {
        ASSERT (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize != 0);
        MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
        MutCertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      } else {
        if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
          MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
          MutCertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
        } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
          MutCertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
          MutCertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
        } else {
          ASSERT (FALSE);
          return RETURN_UNSUPPORTED;
        }
      }
    } else {
      MutCertBuffer = NULL;
      MutCertBufferSize = 0;
    }
  } else {
    CertBuffer = NULL;
    CertBufferSize = 0;
    MutCertBuffer = NULL;
    MutCertBufferSize = 0;
  }

  Result = SpdmCalculateTHCurrAKF (SpdmContext, SessionInfo, CertBuffer, CertBufferSize, MutCertBuffer, MutCertBufferSize, &TH2);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&TH2), GetManagedBufferSize(&TH2), TH2HashData);
  DEBUG((DEBUG_INFO, "TH2 Hash - "));
  InternalDumpData (TH2HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}
