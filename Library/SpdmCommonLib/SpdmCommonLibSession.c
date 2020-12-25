/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

/*
  This function calculates TH1 hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.
  @param  TH1HashData                  TH1 hash

  @retval RETURN_SUCCESS  TH1 hash is calculated.
*/
RETURN_STATUS
SpdmCalculateTh1 (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester,
  OUT UINT8                       *TH1HashData
  )
{
  UINTN                          HashSize;
  UINT8                          *CertBuffer;
  UINTN                          CertBufferSize;
  UINT8                          CertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER           TH1;
  SPDM_SESSION_INFO              *SessionInfo;

  DEBUG((DEBUG_INFO, "Calc TH1 Hash ...\n"));

  InitManagedBuffer (&TH1, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  HashSize = GetSpdmHashSize (SpdmContext);

  if (IsRequester) {
    if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
      CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
      CertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    } else {
      ASSERT (FALSE);
    }
  } else {
    ASSERT (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize != 0);
    CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  }
  SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  if (SessionInfo->UsePsk) {
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    DEBUG((DEBUG_INFO, "MessageA Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

    AppendManagedBuffer (&TH1, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
    DEBUG((DEBUG_INFO, "MessageK Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  } else {
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    DEBUG((DEBUG_INFO, "MessageA Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

    AppendManagedBuffer (&TH1, CertBufferHash, HashSize);
    DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
    InternalDumpHex (CertBuffer, CertBufferSize);
  
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
    DEBUG((DEBUG_INFO, "MessageK Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  }
  
  SpdmHashAll (SpdmContext, GetManagedBuffer(&TH1), GetManagedBufferSize(&TH1), TH1HashData);
  DEBUG((DEBUG_INFO, "TH1 Hash - "));
  InternalDumpData (TH1HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}

/*
  This function calculates TH2 hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.
  @param  TH1HashData                  TH2 hash

  @retval RETURN_SUCCESS  TH2 hash is calculated.
*/
RETURN_STATUS
SpdmCalculateTh2 (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester,
  OUT UINT8                       *TH2HashData
  )
{
  UINTN                          HashSize;
  UINT8                          *CertBuffer;
  UINTN                          CertBufferSize;
  UINT8                          CertBufferHash[MAX_HASH_SIZE];
  UINT8                          *MutCertBuffer;
  UINTN                          MutCertBufferSize;
  UINT8                          MutCertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER           TH2;
  SPDM_SESSION_INFO              *SessionInfo;

  DEBUG((DEBUG_INFO, "Calc TH2 Hash ...\n"));

  InitManagedBuffer (&TH2, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  HashSize = GetSpdmHashSize (SpdmContext);

  if (IsRequester) {
    if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
      CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
      CertBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    } else {
      ASSERT (FALSE);
    }
  } else {
    ASSERT (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize != 0);
    CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  }
  SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);
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
      }
    }
    SpdmHashAll (SpdmContext, MutCertBuffer, MutCertBufferSize, MutCertBufferHash);
  }

  if (SessionInfo->UsePsk) {
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    DEBUG((DEBUG_INFO, "MessageA Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

    AppendManagedBuffer (&TH2, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
    DEBUG((DEBUG_INFO, "MessageK Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

    AppendManagedBuffer (&TH2, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));
    DEBUG((DEBUG_INFO, "MessageF Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));
  } else {
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    DEBUG((DEBUG_INFO, "MessageA Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

    AppendManagedBuffer (&TH2, CertBufferHash, HashSize);
    DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
    InternalDumpHex (CertBuffer, CertBufferSize);

    AppendManagedBuffer (&TH2, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
    DEBUG((DEBUG_INFO, "MessageK Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

    if (SessionInfo->MutAuthRequested) {
      AppendManagedBuffer (&TH2, MutCertBufferHash, HashSize);
      DEBUG((DEBUG_INFO, "THMessageMyCM Data :\n"));
      InternalDumpHex (MutCertBuffer, MutCertBufferSize);
    }

    AppendManagedBuffer (&TH2, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));
    DEBUG((DEBUG_INFO, "MessageF Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));
  }
  SpdmHashAll (SpdmContext, GetManagedBuffer(&TH2), GetManagedBufferSize(&TH2), TH2HashData);
  DEBUG((DEBUG_INFO, "TH2 Hash - "));
  InternalDumpData (TH2HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}

