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
  @param  SessionInfo                  The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.
  @param  TH1HashData                  TH1 hash

  @retval RETURN_SUCCESS  TH1 hash is calculated.
*/
RETURN_STATUS
SpdmCalculateTh1 (
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
SpdmCalculateTh2 (
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

