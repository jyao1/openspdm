/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

extern UINT32 mSpdmBaseHashAlgo;
extern VOID   *mLocalUsedCertChainBuffer;
extern UINTN  mLocalUsedCertChainBufferSize;
extern VOID   *mPeerCertChainBuffer;
extern UINTN  mPeerCertChainBufferSize;

VOID    *mRequesterCertChainBuffer;
UINTN   mRequesterCertChainBufferSize;
VOID    *mResponderCertChainBuffer;
UINTN   mResponderCertChainBufferSize;
VOID    *mDheSecretBuffer;
UINTN   mDheSecretBufferSize;
VOID    *mPskBuffer;
UINTN   mPskBufferSize;

RETURN_STATUS
SpdmDumpSessionDataProvision (
  IN VOID                         *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      NeedMutAuth,
  IN BOOLEAN                      IsRequester
  )
{
  UINTN                          HashSize;
  VOID                           *SessionInfo;
  VOID                           *SecuredMessageContext;
  SPDM_DATA_PARAMETER            Parameter;
  BOOLEAN                        UsePsk;
  UINT8                          MutAuthRequested;
  UINTN                          DataSize;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }
  SecuredMessageContext = SpdmGetSecuredMessageContextViaSessionId (SpdmContext, SessionId);
  if (SecuredMessageContext == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  *(UINT32 *)Parameter.AdditionalData = SessionId;
  DataSize = sizeof(UsePsk);
  SpdmGetData (SpdmContext, SpdmDataSessionUsePsk, &Parameter, &UsePsk, &DataSize);
  DataSize = sizeof(MutAuthRequested);
  SpdmGetData (SpdmContext, SpdmDataSessionMutAuthRequested, &Parameter, &MutAuthRequested, &DataSize);

  HashSize = GetSpdmHashSize (mSpdmBaseHashAlgo);

  if (!UsePsk) {
    if (mDheSecretBuffer == NULL || mDheSecretBufferSize == 0) {
      return RETURN_UNSUPPORTED;
    }
    SpdmSecuredMessageImportDheSecret (SecuredMessageContext, mDheSecretBuffer, mDheSecretBufferSize);

    if (IsRequester) {
      if (NeedMutAuth && MutAuthRequested) {
        if (mRequesterCertChainBuffer == NULL || mRequesterCertChainBufferSize == 0) {
          return RETURN_UNSUPPORTED;
        }
        memcpy ((UINT8 *)mLocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize, mRequesterCertChainBuffer, mRequesterCertChainBufferSize);
        mLocalUsedCertChainBufferSize = sizeof(SPDM_CERT_CHAIN) + HashSize + mRequesterCertChainBufferSize;
        ZeroMem (&Parameter, sizeof(Parameter));
        Parameter.Location = SpdmDataLocationConnection;
        SpdmSetData (SpdmContext, SpdmDataLocalUsedCertChainBuffer, &Parameter, mLocalUsedCertChainBuffer, mLocalUsedCertChainBufferSize);
      }
      if (mResponderCertChainBuffer == NULL || mResponderCertChainBufferSize == 0) {
        return RETURN_UNSUPPORTED;
      }
      memcpy ((UINT8 *)mPeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize, mResponderCertChainBuffer, mResponderCertChainBufferSize);
      mPeerCertChainBufferSize = sizeof(SPDM_CERT_CHAIN) + HashSize + mResponderCertChainBufferSize;
      ZeroMem (&Parameter, sizeof(Parameter));
      Parameter.Location = SpdmDataLocationConnection;
      SpdmSetData (SpdmContext, SpdmDataPeerUsedCertChainBuffer, &Parameter, mPeerCertChainBuffer, mPeerCertChainBufferSize);
    } else {
      if (mResponderCertChainBuffer == NULL || mResponderCertChainBufferSize == 0) {
        return RETURN_UNSUPPORTED;
      }
      memcpy ((UINT8 *)mLocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize, mResponderCertChainBuffer, mResponderCertChainBufferSize);
      mLocalUsedCertChainBufferSize = sizeof(SPDM_CERT_CHAIN) + HashSize + mResponderCertChainBufferSize;
      ZeroMem (&Parameter, sizeof(Parameter));
      Parameter.Location = SpdmDataLocationConnection;
      SpdmSetData (SpdmContext, SpdmDataLocalUsedCertChainBuffer, &Parameter, mLocalUsedCertChainBuffer, mLocalUsedCertChainBufferSize);
      if (NeedMutAuth && MutAuthRequested) {
        if (mRequesterCertChainBuffer == NULL || mRequesterCertChainBufferSize == 0) {
          return RETURN_UNSUPPORTED;
        }
        memcpy ((UINT8 *)mPeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize, mRequesterCertChainBuffer, mRequesterCertChainBufferSize);
        mPeerCertChainBufferSize = sizeof(SPDM_CERT_CHAIN) + HashSize + mRequesterCertChainBufferSize;
        ZeroMem (&Parameter, sizeof(Parameter));
        Parameter.Location = SpdmDataLocationConnection;
        SpdmSetData (SpdmContext, SpdmDataPeerUsedCertChainBuffer, &Parameter, mPeerCertChainBuffer, mPeerCertChainBufferSize);
      }
    }
  } else {
    if (mPskBuffer == NULL || mPskBufferSize == 0) {
      return RETURN_UNSUPPORTED;
    }
    if (mPskBufferSize > MAX_DHE_KEY_SIZE) {
      printf ("BUGBUG: PSK size is too large. It will be supported later.\n");
      return RETURN_UNSUPPORTED;
    }
    SpdmSecuredMessageImportDheSecret (SecuredMessageContext, mPskBuffer, mPskBufferSize);
  }

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmDumpSessionDataCheck (
  IN VOID                         *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester
  )
{
  VOID                           *SessionInfo;
  SPDM_DATA_PARAMETER            Parameter;
  BOOLEAN                        UsePsk;
  UINT8                          MutAuthRequested;
  UINTN                          DataSize;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  *(UINT32 *)Parameter.AdditionalData = SessionId;
  DataSize = sizeof(UsePsk);
  SpdmGetData (SpdmContext, SpdmDataSessionUsePsk, &Parameter, &UsePsk, &DataSize);
  DataSize = sizeof(MutAuthRequested);
  SpdmGetData (SpdmContext, SpdmDataSessionMutAuthRequested, &Parameter, &MutAuthRequested, &DataSize);

  if (!UsePsk) {
    if (mDheSecretBuffer == NULL || mDheSecretBufferSize == 0) {
      return RETURN_UNSUPPORTED;
    }
    if (IsRequester) {
      if (MutAuthRequested) {
        if (mRequesterCertChainBuffer == NULL || mRequesterCertChainBufferSize == 0) {
          return RETURN_UNSUPPORTED;
        }
      }
      if (mResponderCertChainBuffer == NULL || mResponderCertChainBufferSize == 0) {
        return RETURN_UNSUPPORTED;
      }
    } else {
      if (mResponderCertChainBuffer == NULL || mResponderCertChainBufferSize == 0) {
        return RETURN_UNSUPPORTED;
      }
      if (MutAuthRequested) {
        if (mRequesterCertChainBuffer == NULL || mRequesterCertChainBufferSize == 0) {
          return RETURN_UNSUPPORTED;
        }
      }
    }
  } else {
    if (mPskBuffer == NULL || mPskBufferSize == 0) {
      return RETURN_UNSUPPORTED;
    }
  }

  return RETURN_SUCCESS;
}
