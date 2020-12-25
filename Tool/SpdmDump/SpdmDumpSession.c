/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

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
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester
  )
{
  UINTN                          HashSize;
  SPDM_SESSION_INFO              *SessionInfo;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  HashSize = GetSpdmHashSize (SpdmContext);

  if (!SessionInfo->UsePsk) {
    if (mDheSecretBuffer == NULL || mDheSecretBufferSize == 0) {
      return RETURN_UNSUPPORTED;
    }
    SpdmSecuredMessageSetDheSecret (SessionInfo->SecuredMessageContext, mDheSecretBuffer, mDheSecretBufferSize);

    if (IsRequester) {
      if (SessionInfo->MutAuthRequested) {
        if (mRequesterCertChainBuffer == NULL || mRequesterCertChainBufferSize == 0) {
          return RETURN_UNSUPPORTED;
        }
        memcpy (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize, mRequesterCertChainBuffer, mRequesterCertChainBufferSize);
        SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = sizeof(SPDM_CERT_CHAIN) + HashSize + mRequesterCertChainBufferSize;
      }
      if (mResponderCertChainBuffer == NULL || mResponderCertChainBufferSize == 0) {
        return RETURN_UNSUPPORTED;
      }
      memcpy (SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize, mResponderCertChainBuffer, mResponderCertChainBufferSize);
      SpdmContext->ConnectionInfo.PeerCertChainBufferSize = sizeof(SPDM_CERT_CHAIN) + HashSize + mResponderCertChainBufferSize;
    } else {
      if (mResponderCertChainBuffer == NULL || mResponderCertChainBufferSize == 0) {
        return RETURN_UNSUPPORTED;
      }
      memcpy (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize, mResponderCertChainBuffer, mResponderCertChainBufferSize);
      SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = sizeof(SPDM_CERT_CHAIN) + HashSize + mResponderCertChainBufferSize;
      if (SessionInfo->MutAuthRequested) {
        if (mRequesterCertChainBuffer == NULL || mRequesterCertChainBufferSize == 0) {
          return RETURN_UNSUPPORTED;
        }
        memcpy (SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize, mRequesterCertChainBuffer, mRequesterCertChainBufferSize);
        SpdmContext->ConnectionInfo.PeerCertChainBufferSize = sizeof(SPDM_CERT_CHAIN) + HashSize + mRequesterCertChainBufferSize;
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
    SpdmSecuredMessageSetDheSecret (SessionInfo->SecuredMessageContext, mPskBuffer, mPskBufferSize);
  }

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmDumpSessionDataCheck (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester
  )
{
  SPDM_SESSION_INFO              *SessionInfo;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  if (!SessionInfo->UsePsk) {
    if (mDheSecretBuffer == NULL || mDheSecretBufferSize == 0) {
      return RETURN_UNSUPPORTED;
    }
    if (IsRequester) {
      if (SessionInfo->MutAuthRequested) {
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
      if (SessionInfo->MutAuthRequested) {
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
