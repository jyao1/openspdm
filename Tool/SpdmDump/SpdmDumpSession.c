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

extern UINT8  mZeroFilledBuffer[64];

RETURN_STATUS
SpdmCalculateTh1 (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester,
  OUT UINT8                       *TH1HashData
  );

RETURN_STATUS
SpdmCalculateTh2 (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester,
  OUT UINT8                       *TH2HashData
  );

RETURN_STATUS
SpdmGenerateAeadKeyAndIv (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        *MajorSecret,
  OUT UINT8                       *Key,
  OUT UINT8                       *Iv
  );

RETURN_STATUS
SpdmGenerateFinishedKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        *HandshakeSecret,
  OUT UINT8                       *FinishedKey
  );

RETURN_STATUS
SpdmCalculateSessionHandshakeKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester
  )
{
  RETURN_STATUS                  Status;
  BOOLEAN                        RetVal;
  UINTN                          HashSize;
  UINT8                          TH1HashData[64];
  UINT8                          BinStr0[128];
  UINTN                          BinStr0Size;
  UINT8                          BinStr1[128];
  UINTN                          BinStr1Size;
  UINT8                          BinStr2[128];
  UINTN                          BinStr2Size;
  SPDM_SESSION_INFO              *SessionInfo;

  DEBUG ((DEBUG_INFO, "SpdmCalculateSessionHandshakeKey[%x]\n", SessionId));

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  HashSize = GetSpdmHashSize (SpdmContext);
  SessionInfo->HashSize = HashSize;
  SessionInfo->AeadKeySize = GetSpdmAeadKeySize(SpdmContext);
  SessionInfo->AeadIvSize = GetSpdmAeadIvSize(SpdmContext);

  if (!SessionInfo->UsePsk) {
    if (mDheSecretBuffer == NULL || mDheSecretBufferSize == 0) {
      return RETURN_UNSUPPORTED;
    }
    memcpy (SessionInfo->MasterSecret.DheSecret, mDheSecretBuffer, mDheSecretBufferSize);
    SessionInfo->DheKeySize = mDheSecretBufferSize;

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
    memcpy (SessionInfo->MasterSecret.DheSecret, mPskBuffer, mPskBufferSize);
    SessionInfo->DheKeySize = mPskBufferSize;
  }
  Status = SpdmCalculateTh1 (SpdmContext, SessionId, IsRequester, TH1HashData);
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  
  BinStr0Size = sizeof(BinStr0);
  Status = BinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr0 (0x%x):\n", BinStr0Size));
  InternalDumpHex (BinStr0, BinStr0Size);

  RetVal = SpdmHmacAll (SpdmContext, mZeroFilledBuffer, HashSize, SessionInfo->MasterSecret.DheSecret, SessionInfo->DheKeySize, SessionInfo->MasterSecret.HandshakeSecret);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "HandshakeSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->MasterSecret.HandshakeSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  BinStr1Size = sizeof(BinStr1);
  Status = BinConcat (BIN_STR_1_LABEL, sizeof(BIN_STR_1_LABEL), TH1HashData, (UINT16)HashSize, HashSize, BinStr1, &BinStr1Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr1 (0x%x):\n", BinStr1Size));
  InternalDumpHex (BinStr1, BinStr1Size);
  RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.HandshakeSecret, HashSize, BinStr1, BinStr1Size, SessionInfo->HandshakeSecret.RequestHandshakeSecret, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "RequestHandshakeSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->HandshakeSecret.RequestHandshakeSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  BinStr2Size = sizeof(BinStr2);
  Status = BinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL), TH1HashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr2 (0x%x):\n", BinStr2Size));
  InternalDumpHex (BinStr2, BinStr2Size);
  RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.HandshakeSecret, HashSize, BinStr2, BinStr2Size, SessionInfo->HandshakeSecret.ResponseHandshakeSecret, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "ResponseHandshakeSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->HandshakeSecret.ResponseHandshakeSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  SpdmGenerateFinishedKey (
    SpdmContext,
    SessionInfo->HandshakeSecret.RequestHandshakeSecret,
    SessionInfo->HandshakeSecret.RequestFinishedKey
    );

  SpdmGenerateFinishedKey (
    SpdmContext,
    SessionInfo->HandshakeSecret.ResponseHandshakeSecret,
    SessionInfo->HandshakeSecret.ResponseFinishedKey
    );

  SpdmGenerateAeadKeyAndIv (
    SpdmContext,
    SessionInfo->HandshakeSecret.RequestHandshakeSecret,
    SessionInfo->HandshakeSecret.RequestHandshakeEncryptionKey,
    SessionInfo->HandshakeSecret.RequestHandshakeSalt
    );
  SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber = 0;

  SpdmGenerateAeadKeyAndIv (
    SpdmContext,
    SessionInfo->HandshakeSecret.ResponseHandshakeSecret,
    SessionInfo->HandshakeSecret.ResponseHandshakeEncryptionKey,
    SessionInfo->HandshakeSecret.ResponseHandshakeSalt
    );
  SessionInfo->HandshakeSecret.ResponseHandshakeSequenceNumber = 0;

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmCalculateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester
  )
{
  RETURN_STATUS                  Status;
  BOOLEAN                        RetVal;
  UINTN                          HashSize;
  UINT8                          TH2HashData[64];
  UINT8                          Salt1[64];
  UINT8                          BinStr0[128];
  UINTN                          BinStr0Size;
  UINT8                          BinStr3[128];
  UINTN                          BinStr3Size;
  UINT8                          BinStr4[128];
  UINTN                          BinStr4Size;
  UINT8                          BinStr8[128];
  UINTN                          BinStr8Size;
  SPDM_SESSION_INFO              *SessionInfo;

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionDataKey[%x]\n", SessionId));

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  HashSize = GetSpdmHashSize (SpdmContext);

  ASSERT (SessionInfo->HashSize != 0);

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
  Status = SpdmCalculateTh2 (SpdmContext, SessionId, IsRequester, TH2HashData);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  BinStr0Size = sizeof(BinStr0);
  Status = BinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
  ASSERT_RETURN_ERROR (Status);
  RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.HandshakeSecret, HashSize, BinStr0, BinStr0Size, Salt1, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "Salt1 (0x%x) - ", HashSize));
  InternalDumpData (Salt1, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  RetVal = SpdmHmacAll (SpdmContext, Salt1, HashSize, mZeroFilledBuffer, HashSize, SessionInfo->MasterSecret.MasterSecret);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "MasterSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->MasterSecret.MasterSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  BinStr3Size = sizeof(BinStr3);
  Status = BinConcat (BIN_STR_3_LABEL, sizeof(BIN_STR_3_LABEL), TH2HashData, (UINT16)HashSize, HashSize, BinStr3, &BinStr3Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr3 (0x%x):\n", BinStr3Size));
  InternalDumpHex (BinStr3, BinStr3Size);
  RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.MasterSecret, HashSize, BinStr3, BinStr3Size, SessionInfo->ApplicationSecret.RequestDataSecret, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "RequestDataSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->ApplicationSecret.RequestDataSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  BinStr4Size = sizeof(BinStr4);
  Status = BinConcat (BIN_STR_4_LABEL, sizeof(BIN_STR_4_LABEL), TH2HashData, (UINT16)HashSize, HashSize, BinStr4, &BinStr4Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr4 (0x%x):\n", BinStr4Size));
  InternalDumpHex (BinStr4, BinStr4Size);
  RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.MasterSecret, HashSize, BinStr4, BinStr4Size, SessionInfo->ApplicationSecret.ResponseDataSecret, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "ResponseDataSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->ApplicationSecret.ResponseDataSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  BinStr8Size = sizeof(BinStr8);
  Status = BinConcat (BIN_STR_8_LABEL, sizeof(BIN_STR_8_LABEL), TH2HashData, (UINT16)HashSize, HashSize, BinStr8, &BinStr8Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr8 (0x%x):\n", BinStr8Size));
  InternalDumpHex (BinStr8, BinStr8Size);
  RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.MasterSecret, HashSize, BinStr8, BinStr8Size, SessionInfo->HandshakeSecret.ExportMasterSecret, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "ExportMasterSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->HandshakeSecret.ExportMasterSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  SpdmGenerateAeadKeyAndIv (
    SpdmContext,
    SessionInfo->ApplicationSecret.RequestDataSecret,
    SessionInfo->ApplicationSecret.RequestDataEncryptionKey,
    SessionInfo->ApplicationSecret.RequestDataSalt
    );
  SessionInfo->ApplicationSecret.RequestDataSequenceNumber = 0;

  SpdmGenerateAeadKeyAndIv (
    SpdmContext,
    SessionInfo->ApplicationSecret.ResponseDataSecret,
    SessionInfo->ApplicationSecret.ResponseDataEncryptionKey,
    SessionInfo->ApplicationSecret.ResponseDataSalt
    );
  SessionInfo->ApplicationSecret.ResponseDataSequenceNumber = 0;

  return RETURN_SUCCESS;
}
