/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

#define BIN_CONCAT_LABEL "spdm1.1"
#define BIN_STR_0_LABEL  "derived"
#define BIN_STR_1_LABEL  "req hs data"
#define BIN_STR_2_LABEL  "rsp hs data"
#define BIN_STR_3_LABEL  "req app data"
#define BIN_STR_4_LABEL  "rsp app data"
#define BIN_STR_5_LABEL  "key"
#define BIN_STR_6_LABEL  "iv"
#define BIN_STR_7_LABEL  "finished"
#define BIN_STR_8_LABEL  "exp master"
#define BIN_STR_9_LABEL  "traffic upd"

GLOBAL_REMOVE_IF_UNREFERENCED UINT8  mZeroFilledBuffer[64];

/**
  This function concatenates binary data, which is used as Info in HKDF expand later.

  @param  Label                        An ascii string label for the BinConcat.
  @param  LabelSize                    The size in bytes of the ASCII string label, including the NULL terminator.
  @param  Context                      A pre-defined hash value as the context for the BinConcat.
  @param  Length                       16 bits length for the BinConcat.
  @param  HashSize                     The size in bytes of the context hash.
  @param  OutBin                       The buffer to store the output binary.
  @param  OutBinSize                   The size in bytes for the OutBin.

  @retval RETURN_SUCCESS               The binary BinConcat data is generated.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
BinConcat (
  IN CHAR8     *Label,
  IN UINTN     LabelSize,
  IN UINT8     *Context,
  IN UINT16    Length,
  IN UINTN     HashSize,
  OUT UINT8    *OutBin,
  IN OUT UINTN *OutBinSize
  )
{
  UINTN  FinalSize;

  FinalSize = sizeof(UINT16) + sizeof(BIN_CONCAT_LABEL) + LabelSize;
  if (Context != NULL) {
    FinalSize += HashSize;
  }
  if (*OutBinSize < FinalSize) {
    *OutBinSize = FinalSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  
  *OutBinSize = FinalSize;

  CopyMem (OutBin, &Length, sizeof(UINT16));
  CopyMem (OutBin + sizeof(UINT16), BIN_CONCAT_LABEL, sizeof(BIN_CONCAT_LABEL));
  CopyMem (OutBin + sizeof(UINT16) + sizeof(BIN_CONCAT_LABEL), Label, LabelSize);
  if (Context != NULL) {
    CopyMem (OutBin + sizeof(UINT16) + sizeof(BIN_CONCAT_LABEL) + LabelSize, Context, HashSize);
  }

  return RETURN_SUCCESS;
}

/**
  This function generates SPDM AEAD Key and IV for a session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MajorSecret                  The major secret.
  @param  Key                          The buffer to store the AEAD key.
  @param  Iv                           The buffer to store the AEAD IV.

  @retval RETURN_SUCCESS  SPDM AEAD key and IV for a session is generated.
**/
RETURN_STATUS
SpdmGenerateAeadKeyAndIv (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        *MajorSecret,
  OUT UINT8                       *Key,
  OUT UINT8                       *Iv
  )
{
  RETURN_STATUS   Status;
  BOOLEAN         RetVal;
  UINTN           HashSize;
  UINTN           KeyLength;
  UINTN           IvLength;
  UINT8           BinStr5[128];
  UINTN           BinStr5Size;
  UINT8           BinStr6[128];
  UINTN           BinStr6Size;

  HashSize = GetSpdmHashSize (SpdmContext);
  KeyLength = GetSpdmAeadKeySize (SpdmContext);
  IvLength = GetSpdmAeadIvSize (SpdmContext);
  
  BinStr5Size = sizeof(BinStr5);
  Status = BinConcat (BIN_STR_5_LABEL, sizeof(BIN_STR_5_LABEL), NULL, (UINT16)KeyLength, HashSize, BinStr5, &BinStr5Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr5 (0x%x):\n", BinStr5Size));
  InternalDumpHex (BinStr5, BinStr5Size);
  RetVal = SpdmHkdfExpand (SpdmContext, MajorSecret, HashSize, BinStr5, BinStr5Size, Key, KeyLength);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "Key (0x%x) - ", KeyLength));
  InternalDumpData (Key, KeyLength);
  DEBUG((DEBUG_INFO, "\n"));
  
  BinStr6Size = sizeof(BinStr6);
  Status = BinConcat (BIN_STR_6_LABEL, sizeof(BIN_STR_6_LABEL), NULL, (UINT16)IvLength, HashSize, BinStr6, &BinStr6Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr6 (0x%x):\n", BinStr6Size));
  InternalDumpHex (BinStr6, BinStr6Size);
  RetVal = SpdmHkdfExpand (SpdmContext, MajorSecret, HashSize, BinStr6, BinStr6Size, Iv, IvLength);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "Iv (0x%x) - ", IvLength));
  InternalDumpData (Iv, IvLength);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}

/**
  This function generates SPDM FinishedKey for a session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  HandshakeSecret              The handshake secret.
  @param  FinishedKey                  The buffer to store the finished key.

  @retval RETURN_SUCCESS  SPDM FinishedKey for a session is generated.
**/
RETURN_STATUS
SpdmGenerateFinishedKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        *HandshakeSecret,
  OUT UINT8                       *FinishedKey
  )
{
  RETURN_STATUS   Status;
  BOOLEAN         RetVal;
  UINTN           HashSize;
  UINT8           BinStr7[128];
  UINTN           BinStr7Size;

  HashSize = GetSpdmHashSize (SpdmContext);

  BinStr7Size = sizeof(BinStr7);
  Status = BinConcat (BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr7, &BinStr7Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr7 (0x%x):\n", BinStr7Size));
  InternalDumpHex (BinStr7, BinStr7Size);
  RetVal = SpdmHkdfExpand (SpdmContext, HandshakeSecret, HashSize, BinStr7, BinStr7Size, FinishedKey, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "FinishedKey (0x%x) - ", HashSize));
  InternalDumpData (FinishedKey, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}

/**
  This function generates SPDM HandshakeKey for a session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.

  @retval RETURN_SUCCESS  SPDM HandshakeKey for a session is generated.
**/
RETURN_STATUS
SpdmGenerateSessionHandshakeKey (
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
  UINT8                          *CertBuffer;
  UINTN                          CertBufferSize;
  UINT8                          CertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER           TH1;
  SPDM_SESSION_INFO              *SessionInfo;

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionHandshakeKey[%x]\n", SessionId));

  InitManagedBuffer (&TH1, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  HashSize = GetSpdmHashSize (SpdmContext);

  SessionInfo->HashSize = HashSize;
  SessionInfo->AeadKeySize = GetSpdmAeadKeySize(SpdmContext);
  SessionInfo->AeadIvSize = GetSpdmAeadIvSize(SpdmContext);;

  if (IsRequester) {
    ASSERT (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0);
    CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    ASSERT (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize != 0);
    CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  }
  SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  if (SessionInfo->UsePsk) {
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  } else {
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    AppendManagedBuffer (&TH1, CertBufferHash, HashSize);
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  }
  
  SpdmHashAll (SpdmContext, GetManagedBuffer(&TH1), GetManagedBufferSize(&TH1), TH1HashData);
  DEBUG((DEBUG_INFO, "TH1 Hash - "));
  InternalDumpData (TH1HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  
  BinStr0Size = sizeof(BinStr0);
  Status = BinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr0 (0x%x):\n", BinStr0Size));
  InternalDumpHex (BinStr0, BinStr0Size);

  if (SessionInfo->UsePsk) {
    // No HandshakeSecret generation for PSK.
  } else {
    RetVal = SpdmHmacAll (SpdmContext, mZeroFilledBuffer, HashSize, SessionInfo->MasterSecret.DheSecret, SessionInfo->DheKeySize, SessionInfo->MasterSecret.HandshakeSecret);
    ASSERT (RetVal);
    DEBUG((DEBUG_INFO, "HandshakeSecret (0x%x) - ", HashSize));
    InternalDumpData (SessionInfo->MasterSecret.HandshakeSecret, HashSize);
    DEBUG((DEBUG_INFO, "\n"));
  }

  BinStr1Size = sizeof(BinStr1);
  Status = BinConcat (BIN_STR_1_LABEL, sizeof(BIN_STR_1_LABEL), TH1HashData, (UINT16)HashSize, HashSize, BinStr1, &BinStr1Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr1 (0x%x):\n", BinStr1Size));
  InternalDumpHex (BinStr1, BinStr1Size);
  if (SessionInfo->UsePsk) {
    ASSERT (SpdmContext->LocalContext.SpdmPskHandshakeSecretHkdfExpandFunc != NULL);
    if (SpdmContext->LocalContext.SpdmPskHandshakeSecretHkdfExpandFunc == NULL) {
      return RETURN_UNSUPPORTED;
    }
    RetVal = SpdmContext->LocalContext.SpdmPskHandshakeSecretHkdfExpandFunc (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize, BinStr1, BinStr1Size, SessionInfo->HandshakeSecret.RequestHandshakeSecret, HashSize);
  } else {
    RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.HandshakeSecret, HashSize, BinStr1, BinStr1Size, SessionInfo->HandshakeSecret.RequestHandshakeSecret, HashSize);
  }
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "RequestHandshakeSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->HandshakeSecret.RequestHandshakeSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  BinStr2Size = sizeof(BinStr2);
  Status = BinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL), TH1HashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr2 (0x%x):\n", BinStr2Size));
  InternalDumpHex (BinStr2, BinStr2Size);
  if (SessionInfo->UsePsk) {
    ASSERT (SpdmContext->LocalContext.SpdmPskHandshakeSecretHkdfExpandFunc != NULL);
    if (SpdmContext->LocalContext.SpdmPskHandshakeSecretHkdfExpandFunc == NULL) {
      return RETURN_UNSUPPORTED;
    }
    RetVal = SpdmContext->LocalContext.SpdmPskHandshakeSecretHkdfExpandFunc (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize, BinStr2, BinStr2Size, SessionInfo->HandshakeSecret.ResponseHandshakeSecret, HashSize);
  } else {
    RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.HandshakeSecret, HashSize, BinStr2, BinStr2Size, SessionInfo->HandshakeSecret.ResponseHandshakeSecret, HashSize);
  }
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

/**
  This function generates SPDM DataKey for a session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.

  @retval RETURN_SUCCESS  SPDM DataKey for a session is generated.
**/
RETURN_STATUS
SpdmGenerateSessionDataKey (
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
  UINT8                          *CertBuffer;
  UINTN                          CertBufferSize;
  UINT8                          CertBufferHash[MAX_HASH_SIZE];
  UINT8                          *MutCertBuffer;
  UINTN                          MutCertBufferSize;
  UINT8                          MutCertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER           TH2;
  SPDM_SESSION_INFO              *SessionInfo;

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionDataKey[%x]\n", SessionId));

  InitManagedBuffer (&TH2, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  ASSERT (SessionInfo->HashSize != 0);

  HashSize = GetSpdmHashSize (SpdmContext);

  if (IsRequester) {
    ASSERT (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0);
    CertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
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
      ASSERT (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0);
      MutCertBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
      MutCertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    }
    SpdmHashAll (SpdmContext, MutCertBuffer, MutCertBufferSize, MutCertBufferHash);
  }

  if (SessionInfo->UsePsk) {
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));
  } else {
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    AppendManagedBuffer (&TH2, CertBufferHash, HashSize);
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
    if (SessionInfo->MutAuthRequested) {
      AppendManagedBuffer (&TH2, MutCertBufferHash, HashSize);
    }
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));
  }
  SpdmHashAll (SpdmContext, GetManagedBuffer(&TH2), GetManagedBufferSize(&TH2), TH2HashData);
  DEBUG((DEBUG_INFO, "TH2 Hash - "));
  InternalDumpData (TH2HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  
  if (SessionInfo->UsePsk) {
    // No MasterSecret generation for PSK.
  } else {
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
  }

  BinStr3Size = sizeof(BinStr3);
  Status = BinConcat (BIN_STR_3_LABEL, sizeof(BIN_STR_3_LABEL), TH2HashData, (UINT16)HashSize, HashSize, BinStr3, &BinStr3Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr3 (0x%x):\n", BinStr3Size));
  InternalDumpHex (BinStr3, BinStr3Size);
  if (SessionInfo->UsePsk) {
    ASSERT (SpdmContext->LocalContext.SpdmPskMasterSecretHkdfExpandFunc != NULL);
    if (SpdmContext->LocalContext.SpdmPskMasterSecretHkdfExpandFunc == NULL) {
      return RETURN_UNSUPPORTED;
    }
    RetVal = SpdmContext->LocalContext.SpdmPskMasterSecretHkdfExpandFunc (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize, BinStr3, BinStr3Size, SessionInfo->ApplicationSecret.RequestDataSecret, HashSize);
  } else {
    RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.MasterSecret, HashSize, BinStr3, BinStr3Size, SessionInfo->ApplicationSecret.RequestDataSecret, HashSize);
  }
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "RequestDataSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->ApplicationSecret.RequestDataSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  BinStr4Size = sizeof(BinStr4);
  Status = BinConcat (BIN_STR_4_LABEL, sizeof(BIN_STR_4_LABEL), TH2HashData, (UINT16)HashSize, HashSize, BinStr4, &BinStr4Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr4 (0x%x):\n", BinStr4Size));
  InternalDumpHex (BinStr4, BinStr4Size);
  if (SessionInfo->UsePsk) {
    ASSERT (SpdmContext->LocalContext.SpdmPskMasterSecretHkdfExpandFunc != NULL);
    if (SpdmContext->LocalContext.SpdmPskMasterSecretHkdfExpandFunc == NULL) {
      return RETURN_UNSUPPORTED;
    }
    RetVal = SpdmContext->LocalContext.SpdmPskMasterSecretHkdfExpandFunc (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize, BinStr4, BinStr4Size, SessionInfo->ApplicationSecret.ResponseDataSecret, HashSize);
  } else {
    RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.MasterSecret, HashSize, BinStr4, BinStr4Size, SessionInfo->ApplicationSecret.ResponseDataSecret, HashSize);
  }
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "ResponseDataSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->ApplicationSecret.ResponseDataSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  BinStr8Size = sizeof(BinStr8);
  Status = BinConcat (BIN_STR_8_LABEL, sizeof(BIN_STR_8_LABEL), TH2HashData, (UINT16)HashSize, HashSize, BinStr8, &BinStr8Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr8 (0x%x):\n", BinStr8Size));
  InternalDumpHex (BinStr8, BinStr8Size);
  if (SessionInfo->UsePsk) {
    ASSERT (SpdmContext->LocalContext.SpdmPskMasterSecretHkdfExpandFunc != NULL);
    if (SpdmContext->LocalContext.SpdmPskMasterSecretHkdfExpandFunc == NULL) {
      return RETURN_UNSUPPORTED;
    }
    RetVal = SpdmContext->LocalContext.SpdmPskMasterSecretHkdfExpandFunc (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize, BinStr8, BinStr8Size, SessionInfo->HandshakeSecret.ExportMasterSecret, HashSize);
  } else {
    RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->MasterSecret.MasterSecret, HashSize, BinStr8, BinStr8Size, SessionInfo->HandshakeSecret.ExportMasterSecret, HashSize);
  }
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

/**
  This function creates the updates of SPDM DataKey for a session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
  @param  Action                       Indicate of the key update action.

  @retval RETURN_SUCCESS  SPDM DataKey update is created.
**/
RETURN_STATUS
SpdmCreateUpdateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN SPDM_KEY_UPDATE_ACTION       Action
  )
{
  RETURN_STATUS                  Status;
  BOOLEAN                        RetVal;
  UINTN                          HashSize;
  UINT8                          BinStr9[128];
  UINTN                          BinStr9Size;
  SPDM_SESSION_INFO              *SessionInfo;

  DEBUG ((DEBUG_INFO, "SpdmCreateUpdateSessionDataKey[%x]\n", SessionId));

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  ASSERT (SessionInfo->HashSize != 0);

  HashSize = GetSpdmHashSize (SpdmContext);

  BinStr9Size = sizeof(BinStr9);
  Status = BinConcat (BIN_STR_9_LABEL, sizeof(BIN_STR_9_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr9, &BinStr9Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr9 (0x%x):\n", BinStr9Size));
  InternalDumpHex (BinStr9, BinStr9Size);

  if ((Action & SpdmKeyUpdateActionRequester) != 0) {
    CopyMem (&SessionInfo->ApplicationSecretBackup.RequestDataSecret, &SessionInfo->ApplicationSecret.RequestDataSecret, MAX_HASH_SIZE);
    CopyMem (&SessionInfo->ApplicationSecretBackup.RequestDataEncryptionKey, &SessionInfo->ApplicationSecret.RequestDataEncryptionKey, MAX_AEAD_KEY_SIZE);
    CopyMem (&SessionInfo->ApplicationSecretBackup.RequestDataSalt, &SessionInfo->ApplicationSecret.RequestDataSalt, MAX_AEAD_IV_SIZE);
    SessionInfo->ApplicationSecretBackup.RequestDataSequenceNumber = SessionInfo->ApplicationSecret.RequestDataSequenceNumber;

    RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->ApplicationSecret.RequestDataSecret, HashSize, BinStr9, BinStr9Size, SessionInfo->ApplicationSecret.RequestDataSecret, HashSize);
    ASSERT (RetVal);
    DEBUG((DEBUG_INFO, "RequestDataSecretUpdate (0x%x) - ", HashSize));
    InternalDumpData (SessionInfo->ApplicationSecret.RequestDataSecret, HashSize);
    DEBUG((DEBUG_INFO, "\n"));

    SpdmGenerateAeadKeyAndIv (
      SpdmContext,
      SessionInfo->ApplicationSecret.RequestDataSecret,
      SessionInfo->ApplicationSecret.RequestDataEncryptionKey,
      SessionInfo->ApplicationSecret.RequestDataSalt
      );
    SessionInfo->ApplicationSecret.RequestDataSequenceNumber = 0;
  }

  if ((Action & SpdmKeyUpdateActionResponder) != 0) {
    CopyMem (&SessionInfo->ApplicationSecretBackup.ResponseDataSecret, &SessionInfo->ApplicationSecret.ResponseDataSecret, MAX_HASH_SIZE);
    CopyMem (&SessionInfo->ApplicationSecretBackup.ResponseDataEncryptionKey, &SessionInfo->ApplicationSecret.ResponseDataEncryptionKey, MAX_AEAD_KEY_SIZE);
    CopyMem (&SessionInfo->ApplicationSecretBackup.ResponseDataSalt, &SessionInfo->ApplicationSecret.ResponseDataSalt, MAX_AEAD_IV_SIZE);
    SessionInfo->ApplicationSecretBackup.ResponseDataSequenceNumber = SessionInfo->ApplicationSecret.ResponseDataSequenceNumber;

    RetVal = SpdmHkdfExpand (SpdmContext, SessionInfo->ApplicationSecret.ResponseDataSecret, HashSize, BinStr9, BinStr9Size, SessionInfo->ApplicationSecret.ResponseDataSecret, HashSize);
    ASSERT (RetVal);
    DEBUG((DEBUG_INFO, "ResponseDataSecretUpdate (0x%x) - ", HashSize));
    InternalDumpData (SessionInfo->ApplicationSecret.ResponseDataSecret, HashSize);
    DEBUG((DEBUG_INFO, "\n"));

    SpdmGenerateAeadKeyAndIv (
      SpdmContext,
      SessionInfo->ApplicationSecret.ResponseDataSecret,
      SessionInfo->ApplicationSecret.ResponseDataEncryptionKey,
      SessionInfo->ApplicationSecret.ResponseDataSalt
      );
    SessionInfo->ApplicationSecret.ResponseDataSequenceNumber = 0;
  }
  return RETURN_SUCCESS;
}

/**
  This function activates the update of SPDM DataKey for a session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
  @param  Action                       Indicate of the key update action.
  @param  UseNewKey                    Indicate if the new key should be used.

  @retval RETURN_SUCCESS  SPDM DataKey update is activated.
**/
RETURN_STATUS
SpdmActivateUpdateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN SPDM_KEY_UPDATE_ACTION       Action,
  IN BOOLEAN                      UseNewKey
  )
{
  SPDM_SESSION_INFO              *SessionInfo;

  DEBUG ((DEBUG_INFO, "SpdmActivateUpdateSessionDataKey[%x]\n", SessionId));

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  if (!UseNewKey) {
    if ((Action & SpdmKeyUpdateActionRequester) != 0) {
      CopyMem (&SessionInfo->ApplicationSecret.RequestDataSecret, &SessionInfo->ApplicationSecretBackup.RequestDataSecret, MAX_HASH_SIZE);
      CopyMem (&SessionInfo->ApplicationSecret.RequestDataEncryptionKey, &SessionInfo->ApplicationSecretBackup.RequestDataEncryptionKey, MAX_AEAD_KEY_SIZE);
      CopyMem (&SessionInfo->ApplicationSecret.RequestDataSalt, &SessionInfo->ApplicationSecretBackup.RequestDataSalt, MAX_AEAD_IV_SIZE);
      SessionInfo->ApplicationSecret.RequestDataSequenceNumber = SessionInfo->ApplicationSecretBackup.RequestDataSequenceNumber;
    }
    if ((Action & SpdmKeyUpdateActionResponder) != 0) {
      CopyMem (&SessionInfo->ApplicationSecret.ResponseDataSecret, &SessionInfo->ApplicationSecretBackup.ResponseDataSecret, MAX_HASH_SIZE);
      CopyMem (&SessionInfo->ApplicationSecret.ResponseDataEncryptionKey, &SessionInfo->ApplicationSecretBackup.ResponseDataEncryptionKey, MAX_AEAD_KEY_SIZE);
      CopyMem (&SessionInfo->ApplicationSecret.ResponseDataSalt, &SessionInfo->ApplicationSecretBackup.ResponseDataSalt, MAX_AEAD_IV_SIZE);
      SessionInfo->ApplicationSecret.ResponseDataSequenceNumber = SessionInfo->ApplicationSecretBackup.ResponseDataSequenceNumber;
    }
  }

  if ((Action & SpdmKeyUpdateActionRequester) != 0) {
    ZeroMem (&SessionInfo->ApplicationSecretBackup.RequestDataSecret, MAX_HASH_SIZE);
    ZeroMem (&SessionInfo->ApplicationSecretBackup.RequestDataEncryptionKey, MAX_AEAD_KEY_SIZE);
    ZeroMem (&SessionInfo->ApplicationSecretBackup.RequestDataSalt, MAX_AEAD_IV_SIZE);
    SessionInfo->ApplicationSecretBackup.RequestDataSequenceNumber = 0;
  }
  if ((Action & SpdmKeyUpdateActionResponder) != 0) {
    ZeroMem (&SessionInfo->ApplicationSecretBackup.ResponseDataSecret, MAX_HASH_SIZE);
    ZeroMem (&SessionInfo->ApplicationSecretBackup.ResponseDataEncryptionKey, MAX_AEAD_KEY_SIZE);
    ZeroMem (&SessionInfo->ApplicationSecretBackup.ResponseDataSalt, MAX_AEAD_IV_SIZE);
    SessionInfo->ApplicationSecretBackup.ResponseDataSequenceNumber = 0;
  }
  return RETURN_SUCCESS;
}
