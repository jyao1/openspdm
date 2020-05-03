/** @file
  EDKII Device Security library for SPDM device.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

#define BIN_CONCAT_LABEL "spdm1.1"
#define BIN_STR_0_LABEL  "derived"
#define BIN_STR_1_LABEL  "requester traffic"
#define BIN_STR_2_LABEL  "responder traffic"
#define BIN_STR_3_LABEL  "requester app traffic"
#define BIN_STR_4_LABEL  "responder app traffic"
#define BIN_STR_5_LABEL  "key"
#define BIN_STR_6_LABEL  "iv"
#define BIN_STR_7_LABEL  "finished"
#define BIN_STR_8_LABEL  "traffic upd"

GLOBAL_REMOVE_IF_UNREFERENCED UINT8  mZeroFilledBuffer[64];

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
  HKDF_EXPAND     HkdfExpandFunc;
  UINTN           HashSize;
  UINTN           KeyLength;
  UINTN           IvLength;
  UINT8           BinStr5[128];
  UINTN           BinStr5Size;
  UINT8           BinStr6[128];
  UINTN           BinStr6Size;

  HkdfExpandFunc = GetSpdmHkdfExpandFunc (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);
  KeyLength = GetSpdmAeadKeySize (SpdmContext);
  IvLength = GetSpdmAeadIvSize (SpdmContext);
  
  BinStr5Size = sizeof(BinStr5);
  Status = BinConcat (BIN_STR_5_LABEL, sizeof(BIN_STR_5_LABEL), NULL, (UINT16)KeyLength, HashSize, BinStr5, &BinStr5Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr5 (0x%x):\n", BinStr5Size));
  InternalDumpHex (BinStr5, BinStr5Size);
  RetVal = HkdfExpandFunc (MajorSecret, HashSize, BinStr5, BinStr5Size, Key, KeyLength);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "Key (0x%x) - ", KeyLength));
  InternalDumpData (Key, KeyLength);
  DEBUG((DEBUG_INFO, "\n"));
  
  BinStr6Size = sizeof(BinStr6);
  Status = BinConcat (BIN_STR_6_LABEL, sizeof(BIN_STR_6_LABEL), NULL, (UINT16)IvLength, HashSize, BinStr6, &BinStr6Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr6 (0x%x):\n", BinStr6Size));
  InternalDumpHex (BinStr6, BinStr6Size);
  RetVal = HkdfExpandFunc (MajorSecret, HashSize, BinStr6, BinStr6Size, Iv, IvLength);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "Iv (0x%x) - ", IvLength));
  InternalDumpData (Iv, IvLength);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmGenerateFinalKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        *HandshakeSecret,
  OUT UINT8                       *FinishedKey
  )
{
  RETURN_STATUS   Status;
  BOOLEAN         RetVal;
  HKDF_EXPAND     HkdfExpandFunc;
  UINTN           HashSize;
  UINT8           BinStr7[128];
  UINTN           BinStr7Size;

  HkdfExpandFunc = GetSpdmHkdfExpandFunc (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  BinStr7Size = sizeof(BinStr7);
  Status = BinConcat (BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr7, &BinStr7Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr7 (0x%x):\n", BinStr7Size));
  InternalDumpHex (BinStr7, BinStr7Size);
  RetVal = HkdfExpandFunc (HandshakeSecret, HashSize, BinStr7, BinStr7Size, FinishedKey, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "FinishedKey (0x%x) - ", HashSize));
  InternalDumpData (FinishedKey, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}

/**
  This function generate SPDM HandshakeKey.

  @param[in]  SpdmContext            The SPDM context for the device.
**/
RETURN_STATUS
SpdmGenerateSessionHandshakeKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        SessionId
  )
{
  RETURN_STATUS                  Status;
  BOOLEAN                        RetVal;
  HASH_ALL                       HashFunc;
  HMAC_ALL                       HmacFunc;
  HKDF_EXPAND                    HkdfExpandFunc;
  UINTN                          HashSize;
  UINT8                          TH1HashData[64];
  UINT8                          Secret0[64];
  UINT8                          Salt0[64];
  UINT8                          BinStr0[128];
  UINTN                          BinStr0Size;
  UINT8                          BinStr1[128];
  UINTN                          BinStr1Size;
  UINT8                          BinStr2[128];
  UINTN                          BinStr2Size;
  UINT8                          *CertBuffer;
  UINTN                          CertBufferSize;
  LARGE_MANAGED_BUFFER           TH1 = {MAX_SPDM_MESSAGE_BUFFER_SIZE};
  UINT8                          SlotNum;
  SPDM_SESSION_INFO              *SessionInfo;
  
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  ASSERT ((SessionInfo->DheKeySize != 0) || (SpdmContext->LocalContext.PskSize != 0));
  
  HashFunc = GetSpdmHashFunc (SpdmContext);
  HmacFunc = GetSpdmHmacFunc (SpdmContext);
  HkdfExpandFunc = GetSpdmHkdfExpandFunc (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  SlotNum = 0;

  SessionInfo->HashSize = HashSize;
  SessionInfo->AeadKeySize = GetSpdmAeadKeySize(SpdmContext);
  SessionInfo->AeadIvSize = GetSpdmAeadIvSize(SpdmContext);;

  // TBD - cert chain
  if (SpdmContext->LocalContext.SpdmCertChainVarBuffer != NULL) {
    //
    // Requester
    //
    ASSERT ((SpdmContext->LocalContext.SpdmCertChainVarBuffer != NULL) && (SpdmContext->LocalContext.SpdmCertChainVarBufferSize != 0));
    CertBuffer = (UINT8 *)SpdmContext->LocalContext.SpdmCertChainVarBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->LocalContext.SpdmCertChainVarBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    //
    // Responder
    //
    ASSERT ((SpdmContext->LocalContext.CertificateChain[SlotNum] != NULL) && (SpdmContext->LocalContext.CertificateChainSize[SlotNum] != 0));
    CertBuffer = (UINT8 *)SpdmContext->LocalContext.CertificateChain[SlotNum] + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->LocalContext.CertificateChainSize[SlotNum] - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  }

  if (SessionInfo->UsePsk) {
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SpdmContext->Transcript.MessagePK), GetManagedBufferSize(&SpdmContext->Transcript.MessagePK));
  } else {
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    AppendManagedBuffer (&TH1, CertBuffer, CertBufferSize);
    AppendManagedBuffer (&TH1, GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK));
  }
  
  HashFunc (GetManagedBuffer(&TH1), GetManagedBufferSize(&TH1), TH1HashData);
  DEBUG((DEBUG_INFO, "TH1 Hash - "));
  InternalDumpData (TH1HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  
  RetVal = HmacFunc (mZeroFilledBuffer, HashSize, mZeroFilledBuffer, HashSize, Secret0);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "Secret0 (0x%x) - ", HashSize));
  InternalDumpData (Secret0, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  BinStr0Size = sizeof(BinStr0);
  Status = BinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr0 (0x%x):\n", BinStr0Size));
  InternalDumpHex (BinStr0, BinStr0Size);
  RetVal = HkdfExpandFunc (Secret0, HashSize, BinStr0, BinStr0Size, Salt0, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "Salt0 (0x%x) - ", HashSize));
  InternalDumpData (Salt0, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (SessionInfo->UsePsk) {
    RetVal = HmacFunc (SpdmContext->LocalContext.Psk, SpdmContext->LocalContext.PskSize, Salt0, HashSize, SessionInfo->HandshakeSecret);
  } else {
    RetVal = HmacFunc (SessionInfo->DheSecret, SessionInfo->DheKeySize, Salt0, HashSize, SessionInfo->HandshakeSecret);
  }
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "HandshakeSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->HandshakeSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  BinStr1Size = sizeof(BinStr1);
  Status = BinConcat (BIN_STR_1_LABEL, sizeof(BIN_STR_1_LABEL), TH1HashData, (UINT16)HashSize, HashSize, BinStr1, &BinStr1Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr1 (0x%x):\n", BinStr1Size));
  InternalDumpHex (BinStr1, BinStr1Size);
  RetVal = HkdfExpandFunc (SessionInfo->HandshakeSecret, HashSize, BinStr1, BinStr1Size, SessionInfo->RequestHandshakeSecret, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "RequestHandshakeSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->RequestHandshakeSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  BinStr2Size = sizeof(BinStr2);
  Status = BinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL), TH1HashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr2 (0x%x):\n", BinStr2Size));
  InternalDumpHex (BinStr2, BinStr2Size);
  RetVal = HkdfExpandFunc (SessionInfo->HandshakeSecret, HashSize, BinStr2, BinStr2Size, SessionInfo->ResponseHandshakeSecret, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "ResponseHandshakeSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->ResponseHandshakeSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  SpdmGenerateFinalKey (
    SpdmContext,
    SessionInfo->RequestHandshakeSecret,
    SessionInfo->RequestFinishedKey
    );

  SpdmGenerateFinalKey (
    SpdmContext,
    SessionInfo->ResponseHandshakeSecret,
    SessionInfo->ResponseFinishedKey
    );

  SpdmGenerateAeadKeyAndIv (
    SpdmContext,
    SessionInfo->RequestHandshakeSecret,
    SessionInfo->RequestHandshakeEncryptionKey,
    SessionInfo->RequestHandshakeSalt
    );
  SessionInfo->RequestHandshakeSequenceNumber = 0;

  SpdmGenerateAeadKeyAndIv (
    SpdmContext,
    SessionInfo->ResponseHandshakeSecret,
    SessionInfo->ResponseHandshakeEncryptionKey,
    SessionInfo->ResponseHandshakeSalt
    );
  SessionInfo->ResponseHandshakeSequenceNumber = 0;

  return RETURN_SUCCESS;
}

/**
  This function generate SPDM DataKey.

  @param[in]  SpdmContext            The SPDM context for the device.
**/
RETURN_STATUS
SpdmGenerateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        SessionId
  )
{  
  RETURN_STATUS                  Status;
  BOOLEAN                        RetVal;
  HASH_ALL                       HashFunc;
  HMAC_ALL                       HmacFunc;
  HKDF_EXPAND                    HkdfExpandFunc;
  UINTN                          HashSize;
  UINT8                          TH2HashData[64];
  UINT8                          Salt1[64];
  UINT8                          BinStr0[128];
  UINTN                          BinStr0Size;
  UINT8                          BinStr3[128];
  UINTN                          BinStr3Size;
  UINT8                          BinStr4[128];
  UINTN                          BinStr4Size;
  UINT8                          *CertBuffer;
  UINTN                          CertBufferSize;
  LARGE_MANAGED_BUFFER           TH2 = {MAX_SPDM_MESSAGE_BUFFER_SIZE};
  UINT8                          SlotNum;
  SPDM_SESSION_INFO              *SessionInfo;
  
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  ASSERT ((SessionInfo->DheKeySize != 0) || (SpdmContext->LocalContext.PskSize != 0));
  ASSERT (SessionInfo->HashSize != 0);
  
  HashFunc = GetSpdmHashFunc (SpdmContext);
  HmacFunc = GetSpdmHmacFunc (SpdmContext);
  HkdfExpandFunc = GetSpdmHkdfExpandFunc (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  SlotNum = 0;

  // TBD - cert chain
  if (SpdmContext->LocalContext.SpdmCertChainVarBuffer != NULL) {
    //
    // Requester
    //
    ASSERT ((SpdmContext->LocalContext.SpdmCertChainVarBuffer != NULL) && (SpdmContext->LocalContext.SpdmCertChainVarBufferSize != 0));
    CertBuffer = (UINT8 *)SpdmContext->LocalContext.SpdmCertChainVarBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->LocalContext.SpdmCertChainVarBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    //
    // Responder
    //
    ASSERT ((SpdmContext->LocalContext.CertificateChain[SlotNum] != NULL) && (SpdmContext->LocalContext.CertificateChainSize[SlotNum] != 0));
    CertBuffer = (UINT8 *)SpdmContext->LocalContext.CertificateChain[SlotNum] + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = SpdmContext->LocalContext.CertificateChainSize[SlotNum] - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  }

  if (SessionInfo->UsePsk) {
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SpdmContext->Transcript.MessagePK), GetManagedBufferSize(&SpdmContext->Transcript.MessagePK));
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SpdmContext->Transcript.MessagePF), GetManagedBufferSize(&SpdmContext->Transcript.MessagePF));
  } else {
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    AppendManagedBuffer (&TH2, CertBuffer, CertBufferSize);
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK));
    AppendManagedBuffer (&TH2, GetManagedBuffer(&SpdmContext->Transcript.MessageF), GetManagedBufferSize(&SpdmContext->Transcript.MessageF));
  }
  HashFunc (GetManagedBuffer(&TH2), GetManagedBufferSize(&TH2), TH2HashData);
  DEBUG((DEBUG_INFO, "TH2 Hash - "));
  InternalDumpData (TH2HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  
  BinStr0Size = sizeof(BinStr0);
  Status = BinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
  ASSERT_RETURN_ERROR (Status);
  RetVal = HkdfExpandFunc (SessionInfo->HandshakeSecret, HashSize, BinStr0, BinStr0Size, Salt1, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "Salt1 (0x%x) - ", HashSize));
  InternalDumpData (Salt1, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  RetVal = HmacFunc (mZeroFilledBuffer, HashSize, Salt1, HashSize, SessionInfo->MasterSecret);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "MasterSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->MasterSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  BinStr3Size = sizeof(BinStr3);
  Status = BinConcat (BIN_STR_3_LABEL, sizeof(BIN_STR_3_LABEL), TH2HashData, (UINT16)HashSize, HashSize, BinStr3, &BinStr3Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr3 (0x%x):\n", BinStr3Size));
  InternalDumpHex (BinStr3, BinStr3Size);
  RetVal = HkdfExpandFunc (SessionInfo->MasterSecret, HashSize, BinStr3, BinStr3Size, SessionInfo->RequestDataSecret, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "RequestDataSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->RequestDataSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  BinStr4Size = sizeof(BinStr4);
  Status = BinConcat (BIN_STR_4_LABEL, sizeof(BIN_STR_4_LABEL), TH2HashData, (UINT16)HashSize, HashSize, BinStr4, &BinStr4Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr4 (0x%x):\n", BinStr4Size));
  InternalDumpHex (BinStr4, BinStr4Size);
  RetVal = HkdfExpandFunc (SessionInfo->MasterSecret, HashSize, BinStr4, BinStr4Size, SessionInfo->ResponseDataSecret, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "ResponseDataSecret (0x%x) - ", HashSize));
  InternalDumpData (SessionInfo->ResponseDataSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  SpdmGenerateAeadKeyAndIv (
    SpdmContext,
    SessionInfo->RequestDataSecret,
    SessionInfo->RequestDataEncryptionKey,
    SessionInfo->RequestDataSalt
    );
  SessionInfo->RequestDataSequenceNumber = 0;

  SpdmGenerateAeadKeyAndIv (
    SpdmContext,
    SessionInfo->ResponseDataSecret,
    SessionInfo->ResponseDataEncryptionKey,
    SessionInfo->ResponseDataSalt
    );
  SessionInfo->ResponseDataSequenceNumber = 0;

  return RETURN_SUCCESS;
}
