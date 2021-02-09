/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmSecuredMessageLibInternal.h"

GLOBAL_REMOVE_IF_UNREFERENCED UINT8  mZeroFilledBuffer[64];

/**
  This function dump raw data.

  @param  Data  raw data
  @param  Size  raw data size
**/
VOID
InternalDumpHexStr (
  IN UINT8  *Data,
  IN UINTN  Size
  );

/**
  This function dump raw data.

  @param  Data  raw data
  @param  Size  raw data size
**/
VOID
InternalDumpData (
  IN UINT8  *Data,
  IN UINTN  Size
  );

/**
  This function dump raw data with colume format.

  @param  Data  raw data
  @param  Size  raw data size
**/
VOID
InternalDumpHex (
  IN UINT8  *Data,
  IN UINTN  Size
  );

/**
  This function concatenates binary data, which is used as Info in HKDF expand later.

  @param  Label                        An ascii string label for the SpdmBinConcat.
  @param  LabelSize                    The size in bytes of the ASCII string label, including the NULL terminator.
  @param  Context                      A pre-defined hash value as the context for the SpdmBinConcat.
  @param  Length                       16 bits length for the SpdmBinConcat.
  @param  HashSize                     The size in bytes of the context hash.
  @param  OutBin                       The buffer to store the output binary.
  @param  OutBinSize                   The size in bytes for the OutBin.

  @retval RETURN_SUCCESS               The binary SpdmBinConcat data is generated.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmBinConcat (
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

  FinalSize = sizeof(UINT16) + sizeof(BIN_CONCAT_LABEL) - 1 + LabelSize;
  if (Context != NULL) {
    FinalSize += HashSize;
  }
  if (*OutBinSize < FinalSize) {
    *OutBinSize = FinalSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  
  *OutBinSize = FinalSize;

  CopyMem (OutBin, &Length, sizeof(UINT16));
  CopyMem (OutBin + sizeof(UINT16), BIN_CONCAT_LABEL, sizeof(BIN_CONCAT_LABEL) - 1);
  CopyMem (OutBin + sizeof(UINT16) + sizeof(BIN_CONCAT_LABEL) - 1, Label, LabelSize);
  if (Context != NULL) {
    CopyMem (OutBin + sizeof(UINT16) + sizeof(BIN_CONCAT_LABEL) - 1 + LabelSize, Context, HashSize);
  }

  return RETURN_SUCCESS;
}

/**
  This function generates SPDM AEAD Key and IV for a session.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  MajorSecret                  The major secret.
  @param  Key                          The buffer to store the AEAD key.
  @param  Iv                           The buffer to store the AEAD IV.

  @retval RETURN_SUCCESS  SPDM AEAD key and IV for a session is generated.
**/
RETURN_STATUS
SpdmGenerateAeadKeyAndIv (
  IN SPDM_SECURED_MESSAGE_CONTEXT *SecuredMessageContext,
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

  HashSize = SecuredMessageContext->HashSize;
  KeyLength = SecuredMessageContext->AeadKeySize;
  IvLength = SecuredMessageContext->AeadIvSize;
  
  BinStr5Size = sizeof(BinStr5);
  Status = SpdmBinConcat (BIN_STR_5_LABEL, sizeof(BIN_STR_5_LABEL) - 1, NULL, (UINT16)KeyLength, HashSize, BinStr5, &BinStr5Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr5 (0x%x):\n", BinStr5Size));
  InternalDumpHex (BinStr5, BinStr5Size);
  RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, MajorSecret, HashSize, BinStr5, BinStr5Size, Key, KeyLength);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "Key (0x%x) - ", KeyLength));
  InternalDumpData (Key, KeyLength);
  DEBUG((DEBUG_INFO, "\n"));
  
  BinStr6Size = sizeof(BinStr6);
  Status = SpdmBinConcat (BIN_STR_6_LABEL, sizeof(BIN_STR_6_LABEL) - 1, NULL, (UINT16)IvLength, HashSize, BinStr6, &BinStr6Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr6 (0x%x):\n", BinStr6Size));
  InternalDumpHex (BinStr6, BinStr6Size);
  RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, MajorSecret, HashSize, BinStr6, BinStr6Size, Iv, IvLength);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "Iv (0x%x) - ", IvLength));
  InternalDumpData (Iv, IvLength);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}

/**
  This function generates SPDM FinishedKey for a session.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  HandshakeSecret              The handshake secret.
  @param  FinishedKey                  The buffer to store the finished key.

  @retval RETURN_SUCCESS  SPDM FinishedKey for a session is generated.
**/
RETURN_STATUS
SpdmGenerateFinishedKey (
  IN SPDM_SECURED_MESSAGE_CONTEXT *SecuredMessageContext,
  IN UINT8                        *HandshakeSecret,
  OUT UINT8                       *FinishedKey
  )
{
  RETURN_STATUS   Status;
  BOOLEAN         RetVal;
  UINTN           HashSize;
  UINT8           BinStr7[128];
  UINTN           BinStr7Size;

  HashSize = SecuredMessageContext->HashSize;

  BinStr7Size = sizeof(BinStr7);
  Status = SpdmBinConcat (BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr7, &BinStr7Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr7 (0x%x):\n", BinStr7Size));
  InternalDumpHex (BinStr7, BinStr7Size);
  RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, HandshakeSecret, HashSize, BinStr7, BinStr7Size, FinishedKey, HashSize);
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "FinishedKey (0x%x) - ", HashSize));
  InternalDumpData (FinishedKey, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  return RETURN_SUCCESS;
}

/**
  This function generates SPDM HandshakeKey for a session.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  TH1HashData                  TH1 hash

  @retval RETURN_SUCCESS  SPDM HandshakeKey for a session is generated.
**/
RETURN_STATUS
EFIAPI
SpdmGenerateSessionHandshakeKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN UINT8                        *TH1HashData
  )
{
  RETURN_STATUS                  Status;
  BOOLEAN                        RetVal;
  UINTN                          HashSize;
  UINT8                          BinStr0[128];
  UINTN                          BinStr0Size;
  UINT8                          BinStr1[128];
  UINTN                          BinStr1Size;
  UINT8                          BinStr2[128];
  UINTN                          BinStr2Size;
  SPDM_SECURED_MESSAGE_CONTEXT   *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;

  HashSize = SecuredMessageContext->HashSize;

  BinStr0Size = sizeof(BinStr0);
  Status = SpdmBinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr0 (0x%x):\n", BinStr0Size));
  InternalDumpHex (BinStr0, BinStr0Size);

  if (SecuredMessageContext->UsePsk) {
    // No HandshakeSecret generation for PSK.
  } else {
    DEBUG((DEBUG_INFO, "[DHE Secret]: "));
    InternalDumpHexStr (SecuredMessageContext->MasterSecret.DheSecret, SecuredMessageContext->DheKeySize);
    DEBUG((DEBUG_INFO, "\n"));
    RetVal = SpdmHmacAll (SecuredMessageContext->BaseHashAlgo, mZeroFilledBuffer, HashSize, SecuredMessageContext->MasterSecret.DheSecret, SecuredMessageContext->DheKeySize, SecuredMessageContext->MasterSecret.HandshakeSecret);
    ASSERT (RetVal);
    DEBUG((DEBUG_INFO, "HandshakeSecret (0x%x) - ", HashSize));
    InternalDumpData (SecuredMessageContext->MasterSecret.HandshakeSecret, HashSize);
    DEBUG((DEBUG_INFO, "\n"));
  }

  BinStr1Size = sizeof(BinStr1);
  Status = SpdmBinConcat (BIN_STR_1_LABEL, sizeof(BIN_STR_1_LABEL) - 1, TH1HashData, (UINT16)HashSize, HashSize, BinStr1, &BinStr1Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr1 (0x%x):\n", BinStr1Size));
  InternalDumpHex (BinStr1, BinStr1Size);
  if (SecuredMessageContext->UsePsk) {
    RetVal = SpdmPskHandshakeSecretHkdfExpandFunc (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->PskHint, SecuredMessageContext->PskHintSize, BinStr1, BinStr1Size, SecuredMessageContext->HandshakeSecret.RequestHandshakeSecret, HashSize);
    if (!RetVal) {
      return RETURN_UNSUPPORTED;
    }
  } else {
    RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->MasterSecret.HandshakeSecret, HashSize, BinStr1, BinStr1Size, SecuredMessageContext->HandshakeSecret.RequestHandshakeSecret, HashSize);
  }
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "RequestHandshakeSecret (0x%x) - ", HashSize));
  InternalDumpData (SecuredMessageContext->HandshakeSecret.RequestHandshakeSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  BinStr2Size = sizeof(BinStr2);
  Status = SpdmBinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1, TH1HashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr2 (0x%x):\n", BinStr2Size));
  InternalDumpHex (BinStr2, BinStr2Size);
  if (SecuredMessageContext->UsePsk) {
    RetVal = SpdmPskHandshakeSecretHkdfExpandFunc (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->PskHint, SecuredMessageContext->PskHintSize, BinStr2, BinStr2Size, SecuredMessageContext->HandshakeSecret.ResponseHandshakeSecret, HashSize);
    if (!RetVal) {
      return RETURN_UNSUPPORTED;
    }
  } else {
    RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->MasterSecret.HandshakeSecret, HashSize, BinStr2, BinStr2Size, SecuredMessageContext->HandshakeSecret.ResponseHandshakeSecret, HashSize);
  }
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "ResponseHandshakeSecret (0x%x) - ", HashSize));
  InternalDumpData (SecuredMessageContext->HandshakeSecret.ResponseHandshakeSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  SpdmGenerateFinishedKey (
    SecuredMessageContext,
    SecuredMessageContext->HandshakeSecret.RequestHandshakeSecret,
    SecuredMessageContext->HandshakeSecret.RequestFinishedKey
    );

  SpdmGenerateFinishedKey (
    SecuredMessageContext,
    SecuredMessageContext->HandshakeSecret.ResponseHandshakeSecret,
    SecuredMessageContext->HandshakeSecret.ResponseFinishedKey
    );

  SpdmGenerateAeadKeyAndIv (
    SecuredMessageContext,
    SecuredMessageContext->HandshakeSecret.RequestHandshakeSecret,
    SecuredMessageContext->HandshakeSecret.RequestHandshakeEncryptionKey,
    SecuredMessageContext->HandshakeSecret.RequestHandshakeSalt
    );
  SecuredMessageContext->HandshakeSecret.RequestHandshakeSequenceNumber = 0;

  SpdmGenerateAeadKeyAndIv (
    SecuredMessageContext,
    SecuredMessageContext->HandshakeSecret.ResponseHandshakeSecret,
    SecuredMessageContext->HandshakeSecret.ResponseHandshakeEncryptionKey,
    SecuredMessageContext->HandshakeSecret.ResponseHandshakeSalt
    );
  SecuredMessageContext->HandshakeSecret.ResponseHandshakeSequenceNumber = 0;

  return RETURN_SUCCESS;
}

/**
  This function generates SPDM DataKey for a session.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  TH2HashData                  TH2 hash

  @retval RETURN_SUCCESS  SPDM DataKey for a session is generated.
**/
RETURN_STATUS
EFIAPI
SpdmGenerateSessionDataKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN UINT8                        *TH2HashData
  )
{
  RETURN_STATUS                  Status;
  BOOLEAN                        RetVal;
  UINTN                          HashSize;
  UINT8                          Salt1[64];
  UINT8                          BinStr0[128];
  UINTN                          BinStr0Size;
  UINT8                          BinStr3[128];
  UINTN                          BinStr3Size;
  UINT8                          BinStr4[128];
  UINTN                          BinStr4Size;
  UINT8                          BinStr8[128];
  UINTN                          BinStr8Size;
  SPDM_SECURED_MESSAGE_CONTEXT   *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;

  HashSize = SecuredMessageContext->HashSize;

  if (SecuredMessageContext->UsePsk) {
    // No MasterSecret generation for PSK.
  } else {
    BinStr0Size = sizeof(BinStr0);
    Status = SpdmBinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
    ASSERT_RETURN_ERROR (Status);
    RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->MasterSecret.HandshakeSecret, HashSize, BinStr0, BinStr0Size, Salt1, HashSize);
    ASSERT (RetVal);
    DEBUG((DEBUG_INFO, "Salt1 (0x%x) - ", HashSize));
    InternalDumpData (Salt1, HashSize);
    DEBUG((DEBUG_INFO, "\n"));

    RetVal = SpdmHmacAll (SecuredMessageContext->BaseHashAlgo, mZeroFilledBuffer, HashSize, Salt1, HashSize, SecuredMessageContext->MasterSecret.MasterSecret);
    ASSERT (RetVal);
    DEBUG((DEBUG_INFO, "MasterSecret (0x%x) - ", HashSize));
    InternalDumpData (SecuredMessageContext->MasterSecret.MasterSecret, HashSize);
    DEBUG((DEBUG_INFO, "\n"));
  }

  BinStr3Size = sizeof(BinStr3);
  Status = SpdmBinConcat (BIN_STR_3_LABEL, sizeof(BIN_STR_3_LABEL) - 1, TH2HashData, (UINT16)HashSize, HashSize, BinStr3, &BinStr3Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr3 (0x%x):\n", BinStr3Size));
  InternalDumpHex (BinStr3, BinStr3Size);
  if (SecuredMessageContext->UsePsk) {
    RetVal = SpdmPskMasterSecretHkdfExpandFunc (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->PskHint, SecuredMessageContext->PskHintSize, BinStr3, BinStr3Size, SecuredMessageContext->ApplicationSecret.RequestDataSecret, HashSize);
    if (!RetVal) {
      return RETURN_UNSUPPORTED;
    }
  } else {
    RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->MasterSecret.MasterSecret, HashSize, BinStr3, BinStr3Size, SecuredMessageContext->ApplicationSecret.RequestDataSecret, HashSize);
  }
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "RequestDataSecret (0x%x) - ", HashSize));
  InternalDumpData (SecuredMessageContext->ApplicationSecret.RequestDataSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  BinStr4Size = sizeof(BinStr4);
  Status = SpdmBinConcat (BIN_STR_4_LABEL, sizeof(BIN_STR_4_LABEL) - 1, TH2HashData, (UINT16)HashSize, HashSize, BinStr4, &BinStr4Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr4 (0x%x):\n", BinStr4Size));
  InternalDumpHex (BinStr4, BinStr4Size);
  if (SecuredMessageContext->UsePsk) {
    RetVal = SpdmPskMasterSecretHkdfExpandFunc (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->PskHint, SecuredMessageContext->PskHintSize, BinStr4, BinStr4Size, SecuredMessageContext->ApplicationSecret.ResponseDataSecret, HashSize);
    if (!RetVal) {
      return RETURN_UNSUPPORTED;
    }
  } else {
    RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->MasterSecret.MasterSecret, HashSize, BinStr4, BinStr4Size, SecuredMessageContext->ApplicationSecret.ResponseDataSecret, HashSize);
  }
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "ResponseDataSecret (0x%x) - ", HashSize));
  InternalDumpData (SecuredMessageContext->ApplicationSecret.ResponseDataSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  BinStr8Size = sizeof(BinStr8);
  Status = SpdmBinConcat (BIN_STR_8_LABEL, sizeof(BIN_STR_8_LABEL) - 1, TH2HashData, (UINT16)HashSize, HashSize, BinStr8, &BinStr8Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr8 (0x%x):\n", BinStr8Size));
  InternalDumpHex (BinStr8, BinStr8Size);
  if (SecuredMessageContext->UsePsk) {
    RetVal = SpdmPskMasterSecretHkdfExpandFunc (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->PskHint, SecuredMessageContext->PskHintSize, BinStr8, BinStr8Size, SecuredMessageContext->HandshakeSecret.ExportMasterSecret, HashSize);
    if (!RetVal) {
      return RETURN_UNSUPPORTED;
    }
  } else {
    RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->MasterSecret.MasterSecret, HashSize, BinStr8, BinStr8Size, SecuredMessageContext->HandshakeSecret.ExportMasterSecret, HashSize);
  }
  ASSERT (RetVal);
  DEBUG((DEBUG_INFO, "ExportMasterSecret (0x%x) - ", HashSize));
  InternalDumpData (SecuredMessageContext->HandshakeSecret.ExportMasterSecret, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  SpdmGenerateAeadKeyAndIv (
    SecuredMessageContext,
    SecuredMessageContext->ApplicationSecret.RequestDataSecret,
    SecuredMessageContext->ApplicationSecret.RequestDataEncryptionKey,
    SecuredMessageContext->ApplicationSecret.RequestDataSalt
    );
  SecuredMessageContext->ApplicationSecret.RequestDataSequenceNumber = 0;

  SpdmGenerateAeadKeyAndIv (
    SecuredMessageContext,
    SecuredMessageContext->ApplicationSecret.ResponseDataSecret,
    SecuredMessageContext->ApplicationSecret.ResponseDataEncryptionKey,
    SecuredMessageContext->ApplicationSecret.ResponseDataSalt
    );
  SecuredMessageContext->ApplicationSecret.ResponseDataSequenceNumber = 0;

  return RETURN_SUCCESS;
}

/**
  This function creates the updates of SPDM DataKey for a session.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  Action                       Indicate of the key update action.

  @retval RETURN_SUCCESS  SPDM DataKey update is created.
**/
RETURN_STATUS
EFIAPI
SpdmCreateUpdateSessionDataKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN SPDM_KEY_UPDATE_ACTION       Action
  )
{
  RETURN_STATUS                  Status;
  BOOLEAN                        RetVal;
  UINTN                          HashSize;
  UINT8                          BinStr9[128];
  UINTN                          BinStr9Size;
  SPDM_SECURED_MESSAGE_CONTEXT   *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;

  HashSize = SecuredMessageContext->HashSize;

  BinStr9Size = sizeof(BinStr9);
  Status = SpdmBinConcat (BIN_STR_9_LABEL, sizeof(BIN_STR_9_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr9, &BinStr9Size);
  ASSERT_RETURN_ERROR (Status);
  DEBUG((DEBUG_INFO, "BinStr9 (0x%x):\n", BinStr9Size));
  InternalDumpHex (BinStr9, BinStr9Size);

  if ((Action & SpdmKeyUpdateActionRequester) != 0) {
    CopyMem (&SecuredMessageContext->ApplicationSecretBackup.RequestDataSecret, &SecuredMessageContext->ApplicationSecret.RequestDataSecret, MAX_HASH_SIZE);
    CopyMem (&SecuredMessageContext->ApplicationSecretBackup.RequestDataEncryptionKey, &SecuredMessageContext->ApplicationSecret.RequestDataEncryptionKey, MAX_AEAD_KEY_SIZE);
    CopyMem (&SecuredMessageContext->ApplicationSecretBackup.RequestDataSalt, &SecuredMessageContext->ApplicationSecret.RequestDataSalt, MAX_AEAD_IV_SIZE);
    SecuredMessageContext->ApplicationSecretBackup.RequestDataSequenceNumber = SecuredMessageContext->ApplicationSecret.RequestDataSequenceNumber;

    RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->ApplicationSecret.RequestDataSecret, HashSize, BinStr9, BinStr9Size, SecuredMessageContext->ApplicationSecret.RequestDataSecret, HashSize);
    ASSERT (RetVal);
    DEBUG((DEBUG_INFO, "RequestDataSecretUpdate (0x%x) - ", HashSize));
    InternalDumpData (SecuredMessageContext->ApplicationSecret.RequestDataSecret, HashSize);
    DEBUG((DEBUG_INFO, "\n"));

    SpdmGenerateAeadKeyAndIv (
      SecuredMessageContext,
      SecuredMessageContext->ApplicationSecret.RequestDataSecret,
      SecuredMessageContext->ApplicationSecret.RequestDataEncryptionKey,
      SecuredMessageContext->ApplicationSecret.RequestDataSalt
      );
    SecuredMessageContext->ApplicationSecret.RequestDataSequenceNumber = 0;
  }

  if ((Action & SpdmKeyUpdateActionResponder) != 0) {
    CopyMem (&SecuredMessageContext->ApplicationSecretBackup.ResponseDataSecret, &SecuredMessageContext->ApplicationSecret.ResponseDataSecret, MAX_HASH_SIZE);
    CopyMem (&SecuredMessageContext->ApplicationSecretBackup.ResponseDataEncryptionKey, &SecuredMessageContext->ApplicationSecret.ResponseDataEncryptionKey, MAX_AEAD_KEY_SIZE);
    CopyMem (&SecuredMessageContext->ApplicationSecretBackup.ResponseDataSalt, &SecuredMessageContext->ApplicationSecret.ResponseDataSalt, MAX_AEAD_IV_SIZE);
    SecuredMessageContext->ApplicationSecretBackup.ResponseDataSequenceNumber = SecuredMessageContext->ApplicationSecret.ResponseDataSequenceNumber;

    RetVal = SpdmHkdfExpand (SecuredMessageContext->BaseHashAlgo, SecuredMessageContext->ApplicationSecret.ResponseDataSecret, HashSize, BinStr9, BinStr9Size, SecuredMessageContext->ApplicationSecret.ResponseDataSecret, HashSize);
    ASSERT (RetVal);
    DEBUG((DEBUG_INFO, "ResponseDataSecretUpdate (0x%x) - ", HashSize));
    InternalDumpData (SecuredMessageContext->ApplicationSecret.ResponseDataSecret, HashSize);
    DEBUG((DEBUG_INFO, "\n"));

    SpdmGenerateAeadKeyAndIv (
      SecuredMessageContext,
      SecuredMessageContext->ApplicationSecret.ResponseDataSecret,
      SecuredMessageContext->ApplicationSecret.ResponseDataEncryptionKey,
      SecuredMessageContext->ApplicationSecret.ResponseDataSalt
      );
    SecuredMessageContext->ApplicationSecret.ResponseDataSequenceNumber = 0;
  }
  return RETURN_SUCCESS;
}

/**
  This function activates the update of SPDM DataKey for a session.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  Action                       Indicate of the key update action.
  @param  UseNewKey                    Indicate if the new key should be used.

  @retval RETURN_SUCCESS  SPDM DataKey update is activated.
**/
RETURN_STATUS
EFIAPI
SpdmActivateUpdateSessionDataKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN SPDM_KEY_UPDATE_ACTION       Action,
  IN BOOLEAN                      UseNewKey
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT   *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;

  if (!UseNewKey) {
    if ((Action & SpdmKeyUpdateActionRequester) != 0) {
      CopyMem (&SecuredMessageContext->ApplicationSecret.RequestDataSecret, &SecuredMessageContext->ApplicationSecretBackup.RequestDataSecret, MAX_HASH_SIZE);
      CopyMem (&SecuredMessageContext->ApplicationSecret.RequestDataEncryptionKey, &SecuredMessageContext->ApplicationSecretBackup.RequestDataEncryptionKey, MAX_AEAD_KEY_SIZE);
      CopyMem (&SecuredMessageContext->ApplicationSecret.RequestDataSalt, &SecuredMessageContext->ApplicationSecretBackup.RequestDataSalt, MAX_AEAD_IV_SIZE);
      SecuredMessageContext->ApplicationSecret.RequestDataSequenceNumber = SecuredMessageContext->ApplicationSecretBackup.RequestDataSequenceNumber;
    }
    if ((Action & SpdmKeyUpdateActionResponder) != 0) {
      CopyMem (&SecuredMessageContext->ApplicationSecret.ResponseDataSecret, &SecuredMessageContext->ApplicationSecretBackup.ResponseDataSecret, MAX_HASH_SIZE);
      CopyMem (&SecuredMessageContext->ApplicationSecret.ResponseDataEncryptionKey, &SecuredMessageContext->ApplicationSecretBackup.ResponseDataEncryptionKey, MAX_AEAD_KEY_SIZE);
      CopyMem (&SecuredMessageContext->ApplicationSecret.ResponseDataSalt, &SecuredMessageContext->ApplicationSecretBackup.ResponseDataSalt, MAX_AEAD_IV_SIZE);
      SecuredMessageContext->ApplicationSecret.ResponseDataSequenceNumber = SecuredMessageContext->ApplicationSecretBackup.ResponseDataSequenceNumber;
    }
  }

  if ((Action & SpdmKeyUpdateActionRequester) != 0) {
    ZeroMem (&SecuredMessageContext->ApplicationSecretBackup.RequestDataSecret, MAX_HASH_SIZE);
    ZeroMem (&SecuredMessageContext->ApplicationSecretBackup.RequestDataEncryptionKey, MAX_AEAD_KEY_SIZE);
    ZeroMem (&SecuredMessageContext->ApplicationSecretBackup.RequestDataSalt, MAX_AEAD_IV_SIZE);
    SecuredMessageContext->ApplicationSecretBackup.RequestDataSequenceNumber = 0;
  }
  if ((Action & SpdmKeyUpdateActionResponder) != 0) {
    ZeroMem (&SecuredMessageContext->ApplicationSecretBackup.ResponseDataSecret, MAX_HASH_SIZE);
    ZeroMem (&SecuredMessageContext->ApplicationSecretBackup.ResponseDataEncryptionKey, MAX_AEAD_KEY_SIZE);
    ZeroMem (&SecuredMessageContext->ApplicationSecretBackup.ResponseDataSalt, MAX_AEAD_IV_SIZE);
    SecuredMessageContext->ApplicationSecretBackup.ResponseDataSequenceNumber = 0;
  }
  return RETURN_SUCCESS;
}

/**
  Computes the HMAC of a input data buffer, with RequestFinishedKey.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  Data                         Pointer to the buffer containing the data to be HMACed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
BOOLEAN
EFIAPI
SpdmHmacAllWithRequestFinishedKey (
  IN   VOID                         *SpdmSecuredMessageContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HmacValue
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  return SpdmHmacAll (
          SecuredMessageContext->BaseHashAlgo,
          Data,
          DataSize,
          SecuredMessageContext->HandshakeSecret.RequestFinishedKey,
          SecuredMessageContext->HashSize,
          HmacValue
          );
}

/**
  Computes the HMAC of a input data buffer, with ResponseFinishedKey.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  Data                         Pointer to the buffer containing the data to be HMACed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
BOOLEAN
EFIAPI
SpdmHmacAllWithResponseFinishedKey (
  IN   VOID                         *SpdmSecuredMessageContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HmacValue
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  return SpdmHmacAll (
          SecuredMessageContext->BaseHashAlgo,
          Data,
          DataSize,
          SecuredMessageContext->HandshakeSecret.ResponseFinishedKey,
          SecuredMessageContext->HashSize,
          HmacValue
          );
}
