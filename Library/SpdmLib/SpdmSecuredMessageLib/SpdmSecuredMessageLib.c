/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmSecuredMessageLib.h>
#include <IndustryStandard/SpdmSecuredMessage.h>

UINT16
SecuredMessageGetAeadAlgo (
  IN VOID          *SpdmContext
  )
{

  RETURN_STATUS                      Status;
  SPDM_DATA_PARAMETER                Parameter;
  UINTN                              DataSize;
  UINT16                             AEADCipherSuite;

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationConnection;
  DataSize = sizeof(AEADCipherSuite);
  AEADCipherSuite = 0;
  Status = SpdmGetData (SpdmContext, SpdmDataAEADCipherSuite, &Parameter, &AEADCipherSuite, &DataSize);
  ASSERT_RETURN_ERROR(Status);

  return AEADCipherSuite;
}

UINT32
SecuredMessageGetSpdmAeadKeySize (
  IN VOID          *SpdmContext
  )
{
  UINT16                             AEADCipherSuite;

  AEADCipherSuite = SecuredMessageGetAeadAlgo (SpdmContext);
  switch (AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
    return 16;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
    return 32;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
    return 32;
  }
  return 0;
}

UINT32
SecuredMessageGetSpdmAeadIvSize (
  IN VOID          *SpdmContext
  )
{
  UINT16                             AEADCipherSuite;

  AEADCipherSuite = SecuredMessageGetAeadAlgo (SpdmContext);
  switch (AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
    return 12;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
    return 12;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
    return 12;
  }
  return 0;
}

UINT32
SecuredMessageGetSpdmAeadTagSize (
  IN VOID          *SpdmContext
  )
{
  UINT16                             AEADCipherSuite;

  AEADCipherSuite = SecuredMessageGetAeadAlgo (SpdmContext);
  switch (AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
    return 16;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
    return 16;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
    return 16;
  }
  return 0;
}

UINT32
SecuredMessageGetSpdmAeadBlockSize (
  IN VOID          *SpdmContext
  )
{
  UINT16                             AEADCipherSuite;

  AEADCipherSuite = SecuredMessageGetAeadAlgo (SpdmContext);
  switch (AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
    return 16;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
    return 16;
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
    return 16;
  }
  return 0;
}

typedef
BOOLEAN
(EFIAPI *AEAD_ENCRYPT) (
  IN   CONST UINT8* Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8* Iv,
  IN   UINTN        IvSize,
  IN   CONST UINT8* AData,
  IN   UINTN        ADataSize,
  IN   CONST UINT8* DataIn,
  IN   UINTN        DataInSize,
  OUT  UINT8*       TagOut,
  IN   UINTN        TagSize,
  OUT  UINT8*       DataOut,
  OUT  UINTN*       DataOutSize
  );

typedef
BOOLEAN
(EFIAPI *AEAD_DECRYPT) (
  IN   CONST UINT8* Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8* Iv,
  IN   UINTN        IvSize,
  IN   CONST UINT8* AData,
  IN   UINTN        ADataSize,
  IN   CONST UINT8* DataIn,
  IN   UINTN        DataInSize,
  IN   CONST UINT8* Tag,
  IN   UINTN        TagSize,
  OUT  UINT8*       DataOut,
  OUT  UINTN*       DataOutSize
  );

AEAD_ENCRYPT
SecuredMessageGetSpdmAeadEncFunc (
  IN VOID          *SpdmContext
  )
{
  UINT16                             AEADCipherSuite;

  AEADCipherSuite = SecuredMessageGetAeadAlgo (SpdmContext);
  switch (AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
    return AeadAesGcmEncrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
    return AeadAesGcmEncrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
#if OPENSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
    return AeadChaCha20Poly1305Encrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

AEAD_DECRYPT
SecuredMessageGetSpdmAeadDecFunc (
  IN VOID          *SpdmContext
  )
{
  UINT16                             AEADCipherSuite;

  AEADCipherSuite = SecuredMessageGetAeadAlgo (SpdmContext);
  switch (AEADCipherSuite) {
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
    return AeadAesGcmDecrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM:
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
    return AeadAesGcmDecrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  case SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305:
#if OPENSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
    return AeadChaCha20Poly1305Decrypt;
#else
    ASSERT (FALSE);
    break;
#endif
  }
  ASSERT (FALSE);
  return NULL;
}

RETURN_STATUS
EFIAPI
SpdmEncodeSecuredMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                AppMessageSize,
  IN     VOID                 *AppMessage,
  IN OUT UINTN                *SecuredMessageSize,
     OUT VOID                 *SecuredMessage
  )
{
  UINTN                              TotalSecuredMessageSize;
  UINTN                              PlainTextSize;
  UINTN                              CipherTextSize;
  UINTN                              AeadBlockSize;
  UINTN                              AeadTagSize;
  UINTN                              AeadKeySize;
  UINTN                              AeadIvSize;
  UINT8                              *AData;
  UINT8                              *EncMsg;
  UINT8                              *DecMsg;
  UINT8                              *Tag;
  SPDM_SECURED_MESSAGE_ADATA_HEADER  *RecordHeader;
  SPDM_SECURED_MESSAGE_CIPHER_HEADER *EncMsgHeader;
  BOOLEAN                            Result;
  UINT8                              Key[MAX_AEAD_KEY_SIZE];
  UINT8                              Salt[MAX_AEAD_IV_SIZE];
  UINT64                             SequenceNumber;
  SPDM_SESSION_TYPE                  SessionType;
  UINT8                              RandCount;
  RETURN_STATUS                      Status;
  SPDM_DATA_PARAMETER                Parameter;
  UINTN                              DataSize;
  SPDM_DATA_TYPE                     EncryptionKeyDataType;
  SPDM_DATA_TYPE                     SaltDataType;
  SPDM_DATA_TYPE                     SequenceNumberDataType;
  SPDM_SESSION_STATE                 SessionState;
  AEAD_ENCRYPT                       AeadEncFunction;

  AeadEncFunction = SecuredMessageGetSpdmAeadEncFunc (SpdmContext);
  if (AeadEncFunction == NULL) {
    return RETURN_UNSUPPORTED;
  }

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationConnection;
  DataSize = sizeof(SessionType);
  Status = SpdmGetData (SpdmContext, SpdmDataSessionType, &Parameter, &SessionType, &DataSize);
  ASSERT_RETURN_ERROR(Status);
  ASSERT ((SessionType == SpdmSessionTypeMacOnly) || (SessionType == SpdmSessionTypeEncMac));

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  *(UINT32 *)Parameter.AdditionalData = SessionId;
  DataSize = sizeof(SessionState);
  Status = SpdmGetData (SpdmContext, SpdmDataSessionState, &Parameter, &SessionState, &DataSize);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  switch (SessionState) {
  case SpdmStateHandshaking:
    if (IsRequester) {
      EncryptionKeyDataType = SpdmDataRequestHandshakeEncryptionKey;
      SaltDataType = SpdmDataRequestHandshakeSalt;
      SequenceNumberDataType = SpdmDataRequestHandshakeSequenceNumber;
    } else {
      EncryptionKeyDataType = SpdmDataResponseHandshakeEncryptionKey;
      SaltDataType = SpdmDataResponseHandshakeSalt;
      SequenceNumberDataType = SpdmDataResponseHandshakeSequenceNumber;
    }
    break;
  case SpdmStateEstablished:
    if (IsRequester) {
      EncryptionKeyDataType = SpdmDataRequestDataEncryptionKey;
      SaltDataType = SpdmDataRequestDataSalt;
      SequenceNumberDataType = SpdmDataRequestDataSequenceNumber;
    } else {
      EncryptionKeyDataType = SpdmDataResponseDataEncryptionKey;
      SaltDataType = SpdmDataResponseDataSalt;
      SequenceNumberDataType = SpdmDataResponseDataSequenceNumber;
    }
    break;
  default:
    ASSERT(FALSE);
    return RETURN_UNSUPPORTED;
    break;
  }

  AeadBlockSize = SecuredMessageGetSpdmAeadBlockSize (SpdmContext);
  AeadTagSize = SecuredMessageGetSpdmAeadTagSize (SpdmContext);
  AeadKeySize = SecuredMessageGetSpdmAeadKeySize (SpdmContext);
  AeadIvSize = SecuredMessageGetSpdmAeadIvSize (SpdmContext);

  DataSize = sizeof(Key);
  Status = SpdmGetData (SpdmContext, EncryptionKeyDataType, &Parameter, Key, &DataSize);
  ASSERT_RETURN_ERROR(Status);
  ASSERT (DataSize == AeadKeySize);
  DataSize = sizeof(Salt);
  Status = SpdmGetData (SpdmContext, SaltDataType, &Parameter, Salt, &DataSize);
  ASSERT_RETURN_ERROR(Status);
  ASSERT (DataSize == AeadIvSize);
  DataSize = sizeof(SequenceNumber);
  Status = SpdmGetData (SpdmContext, SequenceNumberDataType, &Parameter, &SequenceNumber, &DataSize);
  ASSERT_RETURN_ERROR(Status);
  ASSERT (DataSize == sizeof(SequenceNumber));
  *(UINT64 *)Salt = *(UINT64 *)Salt ^ SequenceNumber;
  SequenceNumber++;
  Status = SpdmSetData (SpdmContext, SequenceNumberDataType, &Parameter, &SequenceNumber, DataSize);
  ASSERT_RETURN_ERROR(Status);

  if (SessionType == SpdmSessionTypeEncMac) {
    RandomBytes (&RandCount, sizeof(RandCount));
    RandCount = (UINT8)((RandCount % 32) + 1);

    PlainTextSize = sizeof(SPDM_SECURED_MESSAGE_CIPHER_HEADER) + AppMessageSize + RandCount;
    CipherTextSize = (PlainTextSize + AeadBlockSize - 1) / AeadBlockSize * AeadBlockSize;
    TotalSecuredMessageSize = sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER) + CipherTextSize + AeadTagSize;

    ASSERT (*SecuredMessageSize >= TotalSecuredMessageSize);
    if (*SecuredMessageSize < TotalSecuredMessageSize) {
      *SecuredMessageSize = TotalSecuredMessageSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *SecuredMessageSize = TotalSecuredMessageSize;
    RecordHeader = (VOID *)SecuredMessage;
    RecordHeader->SessionId = SessionId;
    RecordHeader->Length = (UINT16)(CipherTextSize + AeadTagSize);
    EncMsgHeader = (VOID *)(RecordHeader + 1);
    EncMsgHeader->ApplicationDataLength = (UINT16)AppMessageSize;
    CopyMem (EncMsgHeader + 1, AppMessage, AppMessageSize);
    RandomBytes ((UINT8 *)EncMsgHeader + sizeof(SPDM_SECURED_MESSAGE_CIPHER_HEADER) + AppMessageSize, RandCount);

    AData = (UINT8 *)RecordHeader;
    EncMsg = (UINT8 *)EncMsgHeader;
    DecMsg = (UINT8 *)EncMsgHeader;
    Tag = (UINT8 *)RecordHeader + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER) + CipherTextSize;

    Result = AeadEncFunction (
              Key,
              AeadKeySize,
              Salt,
              AeadIvSize,
              (UINT8 *)AData,
              sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER),
              DecMsg,
              CipherTextSize,
              Tag,
              AeadTagSize,
              EncMsg,
              &CipherTextSize
              );
  } else { // SessionType == SpdmSessionTypeMacOnly
    TotalSecuredMessageSize = sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER) + AppMessageSize + AeadTagSize;

    ASSERT (*SecuredMessageSize >= TotalSecuredMessageSize);
    if (*SecuredMessageSize < TotalSecuredMessageSize) {
      *SecuredMessageSize = TotalSecuredMessageSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *SecuredMessageSize = TotalSecuredMessageSize;
    RecordHeader = (VOID *)SecuredMessage;
    RecordHeader->SessionId = SessionId;
    RecordHeader->Length = (UINT16)(AppMessageSize + AeadTagSize);
    CopyMem (RecordHeader + 1, AppMessage, AppMessageSize);
    AData = (UINT8 *)RecordHeader;
    Tag = (UINT8 *)RecordHeader + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER) + AppMessageSize;

    Result = AeadEncFunction (
              Key,
              AeadKeySize,
              Salt,
              AeadIvSize,
              (UINT8 *)AData,
              sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER) + AppMessageSize,
              NULL,
              0,
              Tag,
              AeadTagSize,
              NULL,
              NULL
              );
  }
  if (!Result) {
    return RETURN_OUT_OF_RESOURCES;
  }
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmDecodeSecuredMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SecuredMessageSize,
  IN     VOID                 *SecuredMessage,
  IN OUT UINTN                *AppMessageSize,
     OUT VOID                 *AppMessage
  )
{
  UINTN                              PlainTextSize;
  UINTN                              CipherTextSize;
  UINTN                              AeadBlockSize;
  UINTN                              AeadTagSize;
  UINTN                              AeadKeySize;
  UINTN                              AeadIvSize;
  UINT8                              *AData;
  UINT8                              *EncMsg;
  UINT8                              *DecMsg;
  UINT8                              *Tag;
  SPDM_SECURED_MESSAGE_ADATA_HEADER  *RecordHeader;
  SPDM_SECURED_MESSAGE_CIPHER_HEADER *EncMsgHeader;
  BOOLEAN                            Result;
  UINT8                              Key[MAX_AEAD_KEY_SIZE];
  UINT8                              Salt[MAX_AEAD_IV_SIZE];
  UINT64                             SequenceNumber;
  SPDM_SESSION_TYPE                  SessionType;
  RETURN_STATUS                      Status;
  SPDM_DATA_PARAMETER                Parameter;
  UINTN                              DataSize;
  SPDM_DATA_TYPE                     EncryptionKeyDataType;
  SPDM_DATA_TYPE                     SaltDataType;
  SPDM_DATA_TYPE                     SequenceNumberDataType;
  SPDM_SESSION_STATE                 SessionState;
  AEAD_DECRYPT                       AeadDecFunction;

  AeadDecFunction = SecuredMessageGetSpdmAeadDecFunc (SpdmContext);
  if (AeadDecFunction == NULL) {
    return RETURN_UNSUPPORTED;
  }

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationConnection;
  DataSize = sizeof(SessionType);
  Status = SpdmGetData (SpdmContext, SpdmDataSessionType, &Parameter, &SessionType, &DataSize);
  ASSERT_RETURN_ERROR(Status);
  ASSERT ((SessionType == SpdmSessionTypeMacOnly) || (SessionType == SpdmSessionTypeEncMac));

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  *(UINT32 *)Parameter.AdditionalData = SessionId;
  DataSize = sizeof(SessionState);
  Status = SpdmGetData (SpdmContext, SpdmDataSessionState, &Parameter, &SessionState, &DataSize);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  switch (SessionState) {
  case SpdmStateHandshaking:
    if (IsRequester) {
      EncryptionKeyDataType = SpdmDataRequestHandshakeEncryptionKey;
      SaltDataType = SpdmDataRequestHandshakeSalt;
      SequenceNumberDataType = SpdmDataRequestHandshakeSequenceNumber;
    } else {
      EncryptionKeyDataType = SpdmDataResponseHandshakeEncryptionKey;
      SaltDataType = SpdmDataResponseHandshakeSalt;
      SequenceNumberDataType = SpdmDataResponseHandshakeSequenceNumber;
    }
    break;
  case SpdmStateEstablished:
    if (IsRequester) {
      EncryptionKeyDataType = SpdmDataRequestDataEncryptionKey;
      SaltDataType = SpdmDataRequestDataSalt;
      SequenceNumberDataType = SpdmDataRequestDataSequenceNumber;
    } else {
      EncryptionKeyDataType = SpdmDataResponseDataEncryptionKey;
      SaltDataType = SpdmDataResponseDataSalt;
      SequenceNumberDataType = SpdmDataResponseDataSequenceNumber;
    }
    break;
  default:
    ASSERT(FALSE);
    return RETURN_UNSUPPORTED;
    break;
  }

  AeadBlockSize = SecuredMessageGetSpdmAeadBlockSize (SpdmContext);
  AeadTagSize = SecuredMessageGetSpdmAeadTagSize (SpdmContext);
  AeadKeySize = SecuredMessageGetSpdmAeadKeySize (SpdmContext);
  AeadIvSize = SecuredMessageGetSpdmAeadIvSize (SpdmContext);

  DataSize = sizeof(Key);
  Status = SpdmGetData (SpdmContext, EncryptionKeyDataType, &Parameter, Key, &DataSize);
  ASSERT_RETURN_ERROR(Status);
  ASSERT (DataSize == AeadKeySize);
  DataSize = sizeof(Salt);
  Status = SpdmGetData (SpdmContext, SaltDataType, &Parameter, Salt, &DataSize);
  ASSERT_RETURN_ERROR(Status);
  ASSERT (DataSize == AeadIvSize);
  DataSize = sizeof(SequenceNumber);
  Status = SpdmGetData (SpdmContext, SequenceNumberDataType, &Parameter, &SequenceNumber, &DataSize);
  ASSERT_RETURN_ERROR(Status);
  ASSERT (DataSize == sizeof(SequenceNumber));
  *(UINT64 *)Salt = *(UINT64 *)Salt ^ SequenceNumber;
  SequenceNumber++;
  Status = SpdmSetData (SpdmContext, SequenceNumberDataType, &Parameter, &SequenceNumber, DataSize);
  ASSERT_RETURN_ERROR(Status);

  if (SessionType == SpdmSessionTypeEncMac) {
    if (SecuredMessageSize < sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER) + AeadBlockSize + AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    RecordHeader = (VOID *)SecuredMessage;
    if (RecordHeader->SessionId != SessionId) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader->Length > SecuredMessageSize - sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER)) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader->Length < AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    CipherTextSize = (RecordHeader->Length - AeadTagSize) / AeadBlockSize * AeadBlockSize;
    EncMsgHeader = (VOID *)(RecordHeader + 1);
    AData = (UINT8 *)RecordHeader;
    EncMsg = (UINT8 *)EncMsgHeader;
    DecMsg = (UINT8 *)EncMsgHeader;
    Tag = (UINT8 *)RecordHeader + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER) + CipherTextSize;
    Result = AeadDecFunction (
              Key,
              AeadKeySize,
              Salt,
              AeadIvSize,
              (UINT8 *)AData,
              sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER),
              EncMsg,
              CipherTextSize,
              Tag,
              AeadTagSize,
              DecMsg,
              &CipherTextSize
              );
    if (!Result) {
      return RETURN_DEVICE_ERROR;
    }
    PlainTextSize = EncMsgHeader->ApplicationDataLength;
    if (PlainTextSize > CipherTextSize) {
      return RETURN_DEVICE_ERROR;      
    }

    ASSERT (*AppMessageSize >= PlainTextSize);
    if (*AppMessageSize < PlainTextSize) {
      *AppMessageSize = PlainTextSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *AppMessageSize = PlainTextSize;
    CopyMem (AppMessage, EncMsgHeader + 1, PlainTextSize);
  } else { // SessionType == SpdmSessionTypeMacOnly
    if (SecuredMessageSize < sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER) + AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    RecordHeader = (VOID *)SecuredMessage;
    if (RecordHeader->SessionId != SessionId) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader->Length > SecuredMessageSize - sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER)) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader->Length < AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    AData = (UINT8 *)RecordHeader;
    Tag = (UINT8 *)RecordHeader + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER) + RecordHeader->Length - AeadTagSize;
    Result = AeadDecFunction (
              Key,
              AeadKeySize,
              Salt,
              AeadIvSize,
              (UINT8 *)AData,
              sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER) + RecordHeader->Length - AeadTagSize,
              NULL,
              0,
              Tag,
              AeadTagSize,
              NULL,
              NULL
              );
    if (!Result) {
      return RETURN_DEVICE_ERROR;
    }

    PlainTextSize = RecordHeader->Length - AeadTagSize;
    ASSERT (*AppMessageSize >= PlainTextSize);
    if (*AppMessageSize < PlainTextSize) {
      *AppMessageSize = PlainTextSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *AppMessageSize = PlainTextSize;
    CopyMem (AppMessage, RecordHeader + 1, PlainTextSize);
  }

  return RETURN_SUCCESS;
}
