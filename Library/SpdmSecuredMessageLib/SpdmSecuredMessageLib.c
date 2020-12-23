/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmSecuredMessageLib.h>
#include <IndustryStandard/SpdmSecuredMessage.h>

/**
  This function returns the SPDM negotiated AEAD algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM negotiated AEAD algorithm.
**/
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

/**
  This function returns the SPDM AEAD algorithm key size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm key size.
**/
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

/**
  This function returns the SPDM AEAD algorithm iv size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm iv size.
**/
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

/**
  This function returns the SPDM AEAD algorithm tag size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm tag size.
**/
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

/**
  This function returns the SPDM AEAD algorithm block size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm block size.
**/
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

/**
  Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  Key                          Pointer to the encryption key.
  @param  KeySize                      Size of the encryption key in bytes.
  @param  Iv                           Pointer to the IV value.
  @param  IvSize                       Size of the IV value in bytes.
  @param  AData                        Pointer to the additional authenticated data (AAD).
  @param  ADataSize                    Size of the additional authenticated data (AAD) in bytes.
  @param  DataIn                       Pointer to the input data buffer to be encrypted.
  @param  DataInSize                   Size of the input data buffer in bytes.
  @param  TagOut                       Pointer to a buffer that receives the authentication tag output.
  @param  TagSize                      Size of the authentication tag in bytes.
  @param  DataOut                      Pointer to a buffer that receives the encryption output.
  @param  DataOutSize                  Size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated encryption succeeded.
  @retval FALSE  AEAD authenticated encryption failed.
**/
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

/**
  Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  Key                          Pointer to the encryption key.
  @param  KeySize                      Size of the encryption key in bytes.
  @param  Iv                           Pointer to the IV value.
  @param  IvSize                       Size of the IV value in bytes.
  @param  AData                        Pointer to the additional authenticated data (AAD).
  @param  ADataSize                    Size of the additional authenticated data (AAD) in bytes.
  @param  DataIn                       Pointer to the input data buffer to be decrypted.
  @param  DataInSize                   Size of the input data buffer in bytes.
  @param  Tag                          Pointer to a buffer that contains the authentication tag.
  @param  TagSize                      Size of the authentication tag in bytes.
  @param  DataOut                      Pointer to a buffer that receives the decryption output.
  @param  DataOutSize                  Size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated decryption succeeded.
  @retval FALSE  AEAD authenticated decryption failed.
**/
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

/**
  Return AEAD encryption function, based upon the negotiated AEAD algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return AEAD encryption function
**/
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

/**
  Return AEAD decryption function, based upon the negotiated AEAD algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return AEAD decryption function
**/
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

/**
  Encode an application message to a secured message.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The session ID of the SPDM session.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  AppMessageSize               Size in bytes of the application message data buffer.
  @param  AppMessage                   A pointer to a source buffer to store the application message.
  @param  SecuredMessageSize           Size in bytes of the secured message data buffer.
  @param  SecuredMessage               A pointer to a destination buffer to store the secured message.
  @param  SpdmSecuredMessageCallbacks  A pointer to a secured message callback functions structure.

  @retval RETURN_SUCCESS               The application message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
**/
RETURN_STATUS
EFIAPI
SpdmEncodeSecuredMessage (
  IN     VOID                           *SpdmContext,
  IN     UINT32                         SessionId,
  IN     BOOLEAN                        IsRequester,
  IN     UINTN                          AppMessageSize,
  IN     VOID                           *AppMessage,
  IN OUT UINTN                          *SecuredMessageSize,
     OUT VOID                           *SecuredMessage,
  IN     SPDM_SECURED_MESSAGE_CALLBACKS *SpdmSecuredMessageCallbacks
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
  SPDM_SECURED_MESSAGE_ADATA_HEADER_1 *RecordHeader1;
  SPDM_SECURED_MESSAGE_ADATA_HEADER_2 *RecordHeader2;
  UINTN                              RecordHeaderSize;
  SPDM_SECURED_MESSAGE_CIPHER_HEADER *EncMsgHeader;
  BOOLEAN                            Result;
  UINT8                              Key[MAX_AEAD_KEY_SIZE];
  UINT8                              Salt[MAX_AEAD_IV_SIZE];
  UINT64                             SequenceNumber;
  UINT64                             SequenceNumInHeader;
  UINT8                              SequenceNumInHeaderSize;
  SPDM_SESSION_TYPE                  SessionType;
  UINT32                             RandCount;
  UINT32                             MaxRandCount;
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

  SequenceNumInHeader = 0;
  SequenceNumInHeaderSize = SpdmSecuredMessageCallbacks->GetSequenceNumber (SequenceNumber, (UINT8 *)&SequenceNumInHeader);
  ASSERT (SequenceNumInHeaderSize <= sizeof(SequenceNumInHeader));

  SequenceNumber++;
  Status = SpdmSetData (SpdmContext, SequenceNumberDataType, &Parameter, &SequenceNumber, DataSize);
  ASSERT_RETURN_ERROR(Status);

  RecordHeaderSize = sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumInHeaderSize + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_2);

  if (SessionType == SpdmSessionTypeEncMac) {
    MaxRandCount = SpdmSecuredMessageCallbacks->GetMaxRandomNumberCount ();
    if (MaxRandCount != 0) {
      RandomBytes ((UINT8 *)&RandCount, sizeof(RandCount));
      RandCount = (UINT8)((RandCount % MaxRandCount) + 1);
    } else {
      RandCount = 0;
    }

    PlainTextSize = sizeof(SPDM_SECURED_MESSAGE_CIPHER_HEADER) + AppMessageSize + RandCount;
    CipherTextSize = (PlainTextSize + AeadBlockSize - 1) / AeadBlockSize * AeadBlockSize;
    TotalSecuredMessageSize = RecordHeaderSize + CipherTextSize + AeadTagSize;

    ASSERT (*SecuredMessageSize >= TotalSecuredMessageSize);
    if (*SecuredMessageSize < TotalSecuredMessageSize) {
      *SecuredMessageSize = TotalSecuredMessageSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *SecuredMessageSize = TotalSecuredMessageSize;
    RecordHeader1 = (VOID *)SecuredMessage;
    RecordHeader2 = (VOID *)((UINT8 *)RecordHeader1 + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumInHeaderSize);
    RecordHeader1->SessionId = SessionId;
    CopyMem (RecordHeader1 + 1, &SequenceNumInHeader, SequenceNumInHeaderSize);
    RecordHeader2->Length = (UINT16)(CipherTextSize + AeadTagSize);
    EncMsgHeader = (VOID *)(RecordHeader2 + 1);
    EncMsgHeader->ApplicationDataLength = (UINT16)AppMessageSize;
    CopyMem (EncMsgHeader + 1, AppMessage, AppMessageSize);
    RandomBytes ((UINT8 *)EncMsgHeader + sizeof(SPDM_SECURED_MESSAGE_CIPHER_HEADER) + AppMessageSize, RandCount);

    AData = (UINT8 *)RecordHeader1;
    EncMsg = (UINT8 *)EncMsgHeader;
    DecMsg = (UINT8 *)EncMsgHeader;
    Tag = (UINT8 *)RecordHeader1 + RecordHeaderSize + CipherTextSize;

    Result = AeadEncFunction (
              Key,
              AeadKeySize,
              Salt,
              AeadIvSize,
              (UINT8 *)AData,
              RecordHeaderSize,
              DecMsg,
              CipherTextSize,
              Tag,
              AeadTagSize,
              EncMsg,
              &CipherTextSize
              );
  } else { // SessionType == SpdmSessionTypeMacOnly
    TotalSecuredMessageSize = RecordHeaderSize + AppMessageSize + AeadTagSize;

    ASSERT (*SecuredMessageSize >= TotalSecuredMessageSize);
    if (*SecuredMessageSize < TotalSecuredMessageSize) {
      *SecuredMessageSize = TotalSecuredMessageSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *SecuredMessageSize = TotalSecuredMessageSize;
    RecordHeader1 = (VOID *)SecuredMessage;
    RecordHeader2 = (VOID *)((UINT8 *)RecordHeader1 + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumInHeaderSize);
    RecordHeader1->SessionId = SessionId;
    CopyMem (RecordHeader1 + 1, &SequenceNumInHeader, SequenceNumInHeaderSize);
    RecordHeader2->Length = (UINT16)(AppMessageSize + AeadTagSize);
    CopyMem (RecordHeader2 + 1, AppMessage, AppMessageSize);
    AData = (UINT8 *)RecordHeader1;
    Tag = (UINT8 *)RecordHeader1 + RecordHeaderSize + AppMessageSize;

    Result = AeadEncFunction (
              Key,
              AeadKeySize,
              Salt,
              AeadIvSize,
              (UINT8 *)AData,
              RecordHeaderSize + AppMessageSize,
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

/**
  Decode an application message from a secured message.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The session ID of the SPDM session.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  SecuredMessageSize           Size in bytes of the secured message data buffer.
  @param  SecuredMessage               A pointer to a source buffer to store the secured message.
  @param  AppMessageSize               Size in bytes of the application message data buffer.
  @param  AppMessage                   A pointer to a destination buffer to store the application message.
  @param  SpdmSecuredMessageCallbacks  A pointer to a secured message callback functions structure.

  @retval RETURN_SUCCESS               The application message is decoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
  @retval RETURN_UNSUPPORTED           The SecuredMessage is unsupported.
**/
RETURN_STATUS
EFIAPI
SpdmDecodeSecuredMessage (
  IN     VOID                           *SpdmContext,
  IN     UINT32                         SessionId,
  IN     BOOLEAN                        IsRequester,
  IN     UINTN                          SecuredMessageSize,
  IN     VOID                           *SecuredMessage,
  IN OUT UINTN                          *AppMessageSize,
     OUT VOID                           *AppMessage,
  IN     SPDM_SECURED_MESSAGE_CALLBACKS *SpdmSecuredMessageCallbacks
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
  SPDM_SECURED_MESSAGE_ADATA_HEADER_1 *RecordHeader1;
  SPDM_SECURED_MESSAGE_ADATA_HEADER_2 *RecordHeader2;
  UINTN                              RecordHeaderSize;
  SPDM_SECURED_MESSAGE_CIPHER_HEADER *EncMsgHeader;
  BOOLEAN                            Result;
  UINT8                              Key[MAX_AEAD_KEY_SIZE];
  UINT8                              Salt[MAX_AEAD_IV_SIZE];
  UINT64                             SequenceNumber;
  UINT64                             SequenceNumInHeader;
  UINT8                              SequenceNumInHeaderSize;
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

  SequenceNumInHeader = 0;
  SequenceNumInHeaderSize = SpdmSecuredMessageCallbacks->GetSequenceNumber (SequenceNumber, (UINT8 *)&SequenceNumInHeader);
  ASSERT (SequenceNumInHeaderSize <= sizeof(SequenceNumInHeader));

  SequenceNumber++;
  Status = SpdmSetData (SpdmContext, SequenceNumberDataType, &Parameter, &SequenceNumber, DataSize);
  ASSERT_RETURN_ERROR(Status);

  RecordHeaderSize = sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumInHeaderSize + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_2);

  if (SessionType == SpdmSessionTypeEncMac) {
    if (SecuredMessageSize < RecordHeaderSize + AeadBlockSize + AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    RecordHeader1 = (VOID *)SecuredMessage;
    RecordHeader2 = (VOID *)((UINT8 *)RecordHeader1 + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumInHeaderSize);
    if (RecordHeader1->SessionId != SessionId) {
      return RETURN_DEVICE_ERROR;
    }
    if (CompareMem (RecordHeader1 + 1, &SequenceNumInHeader, SequenceNumInHeaderSize) != 0) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader2->Length > SecuredMessageSize - RecordHeaderSize) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader2->Length < AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    CipherTextSize = (RecordHeader2->Length - AeadTagSize) / AeadBlockSize * AeadBlockSize;
    EncMsgHeader = (VOID *)(RecordHeader2 + 1);
    AData = (UINT8 *)RecordHeader1;
    EncMsg = (UINT8 *)EncMsgHeader;
    DecMsg = (UINT8 *)EncMsgHeader;
    Tag = (UINT8 *)RecordHeader1 + RecordHeaderSize + CipherTextSize;
    Result = AeadDecFunction (
              Key,
              AeadKeySize,
              Salt,
              AeadIvSize,
              (UINT8 *)AData,
              RecordHeaderSize,
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
    if (SecuredMessageSize < RecordHeaderSize + AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    RecordHeader1 = (VOID *)SecuredMessage;
    RecordHeader2 = (VOID *)((UINT8 *)RecordHeader1 + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumInHeaderSize);
    if (RecordHeader1->SessionId != SessionId) {
      return RETURN_DEVICE_ERROR;
    }
    if (CompareMem (RecordHeader1 + 1, &SequenceNumInHeader, SequenceNumInHeaderSize) != 0) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader2->Length > SecuredMessageSize - RecordHeaderSize) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader2->Length < AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    AData = (UINT8 *)RecordHeader1;
    Tag = (UINT8 *)RecordHeader1 + RecordHeaderSize + RecordHeader2->Length - AeadTagSize;
    Result = AeadDecFunction (
              Key,
              AeadKeySize,
              Salt,
              AeadIvSize,
              (UINT8 *)AData,
              RecordHeaderSize + RecordHeader2->Length - AeadTagSize,
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

    PlainTextSize = RecordHeader2->Length - AeadTagSize;
    ASSERT (*AppMessageSize >= PlainTextSize);
    if (*AppMessageSize < PlainTextSize) {
      *AppMessageSize = PlainTextSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *AppMessageSize = PlainTextSize;
    CopyMem (AppMessage, RecordHeader2 + 1, PlainTextSize);
  }

  return RETURN_SUCCESS;
}
