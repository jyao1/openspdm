/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmSecuredMessageLibInternal.h"

/**
  Encode an application message to a secured message.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
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
  IN     VOID                           *SpdmSecuredMessageContext,
  IN     UINT32                         SessionId,
  IN     BOOLEAN                        IsRequester,
  IN     UINTN                          AppMessageSize,
  IN     VOID                           *AppMessage,
  IN OUT UINTN                          *SecuredMessageSize,
     OUT VOID                           *SecuredMessage,
  IN     SPDM_SECURED_MESSAGE_CALLBACKS *SpdmSecuredMessageCallbacks
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT       *SecuredMessageContext;
  UINTN                              TotalSecuredMessageSize;
  UINTN                              PlainTextSize;
  UINTN                              CipherTextSize;
  UINTN                              AeadPadSize;
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
  SPDM_SESSION_STATE                 SessionState;

  SecuredMessageContext = SpdmSecuredMessageContext;

  SessionType = SecuredMessageContext->SessionType;
  ASSERT ((SessionType == SpdmSessionTypeMacOnly) || (SessionType == SpdmSessionTypeEncMac));
  SessionState = SecuredMessageContext->SessionState;
  ASSERT ((SessionState == SpdmSessionStateHandshaking) || (SessionState == SpdmSessionStateEstablished));

  AeadBlockSize = SecuredMessageContext->AeadBlockSize;
  AeadTagSize = SecuredMessageContext->AeadTagSize;
  AeadKeySize = SecuredMessageContext->AeadKeySize;
  AeadIvSize = SecuredMessageContext->AeadIvSize;

  switch (SessionState) {
  case SpdmSessionStateHandshaking:
    if (IsRequester) {
      CopyMem (Key, SecuredMessageContext->HandshakeSecret.RequestHandshakeEncryptionKey, SecuredMessageContext->AeadKeySize);
      CopyMem (Salt, SecuredMessageContext->HandshakeSecret.RequestHandshakeSalt, SecuredMessageContext->AeadIvSize);
      SequenceNumber = SecuredMessageContext->HandshakeSecret.RequestHandshakeSequenceNumber;
    } else {
      CopyMem (Key, SecuredMessageContext->HandshakeSecret.ResponseHandshakeEncryptionKey, SecuredMessageContext->AeadKeySize);
      CopyMem (Salt, SecuredMessageContext->HandshakeSecret.ResponseHandshakeSalt, SecuredMessageContext->AeadIvSize);
      SequenceNumber = SecuredMessageContext->HandshakeSecret.ResponseHandshakeSequenceNumber;
    }
    break;
  case SpdmSessionStateEstablished:
    if (IsRequester) {
      CopyMem (Key, SecuredMessageContext->ApplicationSecret.RequestDataEncryptionKey, SecuredMessageContext->AeadKeySize);
      CopyMem (Salt, SecuredMessageContext->ApplicationSecret.RequestDataSalt, SecuredMessageContext->AeadIvSize);
      SequenceNumber = SecuredMessageContext->ApplicationSecret.RequestDataSequenceNumber;
    } else {
      CopyMem (Key, SecuredMessageContext->ApplicationSecret.ResponseDataEncryptionKey, SecuredMessageContext->AeadKeySize);
      CopyMem (Salt, SecuredMessageContext->ApplicationSecret.ResponseDataSalt, SecuredMessageContext->AeadIvSize);
      SequenceNumber = SecuredMessageContext->ApplicationSecret.ResponseDataSequenceNumber;
    }
    break;
  default:
    ASSERT(FALSE);
    return RETURN_UNSUPPORTED;
    break;
  }

  if (SequenceNumber == (UINT64)-1) {
    return RETURN_OUT_OF_RESOURCES;
  }

  *(UINT64 *)Salt = *(UINT64 *)Salt ^ SequenceNumber;

  SequenceNumInHeader = 0;
  SequenceNumInHeaderSize = SpdmSecuredMessageCallbacks->GetSequenceNumber (SequenceNumber, (UINT8 *)&SequenceNumInHeader);
  ASSERT (SequenceNumInHeaderSize <= sizeof(SequenceNumInHeader));

  SequenceNumber++;
  switch (SessionState) {
  case SpdmSessionStateHandshaking:
    if (IsRequester) {
      SecuredMessageContext->HandshakeSecret.RequestHandshakeSequenceNumber = SequenceNumber;
    } else {
      SecuredMessageContext->HandshakeSecret.ResponseHandshakeSequenceNumber = SequenceNumber;
    }
    break;
  case SpdmSessionStateEstablished:
    if (IsRequester) {
      SecuredMessageContext->ApplicationSecret.RequestDataSequenceNumber = SequenceNumber;
    } else {
      SecuredMessageContext->ApplicationSecret.ResponseDataSequenceNumber = SequenceNumber;
    }
    break;
  }

  RecordHeaderSize = sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumInHeaderSize + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_2);

  switch (SessionType) {
  case SpdmSessionTypeEncMac:
    MaxRandCount = SpdmSecuredMessageCallbacks->GetMaxRandomNumberCount ();
    if (MaxRandCount != 0) {
      RandomBytes ((UINT8 *)&RandCount, sizeof(RandCount));
      RandCount = (UINT8)((RandCount % MaxRandCount) + 1);
    } else {
      RandCount = 0;
    }

    PlainTextSize = sizeof(SPDM_SECURED_MESSAGE_CIPHER_HEADER) + AppMessageSize + RandCount;
    CipherTextSize = (PlainTextSize + AeadBlockSize - 1) / AeadBlockSize * AeadBlockSize;
    AeadPadSize = CipherTextSize - PlainTextSize;
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
    ZeroMem ((UINT8 *)EncMsgHeader + PlainTextSize, AeadPadSize);

    AData = (UINT8 *)RecordHeader1;
    EncMsg = (UINT8 *)EncMsgHeader;
    DecMsg = (UINT8 *)EncMsgHeader;
    Tag = (UINT8 *)RecordHeader1 + RecordHeaderSize + CipherTextSize;

    Result = SpdmAeadEncryption (
              SecuredMessageContext->AEADCipherSuite,
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
    break;

  case SpdmSessionTypeMacOnly:
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

    Result = SpdmAeadEncryption (
              SecuredMessageContext->AEADCipherSuite,
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
    break;

  default:
    ASSERT(FALSE);
    return RETURN_UNSUPPORTED;
  }
  if (!Result) {
    return RETURN_OUT_OF_RESOURCES;
  }
  return RETURN_SUCCESS;
}

/**
  Decode an application message from a secured message.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
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
  IN     VOID                           *SpdmSecuredMessageContext,
  IN     UINT32                         SessionId,
  IN     BOOLEAN                        IsRequester,
  IN     UINTN                          SecuredMessageSize,
  IN     VOID                           *SecuredMessage,
  IN OUT UINTN                          *AppMessageSize,
     OUT VOID                           *AppMessage,
  IN     SPDM_SECURED_MESSAGE_CALLBACKS *SpdmSecuredMessageCallbacks
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT       *SecuredMessageContext;
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
  SPDM_SESSION_STATE                 SessionState;
  SPDM_ERROR_STRUCT                  SpdmError;
  UINT8                              DecMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];

  SpdmError.ErrorCode = 0;
  SpdmError.SessionId = 0;
  SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);

  SpdmError.ErrorCode = SPDM_ERROR_CODE_DECRYPT_ERROR;
  SpdmError.SessionId = SessionId;

  SecuredMessageContext = SpdmSecuredMessageContext;

  SessionType = SecuredMessageContext->SessionType;
  ASSERT ((SessionType == SpdmSessionTypeMacOnly) || (SessionType == SpdmSessionTypeEncMac));
  SessionState = SecuredMessageContext->SessionState;
  ASSERT ((SessionState == SpdmSessionStateHandshaking) || (SessionState == SpdmSessionStateEstablished));

  AeadBlockSize = SecuredMessageContext->AeadBlockSize;
  AeadTagSize = SecuredMessageContext->AeadTagSize;
  AeadKeySize = SecuredMessageContext->AeadKeySize;
  AeadIvSize = SecuredMessageContext->AeadIvSize;

  switch (SessionState) {
  case SpdmSessionStateHandshaking:
    if (IsRequester) {
      CopyMem (Key, SecuredMessageContext->HandshakeSecret.RequestHandshakeEncryptionKey, SecuredMessageContext->AeadKeySize);
      CopyMem (Salt, SecuredMessageContext->HandshakeSecret.RequestHandshakeSalt, SecuredMessageContext->AeadIvSize);
      SequenceNumber = SecuredMessageContext->HandshakeSecret.RequestHandshakeSequenceNumber;
    } else {
      CopyMem (Key, SecuredMessageContext->HandshakeSecret.ResponseHandshakeEncryptionKey, SecuredMessageContext->AeadKeySize);
      CopyMem (Salt, SecuredMessageContext->HandshakeSecret.ResponseHandshakeSalt, SecuredMessageContext->AeadIvSize);
      SequenceNumber = SecuredMessageContext->HandshakeSecret.ResponseHandshakeSequenceNumber;
    }
    break;
  case SpdmSessionStateEstablished:
    if (IsRequester) {
      CopyMem (Key, SecuredMessageContext->ApplicationSecret.RequestDataEncryptionKey, SecuredMessageContext->AeadKeySize);
      CopyMem (Salt, SecuredMessageContext->ApplicationSecret.RequestDataSalt, SecuredMessageContext->AeadIvSize);
      SequenceNumber = SecuredMessageContext->ApplicationSecret.RequestDataSequenceNumber;
    } else {
      CopyMem (Key, SecuredMessageContext->ApplicationSecret.ResponseDataEncryptionKey, SecuredMessageContext->AeadKeySize);
      CopyMem (Salt, SecuredMessageContext->ApplicationSecret.ResponseDataSalt, SecuredMessageContext->AeadIvSize);
      SequenceNumber = SecuredMessageContext->ApplicationSecret.ResponseDataSequenceNumber;
    }
    break;
  default:
    ASSERT(FALSE);
    return RETURN_UNSUPPORTED;
  }

  if (SequenceNumber == (UINT64)-1) {
    SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
    return RETURN_SECURITY_VIOLATION;
  }

  *(UINT64 *)Salt = *(UINT64 *)Salt ^ SequenceNumber;

  SequenceNumInHeader = 0;
  SequenceNumInHeaderSize = SpdmSecuredMessageCallbacks->GetSequenceNumber (SequenceNumber, (UINT8 *)&SequenceNumInHeader);
  ASSERT (SequenceNumInHeaderSize <= sizeof(SequenceNumInHeader));

  SequenceNumber++;
  switch (SessionState) {
  case SpdmSessionStateHandshaking:
    if (IsRequester) {
      SecuredMessageContext->HandshakeSecret.RequestHandshakeSequenceNumber = SequenceNumber;
    } else {
      SecuredMessageContext->HandshakeSecret.ResponseHandshakeSequenceNumber = SequenceNumber;
    }
    break;
  case SpdmSessionStateEstablished:
    if (IsRequester) {
      SecuredMessageContext->ApplicationSecret.RequestDataSequenceNumber = SequenceNumber;
    } else {
      SecuredMessageContext->ApplicationSecret.ResponseDataSequenceNumber = SequenceNumber;
    }
    break;
  }

  RecordHeaderSize = sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumInHeaderSize + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_2);

  switch (SessionType) {
  case SpdmSessionTypeEncMac:
    if (SecuredMessageSize < RecordHeaderSize + AeadBlockSize + AeadTagSize) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    RecordHeader1 = (VOID *)SecuredMessage;
    RecordHeader2 = (VOID *)((UINT8 *)RecordHeader1 + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumInHeaderSize);
    if (RecordHeader1->SessionId != SessionId) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    if (CompareMem (RecordHeader1 + 1, &SequenceNumInHeader, SequenceNumInHeaderSize) != 0) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    if (RecordHeader2->Length > SecuredMessageSize - RecordHeaderSize) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    if (RecordHeader2->Length < AeadTagSize) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    CipherTextSize = (RecordHeader2->Length - AeadTagSize) / AeadBlockSize * AeadBlockSize;
    if (CipherTextSize > sizeof(DecMessage)) {
      return RETURN_OUT_OF_RESOURCES;
    }
    ZeroMem (DecMessage, sizeof(DecMessage));
    EncMsgHeader = (VOID *)(RecordHeader2 + 1);
    AData = (UINT8 *)RecordHeader1;
    EncMsg = (UINT8 *)EncMsgHeader;
    DecMsg = (UINT8 *)DecMessage;
    EncMsgHeader = (VOID *)DecMsg;
    Tag = (UINT8 *)RecordHeader1 + RecordHeaderSize + CipherTextSize;
    Result = SpdmAeadDecryption (
              SecuredMessageContext->AEADCipherSuite,
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
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    PlainTextSize = EncMsgHeader->ApplicationDataLength;
    if (PlainTextSize > CipherTextSize) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }

    ASSERT (*AppMessageSize >= PlainTextSize);
    if (*AppMessageSize < PlainTextSize) {
      *AppMessageSize = PlainTextSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *AppMessageSize = PlainTextSize;
    CopyMem (AppMessage, EncMsgHeader + 1, PlainTextSize);
    break;

  case SpdmSessionTypeMacOnly:
    if (SecuredMessageSize < RecordHeaderSize + AeadTagSize) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    RecordHeader1 = (VOID *)SecuredMessage;
    RecordHeader2 = (VOID *)((UINT8 *)RecordHeader1 + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumInHeaderSize);
    if (RecordHeader1->SessionId != SessionId) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    if (CompareMem (RecordHeader1 + 1, &SequenceNumInHeader, SequenceNumInHeaderSize) != 0) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    if (RecordHeader2->Length > SecuredMessageSize - RecordHeaderSize) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    if (RecordHeader2->Length < AeadTagSize) {
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }
    AData = (UINT8 *)RecordHeader1;
    Tag = (UINT8 *)RecordHeader1 + RecordHeaderSize + RecordHeader2->Length - AeadTagSize;
    Result = SpdmAeadDecryption (
              SecuredMessageContext->AEADCipherSuite,
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
      SpdmSecuredMessageSetLastSpdmErrorStruct (SpdmSecuredMessageContext, &SpdmError);
      return RETURN_SECURITY_VIOLATION;
    }

    PlainTextSize = RecordHeader2->Length - AeadTagSize;
    ASSERT (*AppMessageSize >= PlainTextSize);
    if (*AppMessageSize < PlainTextSize) {
      *AppMessageSize = PlainTextSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *AppMessageSize = PlainTextSize;
    CopyMem (AppMessage, RecordHeader2 + 1, PlainTextSize);
    break;

  default:
    ASSERT(FALSE);
    return RETURN_UNSUPPORTED;
  }

  return RETURN_SUCCESS;
}
