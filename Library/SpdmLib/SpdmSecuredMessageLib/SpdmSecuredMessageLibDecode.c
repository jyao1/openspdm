/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmSecuredMessageLib.h>

#include <IndustryStandard/SpdmSecuredMessage.h>
#include "SpdmCommonLibInternal.h"

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
  UINT8                              *AData;
  UINT8                              *EncMsg;
  UINT8                              *DecMsg;
  UINT8                              *Tag;
  SPDM_SECURED_MESSAGE_ADATA_HEADER  *RecordHeader;
  SPDM_SECURED_MESSAGE_CIPHER_HEADER *EncMsgHeader;
  BOOLEAN                            Result;
  VOID                               *Key;
  UINT8                              Salt[MAX_AEAD_IV_SIZE];
  SPDM_SESSION_INFO                  *SessionInfo;
  SPDM_SESSION_TYPE                  SessionType;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  SessionType = SpdmGetSessionType (SpdmContext);
  ASSERT ((SessionType == SpdmSessionTypeMacOnly) || (SessionType == SpdmSessionTypeEncMac));

  switch (SessionInfo->SessionState) {
  case SpdmStateHandshaking:
    if (IsRequester) {
      Key = SessionInfo->HandshakeSecret.RequestHandshakeEncryptionKey;
      CopyMem (Salt, SessionInfo->HandshakeSecret.RequestHandshakeSalt, SessionInfo->AeadIvSize);
      *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber;
      SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber ++;
    } else {
      Key = SessionInfo->HandshakeSecret.ResponseHandshakeEncryptionKey;
      CopyMem (Salt, SessionInfo->HandshakeSecret.ResponseHandshakeSalt, SessionInfo->AeadIvSize);
      *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->HandshakeSecret.ResponseHandshakeSequenceNumber;
      SessionInfo->HandshakeSecret.ResponseHandshakeSequenceNumber ++;
    }
    break;
  case SpdmStateEstablished:
    if (IsRequester) {
      Key = SessionInfo->ApplicationSecret.RequestDataEncryptionKey;
      CopyMem (Salt, SessionInfo->ApplicationSecret.RequestDataSalt, SessionInfo->AeadIvSize);
      *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->ApplicationSecret.RequestDataSequenceNumber;
      SessionInfo->ApplicationSecret.RequestDataSequenceNumber ++;
    } else {
      Key = SessionInfo->ApplicationSecret.ResponseDataEncryptionKey;
      CopyMem (Salt, SessionInfo->ApplicationSecret.ResponseDataSalt, SessionInfo->AeadIvSize);
      *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->ApplicationSecret.ResponseDataSequenceNumber;
      SessionInfo->ApplicationSecret.ResponseDataSequenceNumber ++;
    }
    break;
  default:
    ASSERT(FALSE);
    return RETURN_UNSUPPORTED;
    break;
  }

  AeadBlockSize = GetSpdmAeadBlockSize (SpdmContext);
  AeadTagSize = GetSpdmAeadTagSize (SpdmContext);

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
    Result = SpdmAeadDecryption (
              SpdmContext,
              Key,
              SessionInfo->AeadKeySize,
              Salt,
              SessionInfo->AeadIvSize,
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
    Result = SpdmAeadDecryption (
              SpdmContext,
              Key,
              SessionInfo->AeadKeySize,
              Salt,
              SessionInfo->AeadIvSize,
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

RETURN_STATUS
EFIAPI
SpdmDecodeMessage (
  IN     VOID                 *SpdmContext,
     OUT UINT32               **SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *SpdmMessageSize,
     OUT VOID                 *SpdmMessage
  )
{
  RETURN_STATUS                       Status;
  SPDM_SESSION_INFO                   *SessionInfo;
  UINT32                              *SecuredMessageSessionId;
  SPDM_TRANSPORT_DECODE_MESSAGE_FUNC  TransportDecodeMessage;
  UINT8                               SecuredMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               SecuredMessageSize;
  UINT8                               AppMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               AppMessageSize;

  SpdmGetTransportLayerFunc (SpdmContext, NULL, &TransportDecodeMessage);
  ASSERT (TransportDecodeMessage != NULL);
  if (TransportDecodeMessage == NULL) {
    return RETURN_UNSUPPORTED;
  }

  SecuredMessageSessionId = NULL;
  SecuredMessageSize = sizeof(SecuredMessage);
  if (SessionId == NULL) {
    // Expect normal message
    Status = TransportDecodeMessage (
                SpdmContext,
                &SecuredMessageSessionId,
                TransportMessageSize,
                TransportMessage,
                SpdmMessageSize,
                SpdmMessage
                );
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "TransportDecodeMessage - %p\n", Status));
      return RETURN_UNSUPPORTED;
    }
    if (SecuredMessageSessionId == NULL) {
      return RETURN_SUCCESS;
    } else {
      // but get secured message - cannot handle it.
      DEBUG ((DEBUG_ERROR, "TransportDecodeMessage - expect normal but got session (%08x)\n", *SecuredMessageSessionId));
      return RETURN_UNSUPPORTED;
    }
  }

  // Expect secured message
  Status = TransportDecodeMessage (
              SpdmContext,
              &SecuredMessageSessionId,
              TransportMessageSize,
              TransportMessage,
              &SecuredMessageSize,
              SecuredMessage
              );
  if (RETURN_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "TransportDecodeMessage - %p\n", Status));
    return RETURN_UNSUPPORTED;
  }

  if (SecuredMessageSessionId != NULL) {
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, *SecuredMessageSessionId);
    if (SessionInfo == NULL) {
      DEBUG ((DEBUG_ERROR, "SpdmGetSessionInfoViaSessionId (%08x) - ERROR\n", *SecuredMessageSessionId));
      return RETURN_UNSUPPORTED;
    }
    *SessionId = SecuredMessageSessionId;

    AppMessageSize = sizeof(AppMessage);
    Status = SpdmDecodeSecuredMessage (
               SpdmContext,
               *SecuredMessageSessionId,
               IsRequester,
               SecuredMessageSize,
               SecuredMessage,
               &AppMessageSize,
               AppMessage
               );
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "SpdmDecodeSecuredMessage - %p\n", Status));
      return RETURN_UNSUPPORTED;
    }

    Status = TransportDecodeMessage (
                SpdmContext,
                &SecuredMessageSessionId,
                AppMessageSize,
                AppMessage,
                SpdmMessageSize,
                SpdmMessage
                );
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "TransportDecodeMessage - %p\n", Status));
      return RETURN_UNSUPPORTED;
    }
    if (SecuredMessageSessionId == NULL) {
      return RETURN_SUCCESS;
    } else {
      // but get encapsulated secured message - cannot handle it.
      DEBUG ((DEBUG_ERROR, "TransportDecodeMessage - expect encapsulated normal but got session (%08x)\n", *SecuredMessageSessionId));
      return RETURN_UNSUPPORTED;
    }
  } else {
    // but get non-secured message - cannot handle it.
    DEBUG ((DEBUG_ERROR, "TransportDecodeMessage - expect session but got normal\n"));
    return RETURN_UNSUPPORTED;
  }
}

