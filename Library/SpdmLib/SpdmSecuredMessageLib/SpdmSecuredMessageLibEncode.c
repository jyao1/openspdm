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
  UINT8                              RandCount;

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

    Result = SpdmAeadEncryption (
              SpdmContext,
              Key,
              SessionInfo->AeadKeySize,
              Salt,
              SessionInfo->AeadIvSize,
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

    Result = SpdmAeadEncryption (
              SpdmContext,
              Key,
              SessionInfo->AeadKeySize,
              Salt,
              SessionInfo->AeadIvSize,
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
SpdmEncodeMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  )
{
  RETURN_STATUS                       Status;
  SPDM_SESSION_INFO                   *SessionInfo;
  SPDM_TRANSPORT_ENCODE_MESSAGE_FUNC  TransportEncodeMessage;
  UINT8                               AppMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               AppMessageSize;
  UINT8                               SecuredMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               SecuredMessageSize;

  SpdmGetTransportLayerFunc (SpdmContext, &TransportEncodeMessage, NULL);
  ASSERT (TransportEncodeMessage != NULL);
  if (TransportEncodeMessage == NULL) {
    return RETURN_UNSUPPORTED;
  }

  if (SessionId != NULL) {
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, *SessionId);
    if (SessionInfo == NULL) {
      ASSERT (FALSE);
      return RETURN_UNSUPPORTED;
    }

    AppMessageSize = sizeof(AppMessage);
    Status = TransportEncodeMessage (
                SpdmContext,
                NULL,
                SpdmMessageSize,
                SpdmMessage,
                &AppMessageSize,
                AppMessage
                );
    ASSERT_RETURN_ERROR(Status);

    SecuredMessageSize = sizeof(SecuredMessage);
    Status = SpdmEncodeSecuredMessage (
               SpdmContext,
               *SessionId,
               IsRequester,
               AppMessageSize,
               AppMessage,
               &SecuredMessageSize,
               SecuredMessage
               );
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "SpdmEncodeSecuredMessage - %p\n", Status));
      return Status;
    }
    
    Status = TransportEncodeMessage (
                SpdmContext,
                SessionId,
                SecuredMessageSize,
                SecuredMessage,
                TransportMessageSize,
                TransportMessage
                );
    ASSERT_RETURN_ERROR(Status);
  } else {
    Status = TransportEncodeMessage (
                SpdmContext,
                NULL,
                SpdmMessageSize,
                SpdmMessage,
                TransportMessageSize,
                TransportMessage
                );
    ASSERT_RETURN_ERROR(Status);
  }

  return RETURN_SUCCESS;
}
