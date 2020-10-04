/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmSecuredMessageLib.h>

#include <IndustryStandard/SpdmSecureMessage.h>
#include "SpdmCommonLibInternal.h"

RETURN_STATUS
SpdmEncryptSpdmMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *EncMessageSize,
     OUT VOID                 *EncMessage
  )
{
  UINTN                             TotalEncMessageSize;
  UINTN                             PlainTextSize;
  UINTN                             CipherTextSize;
  UINTN                             AeadBlockSize;
  UINTN                             AeadTagSize;
  UINT8                             *AData;
  UINT8                             *EncMsg;
  UINT8                             *DecMsg;
  UINT8                             *Tag;
  SPDM_SECURE_MESSAGE_ADATA_HEADER  *RecordHeader;
  SPDM_SECURE_MESSAGE_CIPHER_HEADER *EncMsgHeader;
  BOOLEAN                           Result;
  VOID                              *Key;
  UINT8                             Salt[MAX_AEAD_IV_SIZE];
  SPDM_SESSION_INFO                 *SessionInfo;
  UINT32                            Alignment;
  SPDM_SESSION_TYPE                 SessionType;
  UINT8                             RandCount;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  SessionType = SpdmGetSessionType (SpdmContext);
  ASSERT ((SessionType == SpdmSessionTypeMacOnly) || (SessionType == SpdmSessionTypeEncMac));

  Alignment = SpdmGetAlignment (SpdmContext);

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

    PlainTextSize = sizeof(SPDM_SECURE_MESSAGE_CIPHER_HEADER) + SpdmMessageSize + RandCount;
    CipherTextSize = (PlainTextSize + AeadBlockSize - 1) / AeadBlockSize * AeadBlockSize;
    TotalEncMessageSize = sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER) + CipherTextSize + AeadTagSize;
    if ((TotalEncMessageSize & (Alignment - 1)) != 0) {
      TotalEncMessageSize = (TotalEncMessageSize + (Alignment - 1)) & ~(Alignment - 1);
    }

    ASSERT (*EncMessageSize >= TotalEncMessageSize);
    if (*EncMessageSize < TotalEncMessageSize) {
      *EncMessageSize = TotalEncMessageSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *EncMessageSize = TotalEncMessageSize;
    RecordHeader = (VOID *)EncMessage;
    RecordHeader->SessionId = SessionId;
    RecordHeader->Length = (UINT16)(CipherTextSize + AeadTagSize);
    EncMsgHeader = (VOID *)(RecordHeader + 1);
    EncMsgHeader->ApplicationDataLength = (UINT16)SpdmMessageSize;
    CopyMem (EncMsgHeader + 1, SpdmMessage, SpdmMessageSize);
    RandomBytes ((UINT8 *)EncMsgHeader + sizeof(SPDM_SECURE_MESSAGE_CIPHER_HEADER) + SpdmMessageSize, RandCount);

    AData = (UINT8 *)RecordHeader;
    EncMsg = (UINT8 *)EncMsgHeader;
    DecMsg = (UINT8 *)EncMsgHeader;
    Tag = (UINT8 *)RecordHeader + sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER) + CipherTextSize;

    Result = SpdmAeadEncryption (
              SpdmContext,
              Key,
              SessionInfo->AeadKeySize,
              Salt,
              SessionInfo->AeadIvSize,
              (UINT8 *)AData,
              sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER),
              DecMsg,
              CipherTextSize,
              Tag,
              AeadTagSize,
              EncMsg,
              &CipherTextSize
              );
  } else { // SessionType == SpdmSessionTypeMacOnly
    TotalEncMessageSize = sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER) + SpdmMessageSize + AeadTagSize;
    if ((TotalEncMessageSize & (Alignment - 1)) != 0) {
      TotalEncMessageSize = (TotalEncMessageSize + (Alignment - 1)) & ~(Alignment - 1);
    }

    ASSERT (*EncMessageSize >= TotalEncMessageSize);
    if (*EncMessageSize < TotalEncMessageSize) {
      *EncMessageSize = TotalEncMessageSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *EncMessageSize = TotalEncMessageSize;
    RecordHeader = (VOID *)EncMessage;
    RecordHeader->SessionId = SessionId;
    RecordHeader->Length = (UINT16)(SpdmMessageSize + AeadTagSize);
    CopyMem (RecordHeader + 1, SpdmMessage, SpdmMessageSize);
    AData = (UINT8 *)RecordHeader;
    Tag = (UINT8 *)RecordHeader + sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER) + SpdmMessageSize;

    Result = SpdmAeadEncryption (
              SpdmContext,
              Key,
              SessionInfo->AeadKeySize,
              Salt,
              SessionInfo->AeadIvSize,
              (UINT8 *)AData,
              sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER) + SpdmMessageSize,
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
SpdmEncodeSpdmMessageSession (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  )
{
  RETURN_STATUS                      Status;
  SPDM_SESSION_INFO                  *SessionInfo;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  switch (SessionInfo->SessionState) {
  case SpdmStateHandshaking:
  case SpdmStateEstablished:
    ZeroMem (TransportMessage, *TransportMessageSize);
    Status = SpdmEncryptSpdmMessage (SpdmContext, SessionId, IsRequester, SpdmMessageSize, SpdmMessage, TransportMessageSize, TransportMessage);
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "SpdmEncryptSpdmMessage - %p\n", Status));
    }
    return Status;
  default:
    ASSERT (FALSE);
    return RETURN_OUT_OF_RESOURCES;
  }
}

RETURN_STATUS
SpdmEncodeSpdmMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  )
{
  UINTN                          CalcTransportMessageSize;
  UINT32                         Alignment;

  Alignment = SpdmGetAlignment (SpdmContext);

  if (SessionId != NULL) {
    return SpdmEncodeSpdmMessageSession (SpdmContext, *SessionId, IsRequester, SpdmMessageSize, SpdmMessage, TransportMessageSize, TransportMessage);
  }

  CalcTransportMessageSize = (SpdmMessageSize + (Alignment - 1)) & ~(Alignment - 1);

  ASSERT (*TransportMessageSize >= CalcTransportMessageSize);
  if (*TransportMessageSize < CalcTransportMessageSize) {
    *TransportMessageSize = CalcTransportMessageSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *TransportMessageSize = CalcTransportMessageSize;
  CopyMem (TransportMessage, SpdmMessage, SpdmMessageSize);
  ZeroMem ((UINT8 *)TransportMessage + SpdmMessageSize, CalcTransportMessageSize - SpdmMessageSize);

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmEncodeRequest (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  )
{
  return SpdmEncodeSpdmMessage (
           SpdmContext,
           SessionId,
           TRUE,
           RequestSize,
           Request,
           MessageSize,
           Message
           );
}

RETURN_STATUS
EFIAPI
SpdmEncodeResponse (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                ResponseSize,
  IN     VOID                 *Response,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  )
{
  return SpdmEncodeSpdmMessage (
           SpdmContext,
           SessionId,
           FALSE,
           ResponseSize,
           Response,
           MessageSize,
           Message
           );
}
