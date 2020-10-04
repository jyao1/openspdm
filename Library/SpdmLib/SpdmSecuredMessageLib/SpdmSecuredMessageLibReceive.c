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
SpdmDecryptSpdmMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *DecMessageSize,
     OUT VOID                 *DecMessage
  )
{
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
  SPDM_SESSION_TYPE                 SessionType;

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
    if (SpdmMessageSize < sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER) + AeadBlockSize + AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    RecordHeader = (VOID *)SpdmMessage;
    if (RecordHeader->SessionId != SessionId) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader->Length > SpdmMessageSize - sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER)) {
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
    Tag = (UINT8 *)RecordHeader + sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER) + CipherTextSize;
    Result = SpdmAeadDecryption (
              SpdmContext,
              Key,
              SessionInfo->AeadKeySize,
              Salt,
              SessionInfo->AeadIvSize,
              (UINT8 *)AData,
              sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER),
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

    ASSERT (*DecMessageSize >= PlainTextSize);
    if (*DecMessageSize < PlainTextSize) {
      *DecMessageSize = PlainTextSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *DecMessageSize = PlainTextSize;
    CopyMem (DecMessage, EncMsgHeader + 1, PlainTextSize);
  } else { // SessionType == SpdmSessionTypeMacOnly
    if (SpdmMessageSize < sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER) + AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    RecordHeader = (VOID *)SpdmMessage;
    if (RecordHeader->SessionId != SessionId) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader->Length > SpdmMessageSize - sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER)) {
      return RETURN_DEVICE_ERROR;
    }
    if (RecordHeader->Length < AeadTagSize) {
      return RETURN_DEVICE_ERROR;
    }
    AData = (UINT8 *)RecordHeader;
    Tag = (UINT8 *)RecordHeader + sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER) + RecordHeader->Length - AeadTagSize;
    Result = SpdmAeadDecryption (
              SpdmContext,
              Key,
              SessionInfo->AeadKeySize,
              Salt,
              SessionInfo->AeadIvSize,
              (UINT8 *)AData,
              sizeof(SPDM_SECURE_MESSAGE_ADATA_HEADER) + RecordHeader->Length - AeadTagSize,
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
    ASSERT (*DecMessageSize >= PlainTextSize);
    if (*DecMessageSize < PlainTextSize) {
      *DecMessageSize = PlainTextSize;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *DecMessageSize = PlainTextSize;
    CopyMem (DecMessage, RecordHeader + 1, PlainTextSize);
  }

  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmDecodeSpdmMessageSession (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *SpdmMessageSize,
     OUT VOID                 *SpdmMessage
  )
{
  RETURN_STATUS                  Status;
  SPDM_SESSION_INFO              *SessionInfo;
  UINT32                         Alignment;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  Alignment = SpdmGetAlignment (SpdmContext);

  switch (SessionInfo->SessionState) {
  case SpdmStateHandshaking:
  case SpdmStateEstablished:
    ASSERT ((TransportMessageSize & (Alignment - 1)) == 0);

    Status = SpdmDecryptSpdmMessage (SpdmContext, SessionId, IsRequester, TransportMessageSize, TransportMessage, SpdmMessageSize, SpdmMessage);
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "SpdmDecryptSpdmMessage - %p\n", Status));
    }
    return Status;
  default:
    ASSERT (FALSE);
    return RETURN_OUT_OF_RESOURCES;
  }
}

RETURN_STATUS
SpdmDecodeSpdmMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *SpdmMessageSize,
     OUT VOID                 *SpdmMessage
  )
{
  UINT32                         Alignment;

  Alignment = SpdmGetAlignment (SpdmContext);

  if (SessionId != NULL) {
    return SpdmDecodeSpdmMessageSession (SpdmContext, *SessionId, IsRequester, TransportMessageSize, TransportMessage, SpdmMessageSize, SpdmMessage);
  }

  ASSERT ((TransportMessageSize & (Alignment - 1)) == 0);

  if (*SpdmMessageSize < TransportMessageSize) {
    if (*SpdmMessageSize + Alignment - 1 >= TransportMessageSize) {
      CopyMem (SpdmMessage, TransportMessage, *SpdmMessageSize);
      return RETURN_SUCCESS;
    }
    ASSERT (*SpdmMessageSize >= TransportMessageSize);
    *SpdmMessageSize = TransportMessageSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *SpdmMessageSize = TransportMessageSize;
  CopyMem (SpdmMessage, TransportMessage, TransportMessageSize);

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmDecodeRequest (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *RequestSize,
     OUT VOID                 *Request
  )
{
  return SpdmDecodeSpdmMessage (
           SpdmContext,
           SessionId,
           TRUE,
           MessageSize,
           Message,
           RequestSize,
           Request
           );
}

RETURN_STATUS
EFIAPI
SpdmDecodeResponse (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  return SpdmDecodeSpdmMessage (
           SpdmContext,
           SessionId,
           FALSE,
           MessageSize,
           Message,
           ResponseSize,
           Response
           );
}

