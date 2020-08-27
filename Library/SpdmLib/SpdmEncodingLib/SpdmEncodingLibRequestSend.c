/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmEncodingLibInternal.h"

RETURN_STATUS
SpdmEncryptRequest (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *EncRequestSize,
     OUT VOID                 *EncRequest
  )
{
  UINT8                          *WrappedRequest;
  UINTN                          WrappedRequestSize;
  UINTN                          PlainTextSize;
  UINTN                          CipherTextSize;
  UINTN                          AeadBlockSize;
  UINTN                          AeadTagSize;
  UINT8                          *AData;
  UINT8                          *EncMsg;
  UINT8                          *DecMsg;
  UINT8                          *Tag;
  MCTP_MESSAGE_PLAINTEXT_HEADER  *RecordHeader;
  MCTP_MESSAGE_CIPHERTEXT_HEADER *EncMsgHeader;
  AEAD_ENCRYPT                   AeadEncFunc;
  BOOLEAN                        Result;
  VOID                           *Key;
  UINT8                          Salt[MAX_AEAD_IV_SIZE];
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
    Key = SessionInfo->HandshakeSecret.RequestHandshakeEncryptionKey;
    CopyMem (Salt, SessionInfo->HandshakeSecret.RequestHandshakeSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber;
    SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber ++;
    break;
  case SpdmStateEstablished:
    Key = SessionInfo->ApplicationSecret.RequestDataEncryptionKey;
    CopyMem (Salt, SessionInfo->ApplicationSecret.RequestDataSalt, SessionInfo->AeadIvSize);
    *(UINT64 *)Salt = *(UINT64 *)Salt ^ SessionInfo->ApplicationSecret.RequestDataSequenceNumber;
    SessionInfo->ApplicationSecret.RequestDataSequenceNumber ++;
    break;
  default:
    ASSERT(FALSE);
    return RETURN_UNSUPPORTED;
    break;
  }

  AeadEncFunc = GetSpdmAeadEncFunc (SpdmContext);
  AeadBlockSize = GetSpdmAeadBlockSize (SpdmContext);
  AeadTagSize = GetSpdmAeadTagSize (SpdmContext);
  PlainTextSize = sizeof(MCTP_MESSAGE_CIPHERTEXT_HEADER) + RequestSize;
  CipherTextSize = (PlainTextSize + AeadBlockSize - 1) / AeadBlockSize * AeadBlockSize;
  WrappedRequestSize = sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) + CipherTextSize + AeadTagSize;
  if ((Alignment > 1) && 
      ((WrappedRequestSize & (Alignment - 1)) != 0)) {
    WrappedRequestSize = (WrappedRequestSize + (Alignment - 1)) & ~(Alignment - 1);
  }

  ASSERT (*EncRequestSize >= WrappedRequestSize);
  if (*EncRequestSize < WrappedRequestSize) {
    *EncRequestSize = WrappedRequestSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *EncRequestSize = WrappedRequestSize;
  WrappedRequest = EncRequest;
  RecordHeader = (VOID *)WrappedRequest;
  RecordHeader->SessionId = SessionId;
  RecordHeader->Length = (UINT16)WrappedRequestSize;
  EncMsgHeader = (VOID *)(RecordHeader + 1);
  EncMsgHeader->TrueLength = (UINT16)RequestSize;
  EncMsgHeader->EncapsulatedMessageType.MessageType = MCTP_MESSAGE_TYPE_SPDM;
  CopyMem (EncMsgHeader + 1, Request, RequestSize);
  AData = (UINT8 *)RecordHeader;
  EncMsg = (UINT8 *)EncMsgHeader;
  DecMsg = (UINT8 *)EncMsgHeader;
  Tag = WrappedRequest + sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER) + CipherTextSize;
  Result = AeadEncFunc (
             Key,
             SessionInfo->AeadKeySize,
             Salt,
             SessionInfo->AeadIvSize,
             (UINT8 *)AData,
             sizeof(MCTP_MESSAGE_PLAINTEXT_HEADER),
             DecMsg,
             CipherTextSize,
             Tag,
             AeadTagSize,
             EncMsg,
             &CipherTextSize
             );
  if (!Result) {
    return RETURN_OUT_OF_RESOURCES;
  }
  return RETURN_SUCCESS;
}

RETURN_STATUS
SpdmEncodeRequestSession (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
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
    ZeroMem (Message, *MessageSize);
    Status = SpdmEncryptRequest (SpdmContext, SessionId, RequestSize, Request, MessageSize, Message);
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "SpdmEncryptRequest - %p\n", Status));
    }
    return Status;
  default:
    ASSERT (FALSE);
    return RETURN_OUT_OF_RESOURCES;
  }
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
  UINTN                          CalcMessageSize;
  UINT32                         Alignment;

  Alignment = SpdmGetAlignment (SpdmContext);

  if (SessionId != NULL) {
    return SpdmEncodeRequestSession (SpdmContext, *SessionId, RequestSize, Request, MessageSize, Message);
  }

  if (Alignment > 1) {
    CalcMessageSize = (RequestSize + (Alignment - 1)) & ~(Alignment - 1);
  } else {
    CalcMessageSize = RequestSize;
  }

  ASSERT (*MessageSize >= CalcMessageSize);
  if (*MessageSize < CalcMessageSize) {
    *MessageSize = CalcMessageSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *MessageSize = CalcMessageSize;
  CopyMem (Message, Request, RequestSize);
  ZeroMem ((UINT8 *)Message + RequestSize, CalcMessageSize - RequestSize);

  return RETURN_SUCCESS;
}

