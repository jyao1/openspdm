/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmTransportTestLib.h>
#include <Library/SpdmSecuredMessageLib.h>

/**
  Encode a normal message or secured message to a transport message.

  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a source buffer to store the message.
  @param  TransportMessageSize         Size in bytes of the transport message data buffer.
  @param  TransportMessage             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
**/
RETURN_STATUS
TestEncodeMessage (
  IN     UINT32               *SessionId,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  );

/**
  Decode a transport message to a normal message or secured message.

  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If *SessionId is NULL, it is a normal message.
                                       If *SessionId is NOT NULL, it is a secured message.
  @param  TransportMessageSize         Size in bytes of the transport message data buffer.
  @param  TransportMessage             A pointer to a source buffer to store the transport message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.
  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
**/
RETURN_STATUS
TestDecodeMessage (
     OUT UINT32               **SessionId,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  );

/**
  Encode a normal message or secured message to a transport message.

  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a source buffer to store the message.
  @param  TransportMessageSize         Size in bytes of the transport message data buffer.
  @param  TransportMessage             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
**/
typedef
RETURN_STATUS
(*TRANSPORT_ENCODE_MESSAGE_FUNC) (
  IN     UINT32               *SessionId,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  );

/**
  Decode a transport message to a normal message or secured message.

  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If *SessionId is NULL, it is a normal message.
                                       If *SessionId is NOT NULL, it is a secured message.
  @param  TransportMessageSize         Size in bytes of the transport message data buffer.
  @param  TransportMessage             A pointer to a source buffer to store the transport message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.
  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
**/
typedef
RETURN_STATUS
(*TRANSPORT_DECODE_MESSAGE_FUNC) (
     OUT UINT32               **SessionId,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  );

/**
  Encode an SPDM or APP message to a transport layer message.

  For normal SPDM message, it adds the transport layer wrapper.
  For secured SPDM message, it encrypts a secured message then adds the transport layer wrapper.
  For secured APP message, it encrypts a secured message then adds the transport layer wrapper.

  The APP message is encoded to a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  IsAppMessage                 Indicates if it is an APP message or SPDM message.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a source buffer to store the message.
  @param  TransportMessageSize         Size in bytes of the transport message data buffer.
  @param  TransportMessage             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
**/
RETURN_STATUS
EFIAPI
SpdmTransportTestEncodeMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsAppMessage,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  )
{
  RETURN_STATUS                       Status;
  TRANSPORT_ENCODE_MESSAGE_FUNC       TransportEncodeMessage;
  UINT8                               AppMessageBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  VOID                                *AppMessage;
  UINTN                               AppMessageSize;
  UINT8                               SecuredMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               SecuredMessageSize;
  SPDM_SECURED_MESSAGE_CALLBACKS      SpdmSecuredMessageCallbacks;
  VOID                                *SecuredMessageContext;

  SpdmSecuredMessageCallbacks.Version = SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
  SpdmSecuredMessageCallbacks.GetSequenceNumber = TestGetSequenceNumber;
  SpdmSecuredMessageCallbacks.GetMaxRandomNumberCount = TestGetMaxRandomNumberCount;

  if (IsAppMessage && (SessionId == NULL)) {
    return RETURN_UNSUPPORTED;
  }

  TransportEncodeMessage = TestEncodeMessage;
  if (SessionId != NULL) {

    SecuredMessageContext = SpdmGetSecuredMessageContextViaSessionId (SpdmContext, *SessionId);
    if (SecuredMessageContext == NULL) {
      return RETURN_UNSUPPORTED;
    }

    if (!IsAppMessage) {
      // SPDM message to APP message
      AppMessage = AppMessageBuffer;
      AppMessageSize = sizeof(AppMessageBuffer);
      Status = TransportEncodeMessage (
                 NULL,
                 MessageSize,
                 Message,
                 &AppMessageSize,
                 AppMessageBuffer
                 );
      if (RETURN_ERROR(Status)) {
        DEBUG ((DEBUG_ERROR, "TransportEncodeMessage - %p\n", Status));
        return RETURN_UNSUPPORTED;
      }
    } else {
      AppMessage = Message;
      AppMessageSize = MessageSize;
    }
    // APP message to secured message
    SecuredMessageSize = sizeof(SecuredMessage);
    Status = SpdmEncodeSecuredMessage (
               SecuredMessageContext,
               *SessionId,
               IsRequester,
               AppMessageSize,
               AppMessage,
               &SecuredMessageSize,
               SecuredMessage,
               &SpdmSecuredMessageCallbacks
               );
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "SpdmEncodeSecuredMessage - %p\n", Status));
      return Status;
    }

    // secured message to secured MCTP message
    Status = TransportEncodeMessage (
                SessionId,
                SecuredMessageSize,
                SecuredMessage,
                TransportMessageSize,
                TransportMessage
                );
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "TransportEncodeMessage - %p\n", Status));
      return RETURN_UNSUPPORTED;
    }
  } else {
    // SPDM message to normal MCTP message
    Status = TransportEncodeMessage (
                NULL,
                MessageSize,
                Message,
                TransportMessageSize,
                TransportMessage
                );
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "TransportEncodeMessage - %p\n", Status));
      return RETURN_UNSUPPORTED;
    }
  }

  return RETURN_SUCCESS;
}

/**
  Decode an SPDM or APP message from a transport layer message.

  For normal SPDM message, it removes the transport layer wrapper,
  For secured SPDM message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
  For secured APP message, it removes the transport layer wrapper, then decrypts and verifies a secured message.

  The APP message is decoded from a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If *SessionId is NULL, it is a normal message.
                                       If *SessionId is NOT NULL, it is a secured message.
  @param  IsAppMessage                 Indicates if it is an APP message or SPDM message.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  TransportMessageSize         Size in bytes of the transport message data buffer.
  @param  TransportMessage             A pointer to a source buffer to store the transport message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.

  @retval RETURN_SUCCESS               The message is decoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
  @retval RETURN_UNSUPPORTED           The TransportMessage is unsupported.
**/
RETURN_STATUS
EFIAPI
SpdmTransportTestDecodeMessage (
  IN     VOID                 *SpdmContext,
     OUT UINT32               **SessionId,
     OUT BOOLEAN              *IsAppMessage,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  )
{
  RETURN_STATUS                       Status;
  TRANSPORT_DECODE_MESSAGE_FUNC       TransportDecodeMessage;
  UINT32                              *SecuredMessageSessionId;
  UINT8                               SecuredMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               SecuredMessageSize;
  UINT8                               AppMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               AppMessageSize;
  SPDM_SECURED_MESSAGE_CALLBACKS      SpdmSecuredMessageCallbacks;
  VOID                                *SecuredMessageContext;
  SPDM_ERROR_STRUCT                   SpdmError;

  SpdmError.ErrorCode = 0;
  SpdmError.SessionId = 0;
  SpdmSetLastSpdmErrorStruct (SpdmContext, &SpdmError);

  SpdmSecuredMessageCallbacks.Version = SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
  SpdmSecuredMessageCallbacks.GetSequenceNumber = TestGetSequenceNumber;
  SpdmSecuredMessageCallbacks.GetMaxRandomNumberCount = TestGetMaxRandomNumberCount;

  if ((SessionId == NULL) || (IsAppMessage == NULL)) {
    return RETURN_UNSUPPORTED;
  }

  TransportDecodeMessage = TestDecodeMessage;

  SecuredMessageSessionId = NULL;
  // Detect received message
  SecuredMessageSize = sizeof(SecuredMessage);
  Status = TransportDecodeMessage (
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
    *SessionId = SecuredMessageSessionId;
    
    SecuredMessageContext = SpdmGetSecuredMessageContextViaSessionId (SpdmContext, *SecuredMessageSessionId);
    if (SecuredMessageContext == NULL) {
      SpdmError.ErrorCode = SPDM_ERROR_CODE_INVALID_SESSION;
      SpdmError.SessionId = *SecuredMessageSessionId;
      SpdmSetLastSpdmErrorStruct (SpdmContext, &SpdmError);
      return RETURN_UNSUPPORTED;
    }

    // Secured message to APP message
    AppMessageSize = sizeof(AppMessage);
    Status = SpdmDecodeSecuredMessage (
               SecuredMessageContext,
               *SecuredMessageSessionId,
               IsRequester,
               SecuredMessageSize,
               SecuredMessage,
               &AppMessageSize,
               AppMessage,
               &SpdmSecuredMessageCallbacks
               );
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "SpdmDecodeSecuredMessage - %p\n", Status));
      SpdmSecuredMessageGetLastSpdmErrorStruct (SecuredMessageContext, &SpdmError);
      SpdmSetLastSpdmErrorStruct (SpdmContext, &SpdmError);
      return RETURN_UNSUPPORTED;
    }

    // APP message to SPDM message.
    Status = TransportDecodeMessage (
                &SecuredMessageSessionId,
                AppMessageSize,
                AppMessage,
                MessageSize,
                Message
                );
    if (RETURN_ERROR(Status)) {
      *IsAppMessage = TRUE;
      // just return APP message.
      if (*MessageSize < AppMessageSize) {
        *MessageSize = AppMessageSize;
        return RETURN_BUFFER_TOO_SMALL;
      }
      *MessageSize = AppMessageSize;
      CopyMem (Message, AppMessage, *MessageSize);
      return RETURN_SUCCESS;
    } else {
      *IsAppMessage = FALSE;
      if (SecuredMessageSessionId == NULL) {
        return RETURN_SUCCESS;
      } else {
        // get encapsulated secured message - cannot handle it.
        DEBUG ((DEBUG_ERROR, "TransportDecodeMessage - expect encapsulated normal but got session (%08x)\n", *SecuredMessageSessionId));
        return RETURN_UNSUPPORTED;
      }
    }
  } else {
    // get non-secured message
    Status = TransportDecodeMessage (
                &SecuredMessageSessionId,
                TransportMessageSize,
                TransportMessage,
                MessageSize,
                Message
                );
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "TransportDecodeMessage - %p\n", Status));
      return RETURN_UNSUPPORTED;
    }
    ASSERT (SecuredMessageSessionId == NULL);
    *SessionId = NULL;
    *IsAppMessage = FALSE;
    return RETURN_SUCCESS;
  }
}
