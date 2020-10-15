/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmTransportTestLib.h>
#include <Library/SpdmSecuredMessageLib.h>

RETURN_STATUS
TestEncodeMessage (
  IN     UINT32               *SessionId,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *TestMessageSize,
     OUT VOID                 *TestMessage
  );

RETURN_STATUS
TestDecodeMessage (
     OUT UINT32               **SessionId,
  IN     UINTN                TestMessageSize,
  IN     VOID                 *TestMessage,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  );

typedef
RETURN_STATUS
(*TRANSPORT_ENCODE_MESSAGE_FUNC) (
  IN     UINT32               *SessionId,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  );

typedef
RETURN_STATUS
(*TRANSPORT_DECODE_MESSAGE_FUNC) (
     OUT UINT32               **SessionId,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  );

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

  if (IsAppMessage && (SessionId != NULL)) {
    return RETURN_UNSUPPORTED;
  }

  TransportEncodeMessage = TestEncodeMessage;
  if (SessionId != NULL) {
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
    // Secured message to APP message
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
