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
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  )
{
  RETURN_STATUS                       Status;
  TRANSPORT_ENCODE_MESSAGE_FUNC       TransportEncodeMessage;
  UINT8                               AppMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               AppMessageSize;
  UINT8                               SecuredMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               SecuredMessageSize;

  TransportEncodeMessage = TestEncodeMessage;
  if (SessionId != NULL) {
    AppMessageSize = sizeof(AppMessage);
    Status = TransportEncodeMessage (
                NULL,
                SpdmMessageSize,
                SpdmMessage,
                &AppMessageSize,
                AppMessage
                );
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_ERROR, "TransportEncodeMessage - %p\n", Status));
      return RETURN_UNSUPPORTED;
    }

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
    Status = TransportEncodeMessage (
                NULL,
                SpdmMessageSize,
                SpdmMessage,
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
  IN     BOOLEAN              IsRequester,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *SpdmMessageSize,
     OUT VOID                 *SpdmMessage
  )
{
  RETURN_STATUS                       Status;
  TRANSPORT_DECODE_MESSAGE_FUNC       TransportDecodeMessage;
  UINT32                              *SecuredMessageSessionId;
  UINT8                               SecuredMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               SecuredMessageSize;
  UINT8                               AppMessage[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                               AppMessageSize;

  TransportDecodeMessage = TestDecodeMessage;
  SecuredMessageSessionId = NULL;
  SecuredMessageSize = sizeof(SecuredMessage);
  if (SessionId == NULL) {
    // Expect normal message
    Status = TransportDecodeMessage (
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
