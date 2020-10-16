/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmTransportTestLib.h>

#define TEST_MESSAGE_TYPE_SPDM                0x01
#define TEST_MESSAGE_TYPE_SECURED_TEST        0x02

#define TEST_ALIGNMENT 1

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
  )
{
  UINTN                       AlignedMessageSize;
  UINTN                       Alignment = TEST_ALIGNMENT;

  AlignedMessageSize = (MessageSize + (Alignment - 1)) & ~(Alignment - 1);

  ASSERT (*TransportMessageSize >= AlignedMessageSize + 1);
  if (*TransportMessageSize < AlignedMessageSize + 1) {
    *TransportMessageSize = AlignedMessageSize + 1;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *TransportMessageSize = AlignedMessageSize + 1;
  if (SessionId != NULL) {
    *(UINT8 *)TransportMessage = TEST_MESSAGE_TYPE_SECURED_TEST;
    ASSERT (*SessionId == *(UINT32 *)(Message));
    if (*SessionId != *(UINT32 *)(Message)) {
      return RETURN_UNSUPPORTED;
    }
  } else {
    *(UINT8 *)TransportMessage = TEST_MESSAGE_TYPE_SPDM;
  }
  CopyMem ((UINT8 *)TransportMessage + 1, Message, MessageSize);
  ZeroMem ((UINT8 *)TransportMessage + 1 + MessageSize, *TransportMessageSize - 1 - MessageSize);
  return RETURN_SUCCESS;
}

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
  )
{
  UINTN                       Alignment = TEST_ALIGNMENT;

  ASSERT (TransportMessageSize > 1);
  if (TransportMessageSize <= 1) {
    return RETURN_UNSUPPORTED;
  }
  switch (*(UINT8 *)TransportMessage) {
  case TEST_MESSAGE_TYPE_SECURED_TEST:
    ASSERT (SessionId != NULL);
    if (SessionId == NULL) {
      return RETURN_UNSUPPORTED;
    }
    if (TransportMessageSize <= 1 + sizeof(UINT32)) {
      return RETURN_UNSUPPORTED;
    }
    *SessionId = (UINT32 *)((UINT8 *)TransportMessage + 1);
    break;
  case TEST_MESSAGE_TYPE_SPDM:
    if (SessionId != NULL) {
      *SessionId = NULL;
    }
    break;
  default:
    return RETURN_UNSUPPORTED;
  }

  ASSERT (((TransportMessageSize - 1) & (Alignment - 1)) == 0);

  if (*MessageSize < TransportMessageSize - 1) {
    //
    // Handle special case for the side effect of alignment
    // Caller may allocate a good enough buffer without considering alignment.
    // Here we will not copy all the message and ignore the the last padding bytes.
    //
    if (*MessageSize + Alignment - 1 >= TransportMessageSize - 1) {
      CopyMem (Message, (UINT8 *)TransportMessage + 1, *MessageSize);
      return RETURN_SUCCESS;
    }
    ASSERT (*MessageSize >= TransportMessageSize - 1);
    *MessageSize = TransportMessageSize - 1;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *MessageSize = TransportMessageSize - 1;
  CopyMem (Message, (UINT8 *)TransportMessage + 1, *MessageSize);
  return RETURN_SUCCESS;
}

