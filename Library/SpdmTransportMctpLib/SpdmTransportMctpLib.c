/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmTransportMctpLib.h>
#include <IndustryStandard/MctpBinding.h>

#define MCTP_ALIGNMENT 1
#define MCTP_SEQUENCE_NUMBER_COUNT 2
#define MCTP_MAX_RANDOM_NUMBER_COUNT 32

/**
  Get sequence number in an SPDM secure message.

  This value is transport layer specific.

  @param SequenceNumber        The current sequence number used to encode or decode message.
  @param SequenceNumberBuffer  A buffer to hold the sequence number output used in the secured message.
                               The size in byte of the output buffer shall be 8.

  @return Size in byte of the SequenceNumberBuffer.
          It shall be no greater than 8.
          0 means no sequence number is required.
**/
UINT8
EFIAPI
MctpGetSequenceNumber (
  IN     UINT64     SequenceNumber,
  IN OUT UINT8      *SequenceNumberBuffer
  )
{
  CopyMem (SequenceNumberBuffer, &SequenceNumber, MCTP_SEQUENCE_NUMBER_COUNT);
  return MCTP_SEQUENCE_NUMBER_COUNT;
}

/**
  Return max random number count in an SPDM secure message.

  This value is transport layer specific.

  @return Max random number count in an SPDM secured message.
          0 means no randum number is required.
**/
UINT32
EFIAPI
MctpGetMaxRandomNumberCount (
  VOID
  )
{
  return MCTP_MAX_RANDOM_NUMBER_COUNT;
}

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
MctpEncodeMessage (
  IN     UINT32               *SessionId,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  )
{
  UINTN                       AlignedMessageSize;
  UINTN                       Alignment;
  MCTP_MESSAGE_HEADER         *MctpMessageHeader;

  Alignment = MCTP_ALIGNMENT;
  AlignedMessageSize = (MessageSize + (Alignment - 1)) & ~(Alignment - 1);

  ASSERT (*TransportMessageSize >= AlignedMessageSize + sizeof(MCTP_MESSAGE_HEADER));
  if (*TransportMessageSize < AlignedMessageSize + sizeof(MCTP_MESSAGE_HEADER)) {
    *TransportMessageSize = AlignedMessageSize + sizeof(MCTP_MESSAGE_HEADER);
    return RETURN_BUFFER_TOO_SMALL;
  }
  *TransportMessageSize = AlignedMessageSize + sizeof(MCTP_MESSAGE_HEADER);
  MctpMessageHeader = TransportMessage;
  if (SessionId != NULL) {
    MctpMessageHeader->MessageType = MCTP_MESSAGE_TYPE_SECURED_MCTP;
    ASSERT (*SessionId == *(UINT32 *)(Message));
    if (*SessionId != *(UINT32 *)(Message)) {
      return RETURN_UNSUPPORTED;
    }
  } else {
    MctpMessageHeader->MessageType = MCTP_MESSAGE_TYPE_SPDM;
  }
  CopyMem ((UINT8 *)TransportMessage + sizeof(MCTP_MESSAGE_HEADER), Message, MessageSize);
  ZeroMem ((UINT8 *)TransportMessage + sizeof(MCTP_MESSAGE_HEADER) + MessageSize, *TransportMessageSize - sizeof(MCTP_MESSAGE_HEADER) - MessageSize);
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
MctpDecodeMessage (
     OUT UINT32               **SessionId,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  )
{
  UINTN                       Alignment;
  MCTP_MESSAGE_HEADER         *MctpMessageHeader;

  Alignment = MCTP_ALIGNMENT;

  ASSERT (TransportMessageSize > sizeof(MCTP_MESSAGE_HEADER));
  if (TransportMessageSize <= sizeof(MCTP_MESSAGE_HEADER)) {
    return RETURN_UNSUPPORTED;
  }

  MctpMessageHeader = TransportMessage;

  switch (MctpMessageHeader->MessageType) {
  case MCTP_MESSAGE_TYPE_SECURED_MCTP:
    ASSERT (SessionId != NULL);
    if (SessionId == NULL) {
      return RETURN_UNSUPPORTED;
    }
    if (TransportMessageSize <= sizeof(MCTP_MESSAGE_HEADER) + sizeof(UINT32)) {
      return RETURN_UNSUPPORTED;
    }
    *SessionId = (UINT32 *)((UINT8 *)TransportMessage + sizeof(MCTP_MESSAGE_HEADER));
    break;
  case MCTP_MESSAGE_TYPE_SPDM:
    if (SessionId != NULL) {
      *SessionId = NULL;
    }
    break;
  default:
    return RETURN_UNSUPPORTED;
  }

  ASSERT (((TransportMessageSize - sizeof(MCTP_MESSAGE_HEADER)) & (Alignment - 1)) == 0);

  if (*MessageSize < TransportMessageSize - sizeof(MCTP_MESSAGE_HEADER)) {
    //
    // Handle special case for the side effect of alignment
    // Caller may allocate a good enough buffer without considering alignment.
    // Here we will not copy all the message and ignore the the last padding bytes.
    //
    if (*MessageSize + Alignment - 1 >= TransportMessageSize - sizeof(MCTP_MESSAGE_HEADER)) {
      CopyMem (Message, (UINT8 *)TransportMessage + sizeof(MCTP_MESSAGE_HEADER), *MessageSize);
      return RETURN_SUCCESS;
    }
    ASSERT (*MessageSize >= TransportMessageSize - sizeof(MCTP_MESSAGE_HEADER));
    *MessageSize = TransportMessageSize - sizeof(MCTP_MESSAGE_HEADER);
    return RETURN_BUFFER_TOO_SMALL;
  }
  *MessageSize = TransportMessageSize - sizeof(MCTP_MESSAGE_HEADER);
  CopyMem (Message, (UINT8 *)TransportMessage + sizeof(MCTP_MESSAGE_HEADER), *MessageSize);
  return RETURN_SUCCESS;
}

