/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmTransportTestLib.h>

#define TEST_ALIGNMENT 1

RETURN_STATUS
TestEncodeMessage (
  IN     UINT32               *SessionId,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *MctpMessageSize,
     OUT VOID                 *MctpMessage
  )
{
  UINTN                       AlignedMessageSize;
  UINTN                       Alignment = TEST_ALIGNMENT;

  AlignedMessageSize = (MessageSize + (Alignment - 1)) & ~(Alignment - 1);

  ASSERT (*MctpMessageSize >= AlignedMessageSize + 1);
  if (*MctpMessageSize < AlignedMessageSize + 1) {
    *MctpMessageSize = AlignedMessageSize + 1;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *MctpMessageSize = AlignedMessageSize + 1;
  if (SessionId != NULL) {
    *(UINT8 *)MctpMessage = TEST_MESSAGE_TYPE_SECURED_TEST;
    ASSERT (*SessionId == *(UINT32 *)(Message));
    if (*SessionId != *(UINT32 *)(Message)) {
      return RETURN_UNSUPPORTED;
    }
  } else {
    *(UINT8 *)MctpMessage = TEST_MESSAGE_TYPE_SPDM;
  }
  CopyMem ((UINT8 *)MctpMessage + 1, Message, MessageSize);
  ZeroMem ((UINT8 *)MctpMessage + 1 + MessageSize, *MctpMessageSize - 1 - MessageSize);
  return RETURN_SUCCESS;
}

RETURN_STATUS
TestDecodeMessage (
     OUT UINT32               **SessionId,
  IN     UINTN                MctpMessageSize,
  IN     VOID                 *MctpMessage,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  )
{
  UINTN                       Alignment = TEST_ALIGNMENT;

  ASSERT (MctpMessageSize > 1);
  if (MctpMessageSize <= 1) {
    return RETURN_UNSUPPORTED;
  }
  switch (*(UINT8 *)MctpMessage) {
  case TEST_MESSAGE_TYPE_SECURED_TEST:
    ASSERT (SessionId != NULL);
    if (SessionId == NULL) {
      return RETURN_UNSUPPORTED;
    }
    if (MctpMessageSize <= 1 + sizeof(UINT32)) {
      return RETURN_UNSUPPORTED;
    }
    *SessionId = (UINT32 *)((UINT8 *)MctpMessage + 1);
    break;
  case TEST_MESSAGE_TYPE_SPDM:
    if (SessionId != NULL) {
      *SessionId = NULL;
    }
    break;
  default:
    return RETURN_UNSUPPORTED;
  }

  ASSERT (((MctpMessageSize - 1) & (Alignment - 1)) == 0);

  if (*MessageSize < MctpMessageSize - 1) {
    //
    // Handle special case for the side effect of alignment
    // Caller may allocate a good enough buffer without considering alignment.
    // Here we will not copy all the message and ignore the the last padding bytes.
    //
    if (*MessageSize + Alignment - 1 >= MctpMessageSize - 1) {
      CopyMem (Message, (UINT8 *)MctpMessage + 1, *MessageSize);
      return RETURN_SUCCESS;
    }
    ASSERT (*MessageSize >= MctpMessageSize - 1);
    *MessageSize = MctpMessageSize - 1;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *MessageSize = MctpMessageSize - 1;
  CopyMem (Message, (UINT8 *)MctpMessage + 1, *MessageSize);
  return RETURN_SUCCESS;
}

