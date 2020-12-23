/** @file
  SPDM Test Transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_TEST_TRANSPORT_LIB_H__
#define __SPDM_TEST_TRANSPORT_LIB_H__

#include <Library/SpdmCommonLib.h>

#define TEST_MESSAGE_TYPE_SPDM                0x01
#define TEST_MESSAGE_TYPE_SECURED_TEST        0x02

typedef struct {
  UINT8    MessageType;
} TEST_MESSAGE_HEADER;

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
  );

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
  );

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
TestGetSequenceNumber (
  IN     UINT64     SequenceNumber,
  IN OUT UINT8      *SequenceNumberBuffer
  );

/**
  Return max random number count in an SPDM secure message.

  This value is transport layer specific.

  @return Max random number count in an SPDM secured message.
          0 means no randum number is required.
**/
UINT32
EFIAPI
TestGetMaxRandomNumberCount (
  VOID
  );

#endif