/** @file
  SPDM MCTP Transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_MCTP_TRANSPORT_LIB_H__
#define __SPDM_MCTP_TRANSPORT_LIB_H__

#include <Library/SpdmCommonLib.h>

/**
  Encode an SPDM message to a transport layer message.

  For normal SPDM message, it adds the transport layer wrapper.
  For secured SPDM message, it encrypts a secured message then adds the transport layer wrapper.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  SpdmMessageSize              Size in bytes of the SPDM message data buffer.
  @param  SpdmMessage                  A pointer to a source buffer to store the SPDM message.
  @param  TransportMessageSize         Size in bytes of the SPDM message data buffer.
  @param  TransportMessage             A pointer to a destination buffer to store the SPDM message.

  @retval RETURN_SUCCESS               The SPDM message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
**/
RETURN_STATUS
EFIAPI
SpdmTransportMctpEncodeMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  );

/**
  Decode an SPDM message from a transport layer message.

  For normal SPDM message, it removes the transport layer wrapper,
  For secured SPDM message, it decrypt and verify a secured message, then removes the transport layer wrapper.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If *SessionId is NULL, it is a normal message.
                                       If *SessionId is NOT NULL, it is a secured message.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  TransportMessageSize         Size in bytes of the SPDM message data buffer.
  @param  TransportMessage             A pointer to a source buffer to store the SPDM message.
  @param  SpdmMessageSize              Size in bytes of the SPDM message data buffer.
  @param  SpdmMessage                  A pointer to a destination buffer to store the SPDM message.

  @retval RETURN_SUCCESS               The SPDM message is decoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
  @retval RETURN_UNSUPPORTED           The TransportMessage is unsupported.
**/
RETURN_STATUS
EFIAPI
SpdmTransportMctpDecodeMessage (
  IN     VOID                 *SpdmContext,
     OUT UINT32               **SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *SpdmMessageSize,
     OUT VOID                 *SpdmMessage
  );

#endif