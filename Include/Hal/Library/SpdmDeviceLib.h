/** @file
  SPDM Device Lib definition

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_DEVICE_LIB_H__
#define __SPDM_DEVICE_LIB_H__

#include <Base.h>
#include <IndustryStandard/Spdm.h>

/**
  Send a SPDM message to a device.

  For requester, the message is an SPDM request.
  For responder, the message is an SPDM response.

  @param  This                         Indicates a pointer to the calling context.
  @param  SessionId                    The SessionId of a SPDM message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secure message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the message. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       message to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the message is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS               The SPDM message is sent successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is sent to the device.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
  @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
                                       to execute.
**/
RETURN_STATUS
EFIAPI
SpdmDeviceSendMessage (
  IN     UINT32                                 *SessionId,
  IN     UINTN                                  MessageSize,
  IN     VOID                                   *Message,
  IN     UINT64                                 Timeout
  );

/**
  Receive a SPDM message from a device.

  For requester, the message is an SPDM response.
  For responder, the message is an SPDM request.

  @param  This                         Indicates a pointer to the calling context.
  @param  SessionId                    The SessionId of a SPDM message.
                                       If *SessionId is NULL, it is a normal message.
                                       If *SessionId is NOT NULL, it is a secure message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the message. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       message to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the message is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS               The SPDM message is received successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is received from the device.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL, MessageSize is NULL or
                                       the *MessageSize is zero.
  @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
                                       to execute.
**/
RETURN_STATUS
EFIAPI
SpdmDeviceReceiveMessage (
     OUT UINT32                                 **SessionId,
  IN OUT UINTN                                  *MessageSize,
  IN OUT VOID                                   *Message,
  IN     UINT64                                 Timeout
  );

#endif
