/** @file
  SPDM IO Protocol definition

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_IO_PROTOCOL_H__
#define __SPDM_IO_PROTOCOL_H__

#include <Base.h>
#include <IndustryStandard/Spdm.h>

typedef struct _SPDM_IO_PROTOCOL SPDM_IO_PROTOCOL;

/**
  Send a SPDM request command to a device.

  @param  This                         Indicates a pointer to the calling context.
  @param  RequestSize                  Size in bytes of the request data buffer.
  @param  Request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the request. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       request to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the request is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS                  The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM request is sent to the device.
  @retval RETURN_INVALID_PARAMETER        The Request is NULL or the RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                       to execute.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_IO_SEND_REQUEST_FUNC) (
  IN     SPDM_IO_PROTOCOL        *This,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  );

/**
  Receive a SPDM response from a device.

  @param  This                         Indicates a pointer to the calling context.
  @param  ResponseSize                 Size in bytes of the response data buffer.
  @param  Response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the response. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       response to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the response is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS                  The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM response is received from the device.
  @retval RETURN_INVALID_PARAMETER        The Reponse is NULL, ResponseSize is NULL or
                                       the *RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM response
                                       to execute.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_IO_RECEIVE_RESPONSE_FUNC) (
  IN     SPDM_IO_PROTOCOL        *This,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response,
  IN     UINT64                  Timeout
  );

/**
  Send a SPDM request command to a device.

  The request is a data blob to send to the messaging device directly,
  including session ID, length, encrypted message and MAC.
  The caller need use GetSecureMessagingType() to decide the format of the message.

  @param  This                         Indicates a pointer to the calling context.
  @param  RequestSize                  Size in bytes of the request data buffer.
  @param  Request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the request. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       request to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the request is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS                  The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM request is sent to the device.
  @retval RETURN_INVALID_PARAMETER        The Request is NULL or the RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                       to execute.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_IO_SECURE_SEND_REQUEST_FUNC) (
  IN     SPDM_IO_PROTOCOL                       *This,
  IN     UINT8                                  SessionId,
  IN     UINTN                                  RequestSize,
  IN     VOID                                   *Request,
  IN     UINT64                                 Timeout
  );

/**
  Receive a SPDM response from a device.

  The response is a data blob received from the messaging device directly,
  including session ID, length, encrypted message and MAC.
  The caller need use GetSecureMessagingType() to decide the format of the message.

  @param  This                         Indicates a pointer to the calling context.
  @param  ResponseSize                 Size in bytes of the response data buffer.
  @param  Response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the response. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       response to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the response is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS                  The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM response is received from the device.
  @retval RETURN_INVALID_PARAMETER        The Reponse is NULL, ResponseSize is NULL or
                                       the *RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM response
                                       to execute.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_IO_SECURE_RECEIVE_RESPONSE_FUNC) (
  IN     SPDM_IO_PROTOCOL                       *This,
  IN     UINT8                                  SessionId,
  IN OUT UINTN                                  *ResponseSize,
  IN OUT VOID                                   *Response,
  IN     UINT64                                 Timeout
  );

typedef enum {
  SpdmIoSecureMessagingTypeDmtfMtcp,
  SpdmIoSecureMessagingTypePciSigDoe,
  SpdmIoSecureMessagingTypeMax,
} SPDM_IO_SECURE_MESSAGING_TYPE;

struct _SPDM_IO_PROTOCOL {
  SPDM_IO_SEND_REQUEST_FUNC               SendRequest;
  SPDM_IO_RECEIVE_RESPONSE_FUNC           ReceiveResponse;
  SPDM_IO_SECURE_SEND_REQUEST_FUNC        SecureSendRequest;
  SPDM_IO_SECURE_RECEIVE_RESPONSE_FUNC    SecureReceiveResponse;
  SPDM_IO_SECURE_MESSAGING_TYPE           SecureMessageType;
  UINT32                                  Alignment;
};

#endif
