/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

RETURN_STATUS
SpdmSendRequestSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request
  )
{
  RETURN_STATUS                      Status;
  UINT8                              Message[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                              MessageSize;

  DEBUG((DEBUG_INFO, "SpdmSendRequestSession[%x] (0x%x): \n", SessionId, RequestSize));
  InternalDumpHex (Request, RequestSize);

  MessageSize = sizeof(Message);
  Status = SpdmEncodeRequest (SpdmContext, &SessionId, RequestSize, Request, &MessageSize, Message);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmEncodeRequest Status - %p\n", Status));
    return Status;
  }

  Status = SpdmDeviceSendMessage (&SessionId, MessageSize, Message, 0);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmSendRequestSession[%x] Status - %p\n", SessionId, Status));
  }

  return Status;
}

/**
  Send a SPDM request command to a device.
  
  @param  SpdmContext                  The SPDM context for the device.
  @param  RequestSize                  Size in bytes of the request data buffer.
  @param  Request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
                                       
  @retval RETURN_SUCCESS                  The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM request is sent to the device.
  @retval RETURN_INVALID_PARAMETER        The Request is NULL or the RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                       to execute.
**/
RETURN_STATUS
SpdmSendRequest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request
  )
{
  RETURN_STATUS                      Status;
  UINT8                              Message[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                              MessageSize;

  ASSERT (RequestSize <= MAX_SPDM_MESSAGE_BUFFER_SIZE);

  DEBUG((DEBUG_INFO, "SpdmSendRequest (0x%x): \n", RequestSize));
  InternalDumpHex (Request, RequestSize);

  MessageSize = sizeof(Message);
  Status = SpdmEncodeRequest (SpdmContext, NULL, RequestSize, Request, &MessageSize, Message);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmEncodeRequest Status - %p\n", Status));
    return Status;
  }

  Status = SpdmDeviceSendMessage (NULL, MessageSize, Message, 0);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmSendRequest Status - %p\n", Status));
  }

  return Status;
}

RETURN_STATUS
SpdmReceiveResponseSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN OUT UINTN                *ResponseSize,
  IN OUT VOID                 *Response
  )
{
  RETURN_STATUS             Status;
  UINT8                     Message[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                     MessageSize;
  UINT32                    *MessageSessionId;

  ASSERT (*ResponseSize <= MAX_SPDM_MESSAGE_BUFFER_SIZE);

  MessageSize = sizeof(Message);
  MessageSessionId = NULL;
  Status = SpdmDeviceReceiveMessage (&MessageSessionId, &MessageSize, Message, 0);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmReceiveResponseSession[%x] Status - %p\n", SessionId, Status));
    return Status;
  }

  if (MessageSessionId == NULL) {
    DEBUG((DEBUG_INFO, "SpdmReceiveResponseSession[%x] GetSessionId - NULL\n", SessionId));
    return RETURN_DEVICE_ERROR;
  }
  if (*MessageSessionId != SessionId) {
    DEBUG((DEBUG_INFO, "SpdmReceiveResponseSession[%x] GetSessionId - %x\n", SessionId, *MessageSessionId));
    return RETURN_DEVICE_ERROR;
  }

  Status = SpdmDecodeResponse (SpdmContext, &SessionId, MessageSize, Message, ResponseSize, Response);

  DEBUG((DEBUG_INFO, "SpdmReceiveResponseSession[%x] (0x%x): \n", SessionId, *ResponseSize));
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmReceiveResponseSession[%x] Status - %p\n", SessionId, Status));    
  } else {
    InternalDumpHex (Response, *ResponseSize);
  }
  return Status;
}

/**
  Receive a SPDM response from a device.
  
  @param  SpdmContext                  The SPDM context for the device.
  @param  ResponseSize                 Size in bytes of the response data buffer.
  @param  Response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
                                       
  @retval RETURN_SUCCESS                  The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM response is received from the device.
  @retval RETURN_INVALID_PARAMETER        The Reponse is NULL, ResponseSize is NULL or
                                       the *RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM response
                                       to execute.
**/
RETURN_STATUS
SpdmReceiveResponse (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *ResponseSize,
  IN OUT VOID                 *Response
  )
{
  RETURN_STATUS             Status;
  UINT8                     Message[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                     MessageSize;
  UINT32                    *MessageSessionId;

  ASSERT (*ResponseSize <= MAX_SPDM_MESSAGE_BUFFER_SIZE);

  MessageSize = sizeof(Message);
  MessageSessionId = NULL;
  Status = SpdmDeviceReceiveMessage (&MessageSessionId, &MessageSize, Message, 0);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmDeviceReceiveMessage Status - %p\n", Status));    
    return Status;
  }

  if (MessageSessionId != NULL) {
    DEBUG((DEBUG_INFO, "SpdmDeviceReceiveMessage GetSessionId - %x\n", *MessageSessionId));    
    return RETURN_DEVICE_ERROR;
  }

  Status = SpdmDecodeResponse (SpdmContext, NULL, MessageSize, Message, ResponseSize, Response);

  DEBUG((DEBUG_INFO, "SpdmReceiveResponse (0x%x): \n", *ResponseSize));
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmReceiveResponse Status - %p\n", Status));    
  } else {
    InternalDumpHex (Response, *ResponseSize);
  }
  return Status;
}
