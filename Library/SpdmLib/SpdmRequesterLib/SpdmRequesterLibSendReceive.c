/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

RETURN_STATUS
SpdmSendRequest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request
  )
{
  RETURN_STATUS                      Status;
  UINT8                              Message[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                              MessageSize;

  DEBUG((DEBUG_INFO, "SpdmSendRequest[%x] (0x%x): \n", (SessionId != NULL) ? *SessionId : 0x0, RequestSize));
  InternalDumpHex (Request, RequestSize);

  MessageSize = sizeof(Message);
  Status = SpdmContext->TransportEncodeMessage (SpdmContext, SessionId, TRUE, RequestSize, Request, &MessageSize, Message);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "TransportEncodeMessage Status - %p\n", Status));
    return Status;
  }

  Status = SpdmContext->SendMessage (SpdmContext, MessageSize, Message, 0);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmSendRequest[%x] Status - %p\n", (SessionId != NULL) ? *SessionId : 0x0, Status));
  }

  return Status;
}

RETURN_STATUS
SpdmReceiveResponse (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               *SessionId,
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
  Status = SpdmContext->ReceiveMessage (SpdmContext, &MessageSize, Message, 0);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmReceiveResponse[%x] Status - %p\n", (SessionId != NULL) ? *SessionId : 0x0, Status));
    return Status;
  }

  Status = SpdmContext->TransportDecodeMessage (SpdmContext, &MessageSessionId, FALSE, MessageSize, Message, ResponseSize, Response);

  if (SessionId != NULL) {
    if (MessageSessionId == NULL) {
      DEBUG((DEBUG_INFO, "SpdmReceiveResponse[%x] GetSessionId - NULL\n", (SessionId != NULL) ? *SessionId : 0x0));
      return RETURN_DEVICE_ERROR;
    }
    if (*MessageSessionId != *SessionId) {
      DEBUG((DEBUG_INFO, "SpdmReceiveResponse[%x] GetSessionId - %x\n", (SessionId != NULL) ? *SessionId : 0x0, *MessageSessionId));
      return RETURN_DEVICE_ERROR;
    }
  } else {
    if (MessageSessionId != NULL) {
      DEBUG((DEBUG_INFO, "SpdmReceiveResponse[%x] GetSessionId - %x\n", (SessionId != NULL) ? *SessionId : 0x0, *MessageSessionId));
      return RETURN_DEVICE_ERROR;
    }
  }

  DEBUG((DEBUG_INFO, "SpdmReceiveResponse[%x] (0x%x): \n", (SessionId != NULL) ? *SessionId : 0x0, *ResponseSize));
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmReceiveResponse[%x] Status - %p\n", (SessionId != NULL) ? *SessionId : 0x0, Status));    
  } else {
    InternalDumpHex (Response, *ResponseSize);
  }
  return Status;
}
