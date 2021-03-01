/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

/**
  Send an SPDM or an APP request to a device.

  @param  SpdmContext                  The SPDM context for the device.
  @param  SessionId                    Indicate if the request is a secured message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  IsAppMessage                 Indicates if it is an APP message or SPDM message.
  @param  RequestSize                  Size in bytes of the request data buffer.
  @param  Request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.

  @retval RETURN_SUCCESS               The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM request is sent to the device.
**/
RETURN_STATUS
EFIAPI
SpdmSendRequest (
  IN     VOID                 *Context,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsAppMessage,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request
  )
{
  SPDM_DEVICE_CONTEXT                *SpdmContext;
  RETURN_STATUS                      Status;
  UINT8                              Message[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                              MessageSize;

  SpdmContext = Context;

  DEBUG((DEBUG_INFO, "SpdmSendSpdmRequest[%x] (0x%x): \n", (SessionId != NULL) ? *SessionId : 0x0, RequestSize));
  InternalDumpHex (Request, RequestSize);

  MessageSize = sizeof(Message);
  Status = SpdmContext->TransportEncodeMessage (SpdmContext, SessionId, IsAppMessage, TRUE, RequestSize, Request, &MessageSize, Message);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "TransportEncodeMessage Status - %p\n", Status));
    return Status;
  }

  Status = SpdmContext->SendMessage (SpdmContext, MessageSize, Message, 0);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmSendSpdmRequest[%x] Status - %p\n", (SessionId != NULL) ? *SessionId : 0x0, Status));
  }

  return Status;
}

/**
  Receive an SPDM or an APP response from a device.
  
  @param  SpdmContext                  The SPDM context for the device.
  @param  SessionId                    Indicate if the response is a secured message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  IsAppMessage                 Indicates if it is an APP message or SPDM message.
  @param  ResponseSize                 Size in bytes of the response data buffer.
  @param  Response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.

  @retval RETURN_SUCCESS               The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is received from the device.
**/
RETURN_STATUS
EFIAPI
SpdmReceiveResponse (
  IN     VOID                 *Context,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsAppMessage,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;
  RETURN_STATUS             Status;
  UINT8                     Message[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                     MessageSize;
  UINT32                    *MessageSessionId;
  BOOLEAN                   IsMessageAppMessage;

  SpdmContext = Context;

  ASSERT (*ResponseSize <= MAX_SPDM_MESSAGE_BUFFER_SIZE);

  MessageSize = sizeof(Message);
  Status = SpdmContext->ReceiveMessage (SpdmContext, &MessageSize, Message, 0);
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmReceiveSpdmResponse[%x] Status - %p\n", (SessionId != NULL) ? *SessionId : 0x0, Status));
    return Status;
  }

  MessageSessionId = NULL;
  IsMessageAppMessage = FALSE;
  Status = SpdmContext->TransportDecodeMessage (SpdmContext, &MessageSessionId, &IsMessageAppMessage, FALSE, MessageSize, Message, ResponseSize, Response);

  if (SessionId != NULL) {
    if (MessageSessionId == NULL) {
      DEBUG((DEBUG_INFO, "SpdmReceiveSpdmResponse[%x] GetSessionId - NULL\n", (SessionId != NULL) ? *SessionId : 0x0));
      return RETURN_DEVICE_ERROR;
    }
    if (*MessageSessionId != *SessionId) {
      DEBUG((DEBUG_INFO, "SpdmReceiveSpdmResponse[%x] GetSessionId - %x\n", (SessionId != NULL) ? *SessionId : 0x0, *MessageSessionId));
      return RETURN_DEVICE_ERROR;
    }
  } else {
    if (MessageSessionId != NULL) {
      DEBUG((DEBUG_INFO, "SpdmReceiveSpdmResponse[%x] GetSessionId - %x\n", (SessionId != NULL) ? *SessionId : 0x0, *MessageSessionId));
      return RETURN_DEVICE_ERROR;
    }
  }

  if ((IsAppMessage && !IsMessageAppMessage) ||
      (!IsAppMessage && IsMessageAppMessage)) {
    DEBUG((DEBUG_INFO, "SpdmReceiveSpdmResponse[%x] AppMessage mismatch\n", (SessionId != NULL) ? *SessionId : 0x0));
    return RETURN_DEVICE_ERROR;
  }

  DEBUG((DEBUG_INFO, "SpdmReceiveSpdmResponse[%x] (0x%x): \n", (SessionId != NULL) ? *SessionId : 0x0, *ResponseSize));
  if (RETURN_ERROR(Status)) {
    DEBUG((DEBUG_INFO, "SpdmReceiveSpdmResponse[%x] Status - %p\n", (SessionId != NULL) ? *SessionId : 0x0, Status));    
  } else {
    InternalDumpHex (Response, *ResponseSize);
  }
  return Status;
}

/**
  Send an SPDM request to a device.

  @param  SpdmContext                  The SPDM context for the device.
  @param  SessionId                    Indicate if the request is a secured message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  RequestSize                  Size in bytes of the request data buffer.
  @param  Request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.

  @retval RETURN_SUCCESS               The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM request is sent to the device.
**/
RETURN_STATUS
SpdmSendSpdmRequest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request
  )
{
  SPDM_SESSION_INFO                         *SessionInfo;
  SPDM_SESSION_STATE                        SessionState;

  if ((SessionId != NULL) &&
      SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, *SessionId);
    ASSERT (SessionInfo != NULL);
    if (SessionInfo == NULL) {
      return RETURN_DEVICE_ERROR;
    }
    SessionState = SpdmSecuredMessageGetSessionState (SessionInfo->SecuredMessageContext);
    if ((SessionState == SpdmSessionStateHandshaking) && !SessionInfo->UsePsk) {
      SessionId = NULL;
    }
  }

  return SpdmSendRequest (SpdmContext, SessionId, FALSE, RequestSize, Request);
}

/**
  Receive an SPDM response from a device.

  @param  SpdmContext                  The SPDM context for the device.
  @param  SessionId                    Indicate if the response is a secured message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  ResponseSize                 Size in bytes of the response data buffer.
  @param  Response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.

  @retval RETURN_SUCCESS               The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is received from the device.
**/
RETURN_STATUS
SpdmReceiveSpdmResponse (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               *SessionId,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_SESSION_INFO                         *SessionInfo;
  SPDM_SESSION_STATE                        SessionState;

  if ((SessionId != NULL) &&
      SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, *SessionId);
    ASSERT (SessionInfo != NULL);
    if (SessionInfo == NULL) {
      return RETURN_DEVICE_ERROR;
    }
    SessionState = SpdmSecuredMessageGetSessionState (SessionInfo->SecuredMessageContext);
    if ((SessionState == SpdmSessionStateHandshaking) && !SessionInfo->UsePsk) {
      SessionId = NULL;
    }
  }

  return SpdmReceiveResponse (SpdmContext, SessionId, FALSE, ResponseSize, Response);
}