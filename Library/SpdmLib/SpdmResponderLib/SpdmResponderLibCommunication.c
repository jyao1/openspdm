/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmReceiveSendData (
  IN     VOID                 *Context,
  IN     VOID                 *RequestBuffer,
  IN     UINTN                RequestBufferSize,
     OUT VOID                 *ResponseBuffer,
  IN OUT UINTN                *ResponseBufferSize
  )
{
  RETURN_STATUS            Status;
  SPDM_DEVICE_CONTEXT      *SpdmContext;

  SpdmContext = Context;

  Status = SpdmReceiveRequest (SpdmContext, RequestBufferSize, RequestBuffer);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  Status = SpdmSendResponse (SpdmContext, ResponseBufferSize, ResponseBuffer);
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmReceiveSendSessionData (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     VOID                 *RequestBuffer,
  IN     UINTN                RequestBufferSize,
     OUT VOID                 *ResponseBuffer,
  IN OUT UINTN                *ResponseBufferSize
  )
{
  RETURN_STATUS            Status;
  SPDM_DEVICE_CONTEXT      *SpdmContext;

  SpdmContext = Context;

  Status = SpdmReceiveRequestSession (SpdmContext, SessionId, RequestBufferSize, RequestBuffer);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  Status = SpdmSendResponseSession (SpdmContext, SessionId, ResponseBufferSize, ResponseBuffer);
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmResponderDispatchMessage (
  IN     VOID                 *Context
  )
{
  RETURN_STATUS             Status;
  SPDM_DEVICE_CONTEXT       *SpdmContext;
  UINT8                     Request[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                     RequestSize;
  UINT8                     Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                     ResponseSize;
  UINT32                    *MessageSessionId;
  UINT32                    SessionId;

  SpdmContext = Context;

  RequestSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  MessageSessionId = NULL;
  Status = SpdmContext->ReceiveMessage (SpdmContext, &MessageSessionId, &RequestSize, Request, 0);
  if (!RETURN_ERROR(Status)) {
    ResponseSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
    if (MessageSessionId == NULL) {
      Status = SpdmReceiveSendData (SpdmContext, Request, RequestSize, Response, &ResponseSize);
    } else {
      // cache to local
      SessionId = *MessageSessionId;
      MessageSessionId = &SessionId;
      Status = SpdmReceiveSendSessionData (SpdmContext, SessionId, Request, RequestSize, Response, &ResponseSize);
    }
    if (!RETURN_ERROR(Status)) {
      Status = SpdmContext->SendMessage (SpdmContext, MessageSessionId, ResponseSize, Response, 0);
    }
  }

  return Status;
}
