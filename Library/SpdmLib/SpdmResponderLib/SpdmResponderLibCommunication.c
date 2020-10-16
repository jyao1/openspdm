/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Process a transport layer message.

  The message can be a normal message or a secured message in SPDM session.
  The message can be an SPDM message or an APP message.

  This function is called in SpdmResponderDispatchMessage to process the message.
  The alternative is: an SPDM responder may receive the request message directly
  and call this function to process it, then send the response message.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If *SessionId is NULL, it is a normal message.
                                       If *SessionId is NOT NULL, it is a secured message.
  @param  Request                      A pointer to the request data.
  @param  RequestSize                  Size in bytes of the request data.
  @param  Response                     A pointer to the response data.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.

  @retval RETURN_SUCCESS               The SPDM request is set successfully.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmProcessMessage (
  IN     VOID                 *Context,
  IN OUT UINT32               **SessionId,
  IN     VOID                 *Request,
  IN     UINTN                RequestSize,
     OUT VOID                 *Response,
  IN OUT UINTN                *ResponseSize
  )
{
  RETURN_STATUS            Status;
  SPDM_DEVICE_CONTEXT      *SpdmContext;
  BOOLEAN                  IsAppMessage;

  SpdmContext = Context;

  Status = SpdmProcessRequest (SpdmContext, SessionId, &IsAppMessage, RequestSize, Request);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  Status = SpdmBuildResponse (SpdmContext, *SessionId, IsAppMessage, ResponseSize, Response);
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  return RETURN_SUCCESS;
}

/**
  This is the main dispatch function in SPDM responder.

  It receives one request message, processes it and sends the response message.

  It should be called in a while loop or an timer/interrupt handler.

  @param  SpdmContext                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               One SPDM request message is processed.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_UNSUPPORTED           One request message is not supported.
**/
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
  UINT32                    *SessionId;

  SpdmContext = Context;

  RequestSize = sizeof(Request);
  Status = SpdmContext->ReceiveMessage (SpdmContext, &RequestSize, Request, 0);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  ResponseSize = sizeof(Response);
  Status = SpdmProcessMessage (SpdmContext, &SessionId, Request, RequestSize, Response, &ResponseSize);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  Status = SpdmContext->SendMessage (SpdmContext, ResponseSize, Response, 0);

  return Status;
}
