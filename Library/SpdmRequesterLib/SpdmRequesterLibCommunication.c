/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

/**
  This function sends GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHM
  to initialize the connection with SPDM responder.

  Before this function, the requester configuration data can be set via SpdmSetData.
  After this function, the negotiated configuration data can be got via SpdmGetData.

  @param  SpdmContext                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The connection is initialized successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmInitConnection (
  IN     VOID                 *Context,
  IN     BOOLEAN              GetVersionOnly
  )
{
  RETURN_STATUS        Status;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmContext = Context;

  Status = SpdmGetVersion (SpdmContext);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  if (!GetVersionOnly) {
    Status = SpdmGetCapabilities (SpdmContext);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
    Status = SpdmNegotiateAlgorithms (SpdmContext);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  }
  return RETURN_SUCCESS;
}

/**
  This function sends KEY_EXCHANGE/FINISH or PSK_EXCHANGE/PSK_FINISH
  to start an SPDM Session.

  If encapsulated mutual authentication is requested from the responder,
  this function also perform the encapsulated mutual authentication.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  UsePsk                       FALSE means to use KEY_EXCHANGE/FINISH to start a session.
                                       TRUE means to use PSK_EXCHANGE/PSK_FINISH to start a session.
  @param  MeasurementHashType          The type of the measurement hash.
  @param  SlotNum                      The number of slot for the certificate chain.
  @param  SessionId                    The session ID of the session.
  @param  HeartbeatPeriod              The heartbeat period for the session.
  @param  MeasurementHash              A pointer to a destination buffer to store the measurement hash.

  @retval RETURN_SUCCESS               The SPDM session is started.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmStartSession (
  IN     VOID                 *Context,
  IN     BOOLEAN              UsePsk,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT32               *SessionId,
     OUT UINT8                *HeartbeatPeriod,
     OUT VOID                 *MeasurementHash
  )
{
  RETURN_STATUS                 Status;
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  SPDM_SESSION_INFO             *SessionInfo;
  UINT8                         ReqSlotIdParam;

  SpdmContext = Context;

  if (!UsePsk) {
    Status = SpdmSendReceiveKeyExchange (SpdmContext, MeasurementHashType, SlotNum, SessionId, HeartbeatPeriod, &ReqSlotIdParam, MeasurementHash);
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_INFO, "SpdmStartSession - SpdmSendReceiveKeyExchange - %p\n", Status));
      return Status;
    }

    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, *SessionId);
    if (SessionInfo == NULL) {
      ASSERT (FALSE);
      return RETURN_UNSUPPORTED;
    }

    switch (SessionInfo->MutAuthRequested) {
    case 0:
      break;
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED:
      break;
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST:
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS:
      Status = SpdmEncapsulatedRequest (SpdmContext, SessionId, SessionInfo->MutAuthRequested, &ReqSlotIdParam);
      DEBUG ((DEBUG_INFO, "SpdmStartSession - SpdmEncapsulatedRequest - %p\n", Status));
      if (RETURN_ERROR(Status)) {
        return Status;
      }
      break;
    default:
      DEBUG ((DEBUG_INFO, "SpdmStartSession - unknown MutAuthRequested - 0x%x\n", SessionInfo->MutAuthRequested));
      return RETURN_UNSUPPORTED;
    }

    if (ReqSlotIdParam == 0xF) {
      ReqSlotIdParam = 0xFF;
    }
    Status = SpdmSendReceiveFinish (SpdmContext, *SessionId, ReqSlotIdParam);
    DEBUG ((DEBUG_INFO, "SpdmStartSession - SpdmSendReceiveFinish - %p\n", Status));
  } else {
    Status = SpdmSendReceivePskExchange (SpdmContext, MeasurementHashType, SessionId, HeartbeatPeriod, MeasurementHash);
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_INFO, "SpdmStartSession - SpdmSendReceivePskExchange - %p\n", Status));
      return Status;
    }

    // send PSK_FINISH only if Responder supports Context.
    if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
      Status = SpdmSendReceivePskFinish (SpdmContext, *SessionId);
      DEBUG ((DEBUG_INFO, "SpdmStartSession - SpdmSendReceivePskFinish - %p\n", Status));
    }
  }
  return Status;
}

/**
  This function sends END_SESSION
  to stop an SPDM Session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The session ID of the session.
  @param  EndSessionAttributes         The end session attribute for the session.

  @retval RETURN_SUCCESS               The SPDM session is stopped.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmStopSession (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     UINT8                EndSessionAttributes
  )
{
  RETURN_STATUS                 Status;
  SPDM_DEVICE_CONTEXT           *SpdmContext;

  SpdmContext = Context;

  Status = SpdmSendReceiveEndSession (SpdmContext, SessionId, EndSessionAttributes);
  DEBUG ((DEBUG_INFO, "SpdmStopSession - %p\n", Status));

  return Status;
}

/**
  Send and receive an SPDM or APP message.

  The SPDM message can be a normal message or a secured message in SPDM session.

  The APP message is encoded to a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  IsAppMessage                 Indicates if it is an APP message or SPDM message.
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
SpdmSendReceiveData (
  IN     VOID                 *Context,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsAppMessage,
  IN     VOID                 *Request,
  IN     UINTN                RequestSize,
  IN OUT VOID                 *Response,
  IN OUT UINTN                *ResponseSize
  )
{
  RETURN_STATUS                 Status;
  SPDM_DEVICE_CONTEXT           *SpdmContext;

  SpdmContext = Context;

  Status = SpdmSendRequest (SpdmContext, SessionId, IsAppMessage, RequestSize, Request);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  Status = SpdmReceiveResponse (SpdmContext, SessionId, IsAppMessage, ResponseSize, Response);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}
