/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

/*
  GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHM.

  The negotiated data can be get via GetData.
*/
RETURN_STATUS
EFIAPI
SpdmInitConnection (
  IN     VOID                 *Context
  )
{
  RETURN_STATUS        Status;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmContext = Context;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  Status = SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  Status = SpdmGetCapabilities (
           SpdmContext,
           SpdmContext->LocalContext.Capability.CTExponent,
           SpdmContext->LocalContext.Capability.Flags,
           &SpdmContext->ConnectionInfo.Capability.CTExponent,
           &SpdmContext->ConnectionInfo.Capability.Flags
           );
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  Status = SpdmNegotiateAlgorithms (SpdmContext);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  return RETURN_SUCCESS;
}

/*
  GET_DIGEST, GET_CERTIFICATE, CHALLENGE.
*/
RETURN_STATUS
EFIAPI
SpdmAuthentication (
  IN     VOID                 *SpdmContext,
     OUT UINT8                *SlotMask,
     OUT VOID                 *TotalDigestBuffer,
  IN     UINT8                SlotNum,
  IN OUT UINTN                *CertChainSize,
     OUT VOID                 *CertChain,
  IN     UINT8                MeasurementHashType,
     OUT VOID                 *MeasurementHash
  )
{
  RETURN_STATUS         Status;
  UINT32                CapabilityFlags;
  UINTN                 DataSize;

  DataSize = sizeof(CapabilityFlags);
  SpdmGetData (SpdmContext, SpdmDataCapabilityFlags, NULL, &CapabilityFlags, &DataSize);

  if ((CapabilityFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) != 0) {
    Status = SpdmGetDigest (SpdmContext, SlotMask, TotalDigestBuffer);
    if (RETURN_ERROR(Status)) {
      return Status;
    }

    Status = SpdmGetCertificate (SpdmContext, SlotNum, CertChainSize, CertChain);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  }

  Status = SpdmChallenge (SpdmContext, SlotNum, MeasurementHashType, MeasurementHash);
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  return RETURN_SUCCESS;
}

/**
  Start a SPDM Session.

  @param  This                         Indicates a pointer to the calling context.

  @retval RETURN_SUCCESS                  The SPDM session is started.
**/
RETURN_STATUS
EFIAPI
SpdmStartSession (
  IN     VOID                 *Context,
  IN     BOOLEAN              UsePsk,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT32               *SessionId,
     OUT VOID                 *MeasurementHash
  )
{
  RETURN_STATUS                 Status;
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  SPDM_SESSION_INFO             *SessionInfo;

  SpdmContext = Context;

  if (!UsePsk) {
    Status = SpdmSendReceiveKeyExchange (SpdmContext, MeasurementHashType, SlotNum, HeartbeatPeriod, SessionId, MeasurementHash);
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
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED:
      break;
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST:
    case SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS:
      Status = SpdmEncapsulatedRequest (SpdmContext, SessionId, SessionInfo->MutAuthRequested);
      DEBUG ((DEBUG_INFO, "SpdmStartSession - SpdmEncapsulatedRequest - %p\n", Status));
      if (RETURN_ERROR(Status)) {
        return Status;
      }
      break;
    default:
      DEBUG ((DEBUG_INFO, "SpdmStartSession - unknown MutAuthRequested - 0x%x\n", SessionInfo->MutAuthRequested));
      return RETURN_UNSUPPORTED;
    }

    Status = SpdmSendReceiveFinish (SpdmContext, *SessionId, SlotNum);
    DEBUG ((DEBUG_INFO, "SpdmStartSession - SpdmSendReceiveFinish - %p\n", Status));
  } else {
    Status = SpdmSendReceivePskExchange (SpdmContext, MeasurementHashType, HeartbeatPeriod, SessionId, MeasurementHash);
    if (RETURN_ERROR(Status)) {
      DEBUG ((DEBUG_INFO, "SpdmStartSession - SpdmSendReceivePskExchange - %p\n", Status));
      return Status;
    }

    Status = SpdmSendReceivePskFinish (SpdmContext, *SessionId);
    DEBUG ((DEBUG_INFO, "SpdmStartSession - SpdmSendReceivePskFinish - %p\n", Status));
  }
  return Status;
}

/**
  Stop a SPDM Session.

  @param  This                         Indicates a pointer to the calling context.

  @retval RETURN_SUCCESS                  The SPDM session is stopped.
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
  Send and receive a packet in the current SPDM session.

  @param  This                         Indicates a pointer to the calling context.
  @param  Request                      A pointer to the request data.
  @param  RequestSize                  Size of the request data.
  @param  Response                     A pointer to the response data.
  @param  ResponseSize                 Size of the response data. On input, it means the size of Data
                                       buffer. On output, it means the size of copied Data buffer if
                                       RETURN_SUCCESS, and means the size of desired Data buffer if
                                       RETURN_BUFFER_TOO_SMALL.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the request. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       request to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the request is greater
                                       than Timeout.

  @retval RETURN_SUCCESS                  The SPDM request is set successfully.
  @retval RETURN_INVALID_PARAMETER        The DataSize is NULL or the Data is NULL and *DataSize is not zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_NOT_FOUND                The DataType cannot be found.
  @retval RETURN_NOT_READY                The DataType is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL         The buffer is too small to hold the data.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                       to execute.
**/
RETURN_STATUS
EFIAPI
SpdmSendReceiveSessionData (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     VOID                 *Request,
  IN     UINTN                RequestSize,
  IN OUT VOID                 *Response,
  IN OUT UINTN                *ResponseSize
  )
{
  RETURN_STATUS                 Status;
  SPDM_DEVICE_CONTEXT           *SpdmContext;

  SpdmContext = Context;

  Status = SpdmSendRequestSession (SpdmContext, SessionId, RequestSize, Request);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  Status = SpdmReceiveResponseSession (SpdmContext, SessionId, ResponseSize, Response);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}

/*
  Send receive SPDM data (non session data).
*/
RETURN_STATUS
EFIAPI
SpdmSendReceiveData (
  IN     VOID                 *Context,
  IN     VOID                 *Request,
  IN     UINTN                RequestSize,
  IN OUT VOID                 *Response,
  IN OUT UINTN                *ResponseSize
  )
{
  RETURN_STATUS                 Status;
  SPDM_DEVICE_CONTEXT           *SpdmContext;

  SpdmContext = Context;

  Status = SpdmSendRequest (SpdmContext, RequestSize, Request);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  Status = SpdmReceiveResponse (SpdmContext, ResponseSize, Response);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}
