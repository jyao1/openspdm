/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_REQUESTER_LIB_H__
#define __SPDM_REQUESTER_LIB_H__

#include <Library/SpdmCommonLib.h>

/*
  GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHM.

  The negotiated data can be get via GetData.
*/
RETURN_STATUS
EFIAPI
SpdmInitConnection (
  IN     VOID                 *SpdmContext
  );

/*
  Get all digest of the CertificateChains returned from device.

  TotalDigestSize = sizeof(Digest) * Count in SlotMask
*/
RETURN_STATUS
EFIAPI
SpdmGetDigest (
  IN     VOID                 *SpdmContext,
     OUT UINT8                *SlotMask,
     OUT VOID                 *TotalDigestBuffer
  );

/*
  Get CertificateChain in one slot returned from device.
*/
RETURN_STATUS
EFIAPI
SpdmGetCertificate (
  IN     VOID                 *SpdmContext,
  IN     UINT8                SlotNum,
  IN OUT UINTN                *CertChainSize,
     OUT VOID                 *CertChain
  );

/*
  Authenticate based upon the key in one slot.
*/
RETURN_STATUS
EFIAPI
SpdmChallenge (
  IN     VOID                 *SpdmContext,
  IN     UINT8                SlotNum,
  IN     UINT8                MeasurementHashType,
     OUT VOID                 *MeasurementHash
  );

/*
  Get measurement
*/
RETURN_STATUS
EFIAPI
SpdmGetMeasurement (
  IN     VOID                 *SpdmContext,
  IN     UINT8                RequestAttribute,
  IN     UINT8                MeasurementOperation,
  IN     UINT8                SlotNum,
     OUT UINT8                *NumberOfBlocks,
  IN OUT UINT32               *MeasurementRecordLength,
     OUT VOID                 *MeasurementRecord
  );

/*
  Send receive SPDM data (non session data).
*/
RETURN_STATUS
EFIAPI
SpdmSendReceiveData (
  IN     VOID                 *SpdmContext,
  IN     VOID                 *Request,
  IN     UINTN                RequestSize,
  IN OUT VOID                 *Response,
  IN OUT UINTN                *ResponseSize
  );

/**
  Start a SPDM Session.

  @param  This                         Indicates a pointer to the calling context.

  @retval RETURN_SUCCESS                  The SPDM session is started.
**/
RETURN_STATUS
EFIAPI
SpdmStartSession (
  IN     VOID                 *SpdmContext,
  IN     BOOLEAN              UsePsk,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT32               *SessionId,
     OUT VOID                 *MeasurementHash
  );

/**
  Stop a SPDM Session.

  @param  This                         Indicates a pointer to the calling context.

  @retval RETURN_SUCCESS                  The SPDM session is stopped.
**/
RETURN_STATUS
EFIAPI
SpdmStopSession (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                EndSessionAttributes
  );

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
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     VOID                 *Request,
  IN     UINTN                RequestSize,
  IN OUT VOID                 *Response,
  IN OUT UINTN                *ResponseSize
  );

RETURN_STATUS
EFIAPI
SpdmHeartbeat (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId
  );

RETURN_STATUS
EFIAPI
SpdmKeyUpdate (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     BOOLEAN              SingleDirection
  );

typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_ENCAP_RESPONSE_FUNC) (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmRegisterGetEncapResponseFunc (
  IN  VOID                          *SpdmContext,
  IN  SPDM_GET_ENCAP_RESPONSE_FUNC  GetResponseFunc
  );

RETURN_STATUS
EFIAPI
SpdmGenerateEncapErrorResponse (
  IN     VOID                 *Context,
  IN     UINT8                ErrorCode,
  IN     UINT8                ErrorData,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGenerateEncapExtendedErrorResponse (
  IN     VOID                 *Context,
  IN     UINT8                ErrorCode,
  IN     UINT8                ErrorData,
  IN     UINTN                ExtendedErrorDataSize,
  IN     UINT8                *ExtendedErrorData,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

#endif