/** @file
  EDKII Device Security library for SPDM device.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_REQUESTER_LIB_INTERNAL_H__
#define __SPDM_REQUESTER_LIB_INTERNAL_H__

#include <Library/SpdmRequesterLib.h>
#include "SpdmCommonLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmGetVersion (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINT8                *VersionCount,
     OUT VOID                 *VersionNumberEntries
  );

RETURN_STATUS
EFIAPI
SpdmGetCapabilities (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                RequesterCTExponent,
  IN     UINT32               RequesterFlags,
     OUT UINT8                *ResponderCTExponent,
     OUT UINT32               *ResponderFlags
  );

/*
  The negotiated data can be get via GetData.
*/
RETURN_STATUS
EFIAPI
SpdmNegotiateAlgorithms (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  );

/**
  This function executes SPDM key change.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceiveKeyExchange (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT8                *SessionId,
     OUT VOID                 *MeasurementHash
  );

/**
  This function executes SPDM finish.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceiveFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINT8                SlotNum
  );

/**
  This function executes SPDM key change.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceivePskExchange (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementHashType,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT8                *SessionId,
     OUT VOID                 *MeasurementHash
  );

/**
  This function executes SPDM finish.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceivePskFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId
  );

/**
  This function executes SPDM EndSession.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceiveEndSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINT8                EndSessionAttributes
  );

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
  );

RETURN_STATUS
SpdmSendRequestSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request
  );

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
  );

RETURN_STATUS
SpdmReceiveResponseSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN OUT UINTN                *ResponseSize,
  IN OUT VOID                 *Response
  );

SPDM_SESSION_INFO *
SpdmAssignSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT8                     SessionId
  );

#endif