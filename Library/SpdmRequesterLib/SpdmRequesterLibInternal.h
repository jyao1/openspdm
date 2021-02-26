/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_REQUESTER_LIB_INTERNAL_H__
#define __SPDM_REQUESTER_LIB_INTERNAL_H__

#include <Library/SpdmRequesterLib.h>
#include <Library/SpdmSecuredMessageLib.h>
#include "SpdmCommonLibInternal.h"

/**
  This function handles simple error code.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ErrorCode                    Indicate the error code.

  @retval RETURN_NO_RESPONSE           If the error code is BUSY.
  @retval RETURN_DEVICE_ERROR          If the error code is REQUEST_RESYNCH or others.
**/
RETURN_STATUS
EFIAPI
SpdmHandleSimpleErrorResponse (
  IN     VOID                 *Context,
  IN     UINT8                ErrorCode
  );

/**
  This function handles the error response.

  The SPDM response code must be SPDM_ERROR.
  For error code RESPONSE_NOT_READY, this function sends RESPOND_IF_READY and receives an expected SPDM response.
  For error code BUSY, this function shrinks the managed buffer, and return RETURN_NO_RESPONSE.
  For error code REQUEST_RESYNCH, this function shrinks the managed buffer, clears ConnectionState, and return RETURN_DEVICE_ERROR.
  For any other error code, this function shrinks the managed buffer, and return RETURN_DEVICE_ERROR.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ManagedBuffer                The managed buffer to be shrinked.
  @param  ShrinkBufferSize             The size in bytes of the size of the buffer to be shrinked.
  @param  ResponseSize                 The size of the response.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned.
  @param  Response                     The SPDM response message.
  @param  OriginalRequestCode          Indicate the original request code.
  @param  ExpectedResponseCode         Indicate the expected response code.
  @param  ExpectedResponseSize         Indicate the expected response size.

  @retval RETURN_SUCCESS               The error code is RESPONSE_NOT_READY. The RESPOND_IF_READY is sent and an expected SPDM response is received.
  @retval RETURN_NO_RESPONSE           The error code is BUSY.
  @retval RETURN_DEVICE_ERROR          The error code is REQUEST_RESYNCH or others.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmHandleErrorResponseMain (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               *SessionId,
  IN OUT VOID                 *ManagedBuffer,
  IN     UINTN                 ShrinkBufferSize,
  IN OUT UINTN                *ResponseSize,
  IN OUT VOID                 *Response,
  IN     UINT8                 OriginalRequestCode,
  IN     UINT8                 ExpectedResponseCode,
  IN     UINTN                 ExpectedResponseSize
  );

/**
  This function sends GET_VERSION and receives VERSION.

  @param  SpdmContext                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The GET_VERSION is sent and the VERSION is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmGetVersion (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  );

/**
  This function sends GET_CAPABILITIES and receives CAPABILITIES.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequesterCTExponent          RequesterCTExponent to the GET_CAPABILITIES request.
  @param  RequesterFlags               RequesterFlags to the GET_CAPABILITIES request.
  @param  ResponderCTExponent          ResponderCTExponent from the CAPABILITIES response.
  @param  ResponderFlags               ResponderFlags from the CAPABILITIES response.

  @retval RETURN_SUCCESS               The GET_CAPABILITIES is sent and the CAPABILITIES is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmGetCapabilities (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  );

/**
  This function sends NEGOTIATE_ALGORITHMS and receives ALGORITHMS.

  @param  SpdmContext                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The NEGOTIATE_ALGORITHMS is sent and the ALGORITHMS is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmNegotiateAlgorithms (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  );

/**
  This function sends KEY_EXCHANGE and receives KEY_EXCHANGE_RSP for SPDM key exchange.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MeasurementHashType          MeasurementHashType to the KEY_EXCHANGE request.
  @param  SlotNum                      SlotNum to the KEY_EXCHANGE request.
  @param  HeartbeatPeriod              HeartbeatPeriod from the KEY_EXCHANGE_RSP response.
  @param  SessionId                    SessionId from the KEY_EXCHANGE_RSP response.
  @param  ReqSlotIdParam               ReqSlotIdParam from the KEY_EXCHANGE_RSP response.
  @param  MeasurementHash              MeasurementHash from the KEY_EXCHANGE_RSP response.

  @retval RETURN_SUCCESS               The KEY_EXCHANGE is sent and the KEY_EXCHANGE_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmSendReceiveKeyExchange (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT32               *SessionId,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT8                *ReqSlotIdParam,
     OUT VOID                 *MeasurementHash
  );

/**
  This function sends FINISH and receives FINISH_RSP for SPDM finish.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    SessionId to the FINISH request.
  @param  ReqSlotIdParam               ReqSlotIdParam to the FINISH request.

  @retval RETURN_SUCCESS               The FINISH is sent and the FINISH_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmSendReceiveFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                ReqSlotIdParam
  );

/**
  This function sends PSK_EXCHANGE and receives PSK_EXCHANGE_RSP for SPDM PSK exchange.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MeasurementHashType          MeasurementHashType to the PSK_EXCHANGE request.
  @param  HeartbeatPeriod              HeartbeatPeriod from the PSK_EXCHANGE_RSP response.
  @param  SessionId                    SessionId from the PSK_EXCHANGE_RSP response.
  @param  MeasurementHash              MeasurementHash from the PSK_EXCHANGE_RSP response.

  @retval RETURN_SUCCESS               The PSK_EXCHANGE is sent and the PSK_EXCHANGE_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmSendReceivePskExchange (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementHashType,
     OUT UINT32               *SessionId,
     OUT UINT8                *HeartbeatPeriod,
     OUT VOID                 *MeasurementHash
  );

/**
  This function sends PSK_FINISH and receives PSK_FINISH_RSP for SPDM PSK finish.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    SessionId to the PSK_FINISH request.

  @retval RETURN_SUCCESS               The PSK_FINISH is sent and the PSK_FINISH_RSP is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmSendReceivePskFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId
  );

/**
  This function sends END_SESSION and receives END_SESSION_ACK for SPDM session end.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    SessionId to the END_SESSION request.
  @param  EndSessionAttributes         EndSessionAttributes to the END_SESSION_ACK request.

  @retval RETURN_SUCCESS               The END_SESSION is sent and the END_SESSION_ACK is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmSendReceiveEndSession (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                EndSessionAttributes
  );

/**
  This function executes a series of SPDM encapsulated requests and receives SPDM encapsulated responses.

  This function starts with the first encapsulated request (such as GET_ENCAPSULATED_REQUEST)
  and ends with last encapsulated response (such as RESPONSE_PAYLOAD_TYPE_ABSENT or RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER).

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicate if the encapsulated request is a secured message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  MutAuthRequested             Indicate of the MutAuthRequested through KEY_EXCHANGE or CHALLENG response.
  @param  ReqSlotIdParam               ReqSlotIdParam from the RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER.

  @retval RETURN_SUCCESS               The SPDM Encapsulated requests are sent and the responses are received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmEncapsulatedRequest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINT8                MutAuthRequested,
     OUT UINT8                *ReqSlotIdParam
  );

/**
  Process the SPDM encapsulated GET_DIGESTS request and return the response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestSize                  Size in bytes of the request data.
  @param  Request                      A pointer to the request data.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  Response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetEncapResponseDigest (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

/**
  Process the SPDM encapsulated GET_CERTIFICATE request and return the response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestSize                  Size in bytes of the request data.
  @param  Request                      A pointer to the request data.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  Response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetEncapResponseCertificate (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

/**
  Process the SPDM encapsulated CHALLENGE request and return the response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestSize                  Size in bytes of the request data.
  @param  Request                      A pointer to the request data.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  Response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetEncapResponseChallengeAuth (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

/**
  Process the SPDM encapsulated KEY_UPDATE request and return the response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestSize                  Size in bytes of the request data.
  @param  Request                      A pointer to the request data.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  Response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetEncapResponseKeyUpdate (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

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
  );

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
  );

#endif
