/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_REQUESTER_LIB_H__
#define __SPDM_REQUESTER_LIB_H__

#include <Library/SpdmCommonLib.h>

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
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsAppMessage,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request
  );

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
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsAppMessage,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

/**
  This function sends GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS
  to initialize the connection with SPDM responder.

  Before this function, the requester configuration data can be set via SpdmSetData.
  After this function, the negotiated configuration data can be got via SpdmGetData.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  GetVersionOnly               If the requester sends GET_VERSION only or not.

  @retval RETURN_SUCCESS               The connection is initialized successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmInitConnection (
  IN     VOID                 *SpdmContext,
  IN     BOOLEAN              GetVersionOnly
  );

/**
  This function sends GET_DIGEST
  to get all digest of the certificate chains from device.

  If the peer certificate chain is deployed,
  this function also verifies the digest with the certificate chain.

  TotalDigestSize = sizeof(Digest) * Count in SlotMask

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SlotMask                     The slots which deploy the CertificateChain.
  @param  TotalDigestBuffer            A pointer to a destination buffer to store the digest buffer.

  @retval RETURN_SUCCESS               The digests are got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetDigest (
  IN     VOID                 *SpdmContext,
     OUT UINT8                *SlotMask,
     OUT VOID                 *TotalDigestBuffer
  );

/**
  This function sends GET_CERTIFICATE
  to get certificate chain in one slot from device.

  This function verify the integrity of the certificate chain.
  RootHash -> Root certificate -> Intermediate certificate -> Leaf certificate.

  If the peer root certificate hash is deployed,
  this function also verifies the digest with the root hash in the certificate chain.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SlotNum                      The number of slot for the certificate chain.
  @param  CertChainSize                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  CertChain                    A pointer to a destination buffer to store the certificate chain.

  @retval RETURN_SUCCESS               The certificate chain is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetCertificate (
  IN     VOID                 *SpdmContext,
  IN     UINT8                SlotNum,
  IN OUT UINTN                *CertChainSize,
     OUT VOID                 *CertChain
  );

/**
  This function sends GET_CERTIFICATE
  to get certificate chain in one slot from device.

  This function verify the integrity of the certificate chain.
  RootHash -> Root certificate -> Intermediate certificate -> Leaf certificate.

  If the peer root certificate hash is deployed,
  this function also verifies the digest with the root hash in the certificate chain.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SlotNum                      The number of slot for the certificate chain.
  @param  Length                       MAX_SPDM_CERT_CHAIN_BLOCK_LEN.
  @param  CertChainSize                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  CertChain                    A pointer to a destination buffer to store the certificate chain.

  @retval RETURN_SUCCESS               The certificate chain is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetCertificateChooseLength (
  IN     VOID                 *SpdmContext,
  IN     UINT8                SlotNum,
  IN     UINT16               Length,
  IN OUT UINTN                *CertChainSize,
     OUT VOID                 *CertChain
  );

/**
  This function sends CHALLENGE
  to authenticate the device based upon the key in one slot.

  This function verifies the signature in the challenge auth.

  If basic mutual authentication is requested from the responder,
  this function also perform the basic mutual authentication.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SlotNum                      The number of slot for the challenge.
  @param  MeasurementHashType          The type of the measurement hash.
  @param  MeasurementHash              A pointer to a destination buffer to store the measurement hash.

  @retval RETURN_SUCCESS               The challenge auth is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmChallenge (
  IN     VOID                 *SpdmContext,
  IN     UINT8                SlotNum,
  IN     UINT8                MeasurementHashType,
     OUT VOID                 *MeasurementHash
  );

/**
  This function sends GET_MEASUREMENT
  to get measurement from the device.

  If the signature is requested, this function verifies the signature of the measurement.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  RequestAttribute             The request attribute of the request message.
  @param  MeasurementOperation         The measurement operation of the request message.
  @param  SlotNum                      The number of slot for the certificate chain.
  @param  NumberOfBlocks               The number of blocks of the measurement record.
  @param  MeasurementRecordLength      On input, indicate the size in bytes of the destination buffer to store the measurement record.
                                       On output, indicate the size in bytes of the measurement record.
  @param  MeasurementRecord            A pointer to a destination buffer to store the measurement record.

  @retval RETURN_SUCCESS               The measurement is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetMeasurement (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINT8                RequestAttribute,
  IN     UINT8                MeasurementOperation,
  IN     UINT8                SlotNum,
     OUT UINT8                *NumberOfBlocks,
  IN OUT UINT32               *MeasurementRecordLength,
     OUT VOID                 *MeasurementRecord
  );

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
  IN     VOID                 *SpdmContext,
  IN     BOOLEAN              UsePsk,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT32               *SessionId,
     OUT UINT8                *HeartbeatPeriod,
     OUT VOID                 *MeasurementHash
  );

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
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINT8                EndSessionAttributes
  );

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
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsAppMessage,
  IN     VOID                 *Request,
  IN     UINTN                RequestSize,
     OUT VOID                 *Response,
  IN OUT UINTN                *ResponseSize
  );

/**
  This function sends HEARTBEAT
  to an SPDM Session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The session ID of the session.

  @retval RETURN_SUCCESS               The heartbeat is sent and received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmHeartbeat (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId
  );

/**
  This function sends KEY_UPDATE
  to update keys for an SPDM Session.

  After keys are updated, this function also uses VERIFY_NEW_KEY to verify the key.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The session ID of the session.
  @param  SingleDirection              TRUE means the operation is UPDATE_KEY.
                                       FALSE means the operation is UPDATE_ALL_KEYS.

  @retval RETURN_SUCCESS               The keys of the session are updated.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmKeyUpdate (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     BOOLEAN              SingleDirection
  );

/**
  This function executes a series of SPDM encapsulated requests and receives SPDM encapsulated responses.

  This function starts with the first encapsulated request (such as GET_ENCAPSULATED_REQUEST)
  and ends with last encapsulated response (such as RESPONSE_PAYLOAD_TYPE_ABSENT or RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER).

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicate if the encapsulated request is a secured message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.

  @retval RETURN_SUCCESS               The SPDM Encapsulated requests are sent and the responses are received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmSendReceiveEncapsulatedRequest (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId
  );

/**
  Process the encapsulated request and return the encapsulated response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SpdmRequestSize              Size in bytes of the request data.
  @param  SpdmRequest                  A pointer to the request data.
  @param  SpdmResponseSize             Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  SpdmResponse                 A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_ENCAP_RESPONSE_FUNC) (
  IN     VOID                 *SpdmContext,
  IN     UINTN                SpdmRequestSize,
  IN     VOID                 *SpdmRequest,
  IN OUT UINTN                *SpdmResponseSize,
     OUT VOID                 *SpdmResponse
  );

/**
  Register an SPDM encapsulated message process function.

  If the default encapsulated message process function cannot handle the encapsulated message,
  this function will be invoked.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  GetEncapResponseFunc         The function to process the encapsuled message.
**/
VOID
EFIAPI
SpdmRegisterGetEncapResponseFunc (
  IN  VOID                          *SpdmContext,
  IN  SPDM_GET_ENCAP_RESPONSE_FUNC  GetEncapResponseFunc
  );

/**
  Generate encapsulated ERROR message.

  This function can be called in SPDM_GET_ENCAP_RESPONSE_FUNC.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ErrorCode                    The error code of the message.
  @param  ErrorData                    The error data of the message.
  @param  SpdmResponseSize             Size in bytes of the response data.
                                       On input, it means the size in bytes of Data buffer.
                                       On output, it means the size in bytes of copied Data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired Data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  SpdmResponse                 A pointer to the response data.

  @retval RETURN_SUCCESS               The error message is generated.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmGenerateEncapErrorResponse (
  IN     VOID                 *SpdmContext,
  IN     UINT8                ErrorCode,
  IN     UINT8                ErrorData,
  IN OUT UINTN                *SpdmResponseSize,
     OUT VOID                 *SpdmResponse
  );

/**
  Generate encapsulated ERROR message with extended error data.

  This function can be called in SPDM_GET_ENCAP_RESPONSE_FUNC.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ErrorCode                    The error code of the message.
  @param  ErrorData                    The error data of the message.
  @param  ExtendedErrorDataSize        The size in bytes of the extended error data.
  @param  ExtendedErrorData            A pointer to the extended error data.
  @param  SpdmResponseSize             Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  SpdmResponse                 A pointer to the response data.

  @retval RETURN_SUCCESS               The error message is generated.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmGenerateEncapExtendedErrorResponse (
  IN     VOID                 *SpdmContext,
  IN     UINT8                ErrorCode,
  IN     UINT8                ErrorData,
  IN     UINTN                ExtendedErrorDataSize,
  IN     UINT8                *ExtendedErrorData,
  IN OUT UINTN                *SpdmResponseSize,
     OUT VOID                 *SpdmResponse
  );

#endif