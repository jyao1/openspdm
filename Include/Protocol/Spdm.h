/** @file
  SPDM Protocol definition

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_PROTOCOL_H__
#define __SPDM_PROTOCOL_H__

#include <Base.h>
#include <IndustryStandard/Spdm.h>

typedef struct _SPDM_PROTOCOL SPDM_PROTOCOL;

//
// Connection: When a host sends messgages to a device, they create a connection.
//             The host can and only can create one connection with one device.
//             The host may create multiple connections with multiple devices at same time.
//             A connection can be unique identified by the connected device.
//             The message exchange in a connection is plain text.
//
// Session: In one connection with one device, a host may create multiple sessions.
//          The session starts with via KEY_EXCHANGE or PSK_EXCHANGE, and step with END_SESSION.
//          A session can be unique identified by a session ID, returned from the device.
//          The message exchange in a session is cipher text.
//

typedef enum {
  //
  // SPDM parameter
  //
  SpdmDataVersion,
  //
  // SPDM capability
  //
  SpdmDataCapabilityFlags,
  SpdmDataCapabilityCTExponent,  
  //
  // SPDM Algorithm setting
  //
  SpdmDataMeasurementHashAlgo,
  SpdmDataBaseAsymAlgo,
  SpdmDataBaseHashAlgo,
  SpdmDataDHENamedGroup,
  SpdmDataAEADCipherSuite,
  SpdmDataKeySchedule,
  //
  // Certificate info
  //
  SpdmDataPeerPublicCertChains,
  SpdmDataSlotCount,
  SpdmDataPublicCertChains,
  SpdmDataPrivateCertificate,
  SpdmDataMeasurementRecord,
  //
  // Pre-shared secret
  // If PSK is present, then PSK_EXCHANGE is used.
  // Otherwise, the KEY_EXCHANGE is used.
  //
  SpdmDataPsk,

  //
  // MAX
  //
  SpdmDataMax,
} SPDM_DATA_TYPE;

typedef enum {
  //
  // Below per session data is defined for debug purpose
  // GET-only in debug mode.
  //
  // NOTE: This is persession data. Need input SessionId in the input buffer
  //

  //
  // Master Secret
  //
  SpdmDataDheSecret = 0x80000000, // No DHE secret if PSK is used.
  SpdmDataHandshakeSecret,
  SpdmDataMasterSecret,
  //
  // Major secret
  //
  SpdmDataRequestHandshakeSecret,
  SpdmDataResponseHandshakeSecret,
  SpdmDataRequestDataSecret,
  SpdmDataResponseDataSecret,
  SpdmDataRequestFinishedKey,
  SpdmDataResponseFinishedKey,
  //
  // Derived Key & Salt
  //
  SpdmDataRequestHandshakeEncryptionKey,
  SpdmDataRequestHandshakeSalt,
  SpdmDataResponseHandshakeEncryptionKey,
  SpdmDataResponseHandshakeSalt,
  SpdmDataRequestDataEncryptionKey,
  SpdmDataRequestDataSalt,
  SpdmDataResponseDataEncryptionKey,
  SpdmDataResponseDataSalt,
  //
  // MAX
  //
  SpdmDataDebugDataMax,
} SPDM_DEBUG_DATA_TYPE;

typedef enum {
  SpdmDataLocationLocal,
  SpdmDataLocationConnection,
  SpdmDataLocationSession,
  SpdmDataLocationMax,
} SPDM_DATA_LOCATION;

typedef struct {
  SPDM_DATA_LOCATION   Location;
  // DataType specific:
  //   SessionId for the negoatiated key.
  //   SlotId for the certificate.
  UINT8                AdditionalData[4];
} SPDM_DATA_PARAMETER;

/**
  Set a SPDM local Data.

  @param  This                         Indicates a pointer to the calling context.
  @param  DataType                     Type of the session data.
  @param  Data                         A pointer to the session data.
  @param  DataSize                     Size of the session data.

  @retval RETURN_SUCCESS                  The SPDM session data is set successfully.
  @retval RETURN_INVALID_PARAMETER        The Data is NULL or the DataType is zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_ACCESS_DENIED            The DataType cannot be set.
  @retval RETURN_NOT_READY                Current session is not started.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_SET_DATA_FUNC) (
  IN     SPDM_PROTOCOL             *This,
  IN     SPDM_DATA_TYPE            DataType,
  IN     SPDM_DATA_PARAMETER       *Parameter,
  IN     VOID                      *Data,
  IN     UINTN                     DataSize
  );

/**
  Get a SPDM local or remote Data.

  If the data is session specific, the session ID should be input.

  @param  This                         Indicates a pointer to the calling context.
  @param  DataType                     Type of the session data.
  @param  Data                         A pointer to the session data.
  @param  DataSize                     Size of the session data. On input, it means the size of Data
                                       buffer. On output, it means the size of copied Data buffer if
                                       RETURN_SUCCESS, and means the size of desired Data buffer if
                                       RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS                  The SPDM session data is set successfully.
  @retval RETURN_INVALID_PARAMETER        The DataSize is NULL or the Data is NULL and *DataSize is not zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_NOT_FOUND                The DataType cannot be found.
  @retval RETURN_NOT_READY                The DataType is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL         The buffer is too small to hold the data.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_DATA_FUNC) (
  IN     SPDM_PROTOCOL             *This,
  IN     SPDM_DATA_TYPE            DataType,
  IN     SPDM_DATA_PARAMETER       *Parameter,
  IN OUT VOID                      *Data,
  IN OUT UINTN                     *DataSize
  );

/**
  Start a SPDM Session.

  @param  This                         Indicates a pointer to the calling context.

  @retval RETURN_SUCCESS                  The SPDM session is started.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_START_SESSION_FUNC) (
  IN     SPDM_PROTOCOL        *This,
  IN     BOOLEAN              UsePsk,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT8                *SessionId,
     OUT VOID                 *MeasurementHash
  );

/**
  Stop a SPDM Session.

  @param  This                         Indicates a pointer to the calling context.

  @retval RETURN_SUCCESS                  The SPDM session is stopped.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_STOP_SESSION_FUNC) (
  IN     SPDM_PROTOCOL        *This,
  IN     UINT8                SessionId,
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
typedef
RETURN_STATUS
(EFIAPI *SPDM_SEND_RECEIVE_SESSION_DATA_FUNC) (
  IN     SPDM_PROTOCOL        *This,
  IN     UINT8                SessionId,
  IN     VOID                 *Request,
  IN     UINTN                RequestSize,
  IN OUT VOID                 *Response,
  IN OUT UINTN                *ResponseSize
  );

/*
  Call GetVersion, GetCapabilities, NegotiateAlgorithms

  The negotiated data can be get via GetData.
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_INIT_CONNECTION_FUNC) (
  IN     SPDM_PROTOCOL        *This
  );

/*
  Get all digest of the CertificateChains returned from device.

  TotalDigestSize = sizeof(Digest) * Count in SlotMask
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_DIGEST_FUNC) (
  IN     SPDM_PROTOCOL        *This,
     OUT UINT8                *SlotMask,
     OUT VOID                 *TotalDigestBuffer
  );

/*
  Get CertificateChain in one slot returned from device.
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_CERTIFICATE_FUNC) (
  IN     SPDM_PROTOCOL        *This,
  IN     UINT8                SlotNum,
     OUT UINTN                *CertChainSize,
     OUT VOID                 *CertChain
  );

/*
  Authenticate based upon the key in one slot.
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_CHALLENGE_FUNC) (
  IN     SPDM_PROTOCOL        *This,
  IN     UINT8                SlotNum,
  IN     UINT8                MeasurementHashType,
     OUT VOID                 *MeasurementHash
  );

/*
  Get measurement
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_MEASUREMENT_FUNC) (
  IN     SPDM_PROTOCOL        *This,
  IN     UINT8                RequestAttribute,
  IN     UINT8                MeasurementOperation,
     OUT UINT8                *NumberOfBlocks,
     OUT UINT32               *MeasurementRecordLength,
     OUT VOID                 *MeasurementRecord
  );

/*
  Send receive SPDM data (non session data).
*/
typedef
RETURN_STATUS
(EFIAPI *SPDM_SEND_RECEIVE_DATA_FUNC) (
  IN     SPDM_PROTOCOL        *This,
  IN     VOID                 *Request,
  IN     UINTN                RequestSize,
  IN OUT VOID                 *Response,
  IN OUT UINTN                *ResponseSize
  );

struct _SPDM_PROTOCOL {
  SPDM_SET_DATA_FUNC                   SetData;
  SPDM_GET_DATA_FUNC                   GetData;
  SPDM_INIT_CONNECTION_FUNC            InitConnection;
  SPDM_GET_DIGEST_FUNC                 GetDigest;
  SPDM_GET_CERTIFICATE_FUNC            GetCertificate;
  SPDM_CHALLENGE_FUNC                  Challenge;
  SPDM_GET_MEASUREMENT_FUNC            GetMeasurement;
  SPDM_SEND_RECEIVE_DATA_FUNC          SendReceiveData;
  SPDM_START_SESSION_FUNC              StartSession;
  SPDM_STOP_SESSION_FUNC               StopSession;
  SPDM_SEND_RECEIVE_SESSION_DATA_FUNC  SendReceiveSessionData;
};

#endif
