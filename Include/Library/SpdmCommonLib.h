/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_COMMON_LIB_H__
#define __SPDM_COMMON_LIB_H__

#include "SpdmLibConfig.h"

#include <Base.h>
#include <IndustryStandard/Spdm.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>

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

#define MAX_SPDM_VERSION_COUNT            2
#define MAX_SPDM_SLOT_COUNT               8
#define MAX_SPDM_OPAQUE_DATA_SIZE         1024

#define SPDM_NONCE_SIZE           32
#define SPDM_RANDOM_DATA_SIZE     32

#define MAX_DHE_KEY_SIZE    512
#define MAX_ASYM_KEY_SIZE   512
#define MAX_HASH_SIZE       64
#define MAX_AEAD_KEY_SIZE   32
#define MAX_AEAD_IV_SIZE    12

#define SPDM_STATUS_SUCCESS                          0
#define SPDM_STATUS_ERROR                            BIT31
#define SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES     (SPDM_STATUS_ERROR + 0x10)
#define SPDM_STATUS_ERROR_DEVICE_ERROR               (SPDM_STATUS_ERROR + 0x11)
#define SPDM_STATUS_ERROR_TCG_EXTEND_TPM_PCR         (SPDM_STATUS_ERROR + 0x20)
#define SPDM_STATUS_ERROR_MEASUREMENT_AUTH_FAILURE   (SPDM_STATUS_ERROR + 0x21)
#define SPDM_STATUS_ERROR_CHALLENGE_FAILURE          (SPDM_STATUS_ERROR + 0x30)
#define SPDM_STATUS_ERROR_CERTIFIACTE_FAILURE        (SPDM_STATUS_ERROR + 0x31)
#define SPDM_STATUS_ERROR_NO_CERT_PROVISION          (SPDM_STATUS_ERROR + 0x32)
#define SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE       (SPDM_STATUS_ERROR + 0x40)
#define SPDM_STATUS_ERROR_NO_MUTUAL_AUTH             (SPDM_STATUS_ERROR + 0x41)

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
  SpdmDataReqBaseAsymAlg,
  SpdmDataKeySchedule,
  //
  // Certificate info
  //
  SpdmDataPeerPublicRootCertHash,
  SpdmDataPeerPublicCertChains,
  SpdmDataSlotCount,
  SpdmDataPublicCertChains,
  SpdmDataMeasurementRecord,
  SpdmDataMutAuthRequested,
  //
  // Pre-shared secret
  // If PSK is present, then PSK_EXCHANGE is used.
  // Otherwise, the KEY_EXCHANGE is used.
  //
  SpdmDataPsk,
  SpdmDataPskHint,
  //
  // OpaqueData
  //
  SpdmDataOpaqueChallengeAuthRsp,
  SpdmDataOpaqueMeasurementRsp,
  SpdmDataOpaqueKeyExchangeReq,
  SpdmDataOpaqueKeyExchangeRsp,
  SpdmDataOpaquePskExchangeReq,
  SpdmDataOpaquePskExchangeRsp,

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
  Set a SPDM Session Data.

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
RETURN_STATUS
EFIAPI
SpdmSetData (
  IN     VOID                      *SpdmContext,
  IN     SPDM_DATA_TYPE            DataType,
  IN     SPDM_DATA_PARAMETER       *Parameter,
  IN     VOID                      *Data,
  IN     UINTN                     DataSize
  );

/**
  Get a SPDM Session Data.

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
RETURN_STATUS
EFIAPI
SpdmGetData (
  IN     VOID                      *SpdmContext,
  IN     SPDM_DATA_TYPE            DataType,
  IN     SPDM_DATA_PARAMETER       *Parameter,
  IN OUT VOID                      *Data,
  IN OUT UINTN                     *DataSize
  );

UINT32
EFIAPI
SpdmGetLastError (
  IN     VOID                      *SpdmContext
  );

RETURN_STATUS
EFIAPI
SpdmSetAlignment (
  IN     VOID                      *SpdmContext,
  IN     UINT32                    Alignment
  );

UINT32
EFIAPI
SpdmGetAlignment (
  IN     VOID                      *SpdmContext
  );

RETURN_STATUS
EFIAPI
SpdmInitContext (
  IN     VOID                      *SpdmContext
  );

UINTN
EFIAPI
SpdmGetContextSize (
  VOID
  );

/**
  The asym algo is aligned with SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_*
**/
typedef
BOOLEAN
(EFIAPI *SPDM_DATA_SIGN_FUNC) (
  IN      VOID         *SpdmContext,
  IN      BOOLEAN      IsResponder,
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

RETURN_STATUS
EFIAPI
SpdmRegisterDataSignFunc (
  IN     VOID                      *SpdmContext,
  IN     SPDM_DATA_SIGN_FUNC       SpdmDataSignFunc
  );

/**
  Send a SPDM message to a device.

  For requester, the message is an SPDM request.
  For responder, the message is an SPDM response.

  @param  This                         Indicates a pointer to the calling context.
  @param  SessionId                    The SessionId of a SPDM message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secure message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the message. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       message to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the message is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS               The SPDM message is sent successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is sent to the device.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
  @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
                                       to execute.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_DEVICE_SEND_MESSAGE_FUNC) (
  IN     VOID                                   *SpdmContext,
  IN     UINT32                                 *SessionId,
  IN     UINTN                                  MessageSize,
  IN     VOID                                   *Message,
  IN     UINT64                                 Timeout
  );

/**
  Receive a SPDM message from a device.

  For requester, the message is an SPDM response.
  For responder, the message is an SPDM request.

  @param  This                         Indicates a pointer to the calling context.
  @param  SessionId                    The SessionId of a SPDM message.
                                       If *SessionId is NULL, it is a normal message.
                                       If *SessionId is NOT NULL, it is a secure message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the message. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       message to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the message is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS               The SPDM message is received successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is received from the device.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL, MessageSize is NULL or
                                       the *MessageSize is zero.
  @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
                                       to execute.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_DEVICE_RECEIVE_MESSAGE_FUNC) (
  IN     VOID                                   *SpdmContext,
     OUT UINT32                                 **SessionId,
  IN OUT UINTN                                  *MessageSize,
  IN OUT VOID                                   *Message,
  IN     UINT64                                 Timeout
  );

RETURN_STATUS
EFIAPI
SpdmRegisterDeviceIoFunc (
  IN     VOID                              *SpdmContext,
  IN     SPDM_DEVICE_SEND_MESSAGE_FUNC     SendMessage,
  IN     SPDM_DEVICE_RECEIVE_MESSAGE_FUNC  ReceiveMessage
  );

#endif