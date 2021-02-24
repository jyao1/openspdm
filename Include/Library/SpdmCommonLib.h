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
#include <Library/SpdmCryptLib.h>
#include <Library/SpdmSecuredMessageLib.h>
#include <Library/SpdmDeviceSecretLib.h>

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

#define MAX_SPDM_VERSION_COUNT            5
#define MAX_SPDM_SLOT_COUNT               8
#define MAX_SPDM_OPAQUE_DATA_SIZE         1024

#define SPDM_NONCE_SIZE           32
#define SPDM_RANDOM_DATA_SIZE     32

#define SPDM_STATUS_SUCCESS                          0
#define SPDM_STATUS_ERROR                            BIT31
#define SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES     (SPDM_STATUS_ERROR + 0x10)
#define SPDM_STATUS_ERROR_DEVICE_ERROR               (SPDM_STATUS_ERROR + 0x11)
#define SPDM_STATUS_ERROR_TCG_EXTEND_TPM_PCR         (SPDM_STATUS_ERROR + 0x20)
#define SPDM_STATUS_ERROR_MEASUREMENT_AUTH_FAILURE   (SPDM_STATUS_ERROR + 0x21)
#define SPDM_STATUS_ERROR_CHALLENGE_FAILURE          (SPDM_STATUS_ERROR + 0x30)
#define SPDM_STATUS_ERROR_CERTIFICATE_FAILURE        (SPDM_STATUS_ERROR + 0x31)
#define SPDM_STATUS_ERROR_NO_CERT_PROVISION          (SPDM_STATUS_ERROR + 0x32)
#define SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE       (SPDM_STATUS_ERROR + 0x40)
#define SPDM_STATUS_ERROR_NO_MUTUAL_AUTH             (SPDM_STATUS_ERROR + 0x41)

typedef enum {
  //
  // SPDM parameter
  //
  SpdmDataSpdmVersion,
  SpdmDataSecuredMessageVersion,
  //
  // SPDM capability
  //
  SpdmDataCapabilityFlags,
  SpdmDataCapabilityCTExponent,
  //
  // SPDM Algorithm setting
  //
  SpdmDataMeasurementSpec,
  SpdmDataMeasurementHashAlgo,
  SpdmDataBaseAsymAlgo,
  SpdmDataBaseHashAlgo,
  SpdmDataDHENamedGroup,
  SpdmDataAEADCipherSuite,
  SpdmDataReqBaseAsymAlg,
  SpdmDataKeySchedule,
  //
  // Connection State
  //
  SpdmDataConnectionState,
  //
  // ResponseState
  //
  SpdmDataResponseState,
  //
  // Certificate info
  //
  SpdmDataLocalPublicCertChain,
  SpdmDataLocalSlotCount,
  SpdmDataPeerPublicRootCertHash,
  SpdmDataPeerPublicCertChains,
  SpdmDataBasicMutAuthRequested,
  SpdmDataMutAuthRequested,
  //
  // Negotiated result
  //
  SpdmDataLocalUsedCertChainBuffer,
  SpdmDataPeerUsedCertChainBuffer,
  //
  // Pre-shared Key Hint
  // If PSK is present, then PSK_EXCHANGE is used.
  // Otherwise, the KEY_EXCHANGE is used.
  //
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
  // SessionData
  //
  SpdmDataSessionUsePsk,
  SpdmDataSessionMutAuthRequested,
  SpdmDataSessionEndSessionAttributes,

  //
  // MAX
  //
  SpdmDataMax,
} SPDM_DATA_TYPE;

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
  //   ReqSlotNum + MeasurementHashType for SpdmDataMutAuthRequested
  UINT8                AdditionalData[4];
} SPDM_DATA_PARAMETER;

typedef enum {
  //
  // Before GET_VERSION/VERSION
  //
  SpdmConnectionStateNotStarted,
  //
  // After GET_VERSION/VERSION
  //
  SpdmConnectionStateAfterVersion,
  //
  // After GET_CAPABILITIES/CAPABILITIES
  //
  SpdmConnectionStateAfterCapabilities,
  //
  // After NEGOTIATE_ALGORITHMS/ALGORITHMS
  //
  SpdmConnectionStateNegotiated,
  //
  // After GET_DIGESTS/DIGESTS
  //
  SpdmConnectionStateAfterDigests,
  //
  // After GET_CERTIFICATE/CERTIFICATE
  //
  SpdmConnectionStateAfterCertificate,
  //
  // After CHALLENGE/CHALLENGE_AUTH, and ENCAP CALLENGE/CHALLENG_AUTH if MUT_AUTH is enabled.
  //
  SpdmConnectionStateAuthenticated,
  //
  // MAX
  //
  SpdmConnectionStateMax,
} SPDM_CONNECTION_STATE;

typedef enum {
  //
  // Normal response.
  //
  SpdmResponseStateNormal,
  //
  // Other component is busy.
  //
  SpdmResponseStateBusy,
  //
  // Hardware is not ready.
  //
  SpdmResponseStateNotReady,
  //
  // Firmware Update is done. Need resync.
  //
  SpdmResponseStateNeedResync,
  //
  // Processing Encapsulated message.
  //
  SpdmResponseStateProcessingEncap,
  //
  // MAX
  //
  SpdmResponseStateMax,
} SPDM_RESPONSE_STATE;

/**
  Set an SPDM context data.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  DataType                     Type of the SPDM context data.
  @param  Parameter                    Type specific parameter of the SPDM context data.
  @param  Data                         A pointer to the SPDM context data.
  @param  DataSize                     Size in bytes of the SPDM context data.

  @retval RETURN_SUCCESS               The SPDM context data is set successfully.
  @retval RETURN_INVALID_PARAMETER     The Data is NULL or the DataType is zero.
  @retval RETURN_UNSUPPORTED           The DataType is unsupported.
  @retval RETURN_ACCESS_DENIED         The DataType cannot be set.
  @retval RETURN_NOT_READY             Data is not ready to set.
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
  Get an SPDM context data.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  DataType                     Type of the SPDM context data.
  @param  Parameter                    Type specific parameter of the SPDM context data.
  @param  Data                         A pointer to the SPDM context data.
  @param  DataSize                     Size in bytes of the SPDM context data.
                                       On input, it means the size in bytes of Data buffer.
                                       On output, it means the size in bytes of copied Data buffer if RETURN_SUCCESS,
                                       and means the size in bytes of desired Data buffer if RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS               The SPDM context data is set successfully.
  @retval RETURN_INVALID_PARAMETER     The DataSize is NULL or the Data is NULL and *DataSize is not zero.
  @retval RETURN_UNSUPPORTED           The DataType is unsupported.
  @retval RETURN_NOT_FOUND             The DataType cannot be found.
  @retval RETURN_NOT_READY             The Data is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
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

/**
  Get the last error of an SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return Last error of an SPDM context.
*/
UINT32
EFIAPI
SpdmGetLastError (
  IN     VOID                      *SpdmContext
  );

/**
  Get the last SPDM error struct of an SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  LastSpdmError                Last SPDM error struct of an SPDM context.
*/
VOID
EFIAPI
SpdmGetLastSpdmErrorStruct (
  IN     VOID                      *SpdmContext,
     OUT SPDM_ERROR_STRUCT         *LastSpdmError
  );

/**
  Set the last SPDM error struct of an SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  LastSpdmError                Last SPDM error struct of an SPDM context.
*/
VOID
EFIAPI
SpdmSetLastSpdmErrorStruct (
  IN     VOID                      *SpdmContext,
  IN     SPDM_ERROR_STRUCT         *LastSpdmError
  );

/**
  Initialize an SPDM context.

  The size in bytes of the SpdmContext can be returned by SpdmGetContextSize.

  @param  SpdmContext                  A pointer to the SPDM context.
*/
VOID
EFIAPI
SpdmInitContext (
  IN     VOID                      *SpdmContext
  );

/**
  Return the size in bytes of the SPDM context.

  @return the size in bytes of the SPDM context.
**/
UINTN
EFIAPI
SpdmGetContextSize (
  VOID
  );

/**
  Send an SPDM transport layer message to a device.

  The message is an SPDM message with transport layer wrapper,
  or a secured SPDM message with transport layer wrapper.

  For requester, the message is a transport layer SPDM request.
  For responder, the message is a transport layer SPDM response.

  @param  SpdmContext                  A pointer to the SPDM context.
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
  IN     UINTN                                  MessageSize,
  IN     VOID                                   *Message,
  IN     UINT64                                 Timeout
  );

/**
  Receive an SPDM transport layer message from a device.

  The message is an SPDM message with transport layer wrapper,
  or a secured SPDM message with transport layer wrapper.

  For requester, the message is a transport layer SPDM response.
  For responder, the message is a transport layer SPDM request.

  @param  SpdmContext                  A pointer to the SPDM context.
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
  IN OUT UINTN                                  *MessageSize,
  IN OUT VOID                                   *Message,
  IN     UINT64                                 Timeout
  );

/**
  Register SPDM device input/output functions.

  This function must be called after SpdmInitContext, and before any SPDM communication.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SendMessage                  The fuction to send an SPDM transport layer message.
  @param  ReceiveMessage               The fuction to receive an SPDM transport layer message.
**/
VOID
EFIAPI
SpdmRegisterDeviceIoFunc (
  IN     VOID                              *SpdmContext,
  IN     SPDM_DEVICE_SEND_MESSAGE_FUNC     SendMessage,
  IN     SPDM_DEVICE_RECEIVE_MESSAGE_FUNC  ReceiveMessage
  );

/**
  Encode an SPDM or APP message to a transport layer message.

  For normal SPDM message, it adds the transport layer wrapper.
  For secured SPDM message, it encrypts a secured message then adds the transport layer wrapper.
  For secured APP message, it encrypts a secured message then adds the transport layer wrapper.

  The APP message is encoded to a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  IsAppMessage                 Indicates if it is an APP message or SPDM message.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a source buffer to store the message.
  @param  TransportMessageSize         Size in bytes of the transport message data buffer.
  @param  TransportMessage             A pointer to a destination buffer to store the transport message.

  @retval RETURN_SUCCESS               The message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_TRANSPORT_ENCODE_MESSAGE_FUNC) (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsAppMessage,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  );

/**
  Decode an SPDM or APP message from a transport layer message.

  For normal SPDM message, it removes the transport layer wrapper,
  For secured SPDM message, it removes the transport layer wrapper, then decrypts and verifies a secured message.
  For secured APP message, it removes the transport layer wrapper, then decrypts and verifies a secured message.

  The APP message is decoded from a secured message directly in SPDM session.
  The APP message format is defined by the transport layer.
  Take MCTP as example: APP message == MCTP header (MCTP_MESSAGE_TYPE_SPDM) + SPDM message

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If *SessionId is NULL, it is a normal message.
                                       If *SessionId is NOT NULL, it is a secured message.
  @param  IsAppMessage                 Indicates if it is an APP message or SPDM message.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  TransportMessageSize         Size in bytes of the transport message data buffer.
  @param  TransportMessage             A pointer to a source buffer to store the transport message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.

  @retval RETURN_SUCCESS               The message is decoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
  @retval RETURN_UNSUPPORTED           The TransportMessage is unsupported.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_TRANSPORT_DECODE_MESSAGE_FUNC) (
  IN     VOID                 *SpdmContext,
     OUT UINT32               **SessionId,
     OUT BOOLEAN              *IsAppMessage,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  );

/**
  Register SPDM transport layer encode/decode functions for SPDM or APP messages.

  This function must be called after SpdmInitContext, and before any SPDM communication.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  TransportEncodeMessage       The fuction to encode an SPDM or APP message to a transport layer message.
  @param  TransportDecodeMessage       The fuction to decode an SPDM or APP message from a transport layer message.
**/
VOID
EFIAPI
SpdmRegisterTransportLayerFunc (
  IN     VOID                                *SpdmContext,
  IN     SPDM_TRANSPORT_ENCODE_MESSAGE_FUNC  TransportEncodeMessage,
  IN     SPDM_TRANSPORT_DECODE_MESSAGE_FUNC  TransportDecodeMessage
  );

/**
  Reset Message A cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageA (
  IN     VOID                                *SpdmContext
  );

/**
  Reset Message B cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageB (
  IN     VOID                                *SpdmContext
  );

/**
  Reset Message C cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageC (
  IN     VOID                                *SpdmContext
  );

/**
  Reset Message MutB cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageMutB (
  IN     VOID                                *SpdmContext
  );

/**
  Reset Message MutC cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageMutC (
  IN     VOID                                *SpdmContext
  );

/**
  Reset Message M cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageM (
  IN     VOID                                *SpdmContext
  );

/**
  Append Message A cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageA (
  IN     VOID                                *SpdmContext,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  );

/**
  Append Message B cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageB (
  IN     VOID                                *SpdmContext,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  );

/**
  Append Message C cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageC (
  IN     VOID                                *SpdmContext,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  );

/**
  Append Message MutB cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageMutB (
  IN     VOID                                *SpdmContext,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  );

/**
  Append Message MutC cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageMutC (
  IN     VOID                                *SpdmContext,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  );

/**
  Append Message M cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageM (
  IN     VOID                                *SpdmContext,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  );

/**
  Append Message K cache in SPDM context.

  @param  SpdmSessionInfo              A pointer to the SPDM session context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageK (
  IN     VOID                                *SpdmSessionInfo,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  );

/**
  Append Message F cache in SPDM context.

  @param  SpdmSessionInfo              A pointer to the SPDM session context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageF (
  IN     VOID                                *SpdmSessionInfo,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  );

/**
  This function gets the session info via session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return session info.
**/
VOID *
EFIAPI
SpdmGetSessionInfoViaSessionId (
  IN     VOID                      *SpdmContext,
  IN     UINT32                    SessionId
  );

/**
  This function gets the secured message context via session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return secured message context.
**/
VOID *
EFIAPI
SpdmGetSecuredMessageContextViaSessionId (
  IN     VOID                      *SpdmContext,
  IN     UINT32                    SessionId
  );

/**
  This function gets the secured message context via session ID.

  @param  SpdmSessionInfo              A pointer to the SPDM context.

  @return secured message context.
**/
VOID *
EFIAPI
SpdmGetSecuredMessageContextViaSessionInfo (
  IN     VOID                      *SpdmSessionInfo
  );

/**
  This function assigns a new session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return session info associated with this new session ID.
**/
VOID *
EFIAPI
SpdmAssignSessionId (
  IN     VOID                      *SpdmContext,
  IN     UINT32                    SessionId,
  IN     BOOLEAN                   UsePsk
  );

/**
  This function frees a session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return freed session info assicated with this session ID.
**/
VOID *
EFIAPI
SpdmFreeSessionId (
  IN     VOID                      *SpdmContext,
  IN     UINT32                    SessionId
  );

/*
  This function calculates current TH data with Message A and Message K.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The SPDM session ID.
  @param  CertChainData                Certitiface chain data without SPDM_CERT_CHAIN header.
  @param  CertChainDataSize            Size in bytes of the certitiface chain data.
  @param  THDataBufferSize             Size in bytes of the THDataBuffer
  @param  THDataBuffer                 The buffer to store the THDataBuffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
BOOLEAN
EFIAPI
SpdmCalculateTHForExchange (
  IN     VOID                      *SpdmContext,
  IN     VOID                      *SpdmSessionInfo,
  IN     UINT8                     *CertChainData, OPTIONAL
  IN     UINTN                     CertChainDataSize, OPTIONAL
  IN OUT UINTN                     *THDataBufferSize,
     OUT VOID                      *THDataBuffer
  );

/*
  This function calculates current TH data with Message A, Message K and Message F.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The SPDM session ID.
  @param  CertChainData                Certitiface chain data without SPDM_CERT_CHAIN header.
  @param  CertChainDataSize            Size in bytes of the certitiface chain data.
  @param  MutCertChainData             Certitiface chain data without SPDM_CERT_CHAIN header in mutual authentication.
  @param  MutCertChainDataSize         Size in bytes of the certitiface chain data in mutual authentication.
  @param  THDataBufferSize             Size in bytes of the THDataBuffer
  @param  THDataBuffer                 The buffer to store the THDataBuffer

  @retval RETURN_SUCCESS  current TH data is calculated.
*/
BOOLEAN
EFIAPI
SpdmCalculateTHForFinish (
  IN     VOID                      *SpdmContext,
  IN     VOID                      *SpdmSessionInfo,
  IN     UINT8                     *CertChainData, OPTIONAL
  IN     UINTN                     CertChainDataSize, OPTIONAL
  IN     UINT8                     *MutCertChainData, OPTIONAL
  IN     UINTN                     MutCertChainDataSize, OPTIONAL
  IN OUT UINTN                     *THDataBufferSize,
     OUT VOID                      *THDataBuffer
  );

/*
  This function calculates TH1 hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.
  @param  TH1HashData                  TH1 hash

  @retval RETURN_SUCCESS  TH1 hash is calculated.
*/
RETURN_STATUS
EFIAPI
SpdmCalculateTH1Hash (
  IN VOID                         *SpdmContext,
  IN VOID                         *SpdmSessionInfo,
  IN BOOLEAN                      IsRequester,
  OUT UINT8                       *TH1HashData
  );

/*
  This function calculates TH2 hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.
  @param  TH1HashData                  TH2 hash

  @retval RETURN_SUCCESS  TH2 hash is calculated.
*/
RETURN_STATUS
EFIAPI
SpdmCalculateTH2Hash (
  IN VOID                         *SpdmContext,
  IN VOID                         *SpdmSessionInfo,
  IN BOOLEAN                      IsRequester,
  OUT UINT8                       *TH2HashData
  );

/**
  This function returns peer certificate chain buffer including SPDM_CERT_CHAIN header.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertChainBuffer              Certitiface chain buffer including SPDM_CERT_CHAIN header.
  @param  CertChainBufferSize          Size in bytes of the certitiface chain buffer.

  @retval TRUE  Peer certificate chain buffer including SPDM_CERT_CHAIN header is returned.
  @retval FALSE Peer certificate chain buffer including SPDM_CERT_CHAIN header is not found.
**/
BOOLEAN
EFIAPI
SpdmGetPeerCertChainBuffer (
  IN     VOID                     *SpdmContext,
     OUT VOID                     **CertChainBuffer,
     OUT UINTN                    *CertChainBufferSize
  );

/**
  This function returns peer certificate chain data without SPDM_CERT_CHAIN header.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertChainData                Certitiface chain data without SPDM_CERT_CHAIN header.
  @param  CertChainDataSize            Size in bytes of the certitiface chain data.

  @retval TRUE  Peer certificate chain data without SPDM_CERT_CHAIN header is returned.
  @retval FALSE Peer certificate chain data without SPDM_CERT_CHAIN header is not found.
**/
BOOLEAN
EFIAPI
SpdmGetPeerCertChainData (
  IN     VOID                     *SpdmContext,
     OUT VOID                     **CertChainData,
     OUT UINTN                    *CertChainDataSize
  );

/**
  This function returns local used certificate chain buffer including SPDM_CERT_CHAIN header.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertChainBuffer              Certitiface chain buffer including SPDM_CERT_CHAIN header.
  @param  CertChainBufferSize          Size in bytes of the certitiface chain buffer.

  @retval TRUE  Local used certificate chain buffer including SPDM_CERT_CHAIN header is returned.
  @retval FALSE Local used certificate chain buffer including SPDM_CERT_CHAIN header is not found.
**/
BOOLEAN
EFIAPI
SpdmGetLocalCertChainBuffer (
  IN     VOID                     *SpdmContext,
     OUT VOID                     **CertChainBuffer,
     OUT UINTN                    *CertChainBufferSize
  );

/**
  This function returns local used certificate chain data without SPDM_CERT_CHAIN header.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertChainData                Certitiface chain data without SPDM_CERT_CHAIN header.
  @param  CertChainDataSize            Size in bytes of the certitiface chain data.

  @retval TRUE  Local used certificate chain data without SPDM_CERT_CHAIN header is returned.
  @retval FALSE Local used certificate chain data without SPDM_CERT_CHAIN header is not found.
**/
BOOLEAN
EFIAPI
SpdmGetLocalCertChainData (
  IN     VOID                     *SpdmContext,
     OUT VOID                     **CertChainData,
     OUT UINTN                    *CertChainDataSize
  );

/**
  Reads a 24-bit value from memory that may be unaligned.

  @param  Buffer  The pointer to a 24-bit value that may be unaligned.

  @return The 24-bit value read from Buffer.
**/
UINT32
EFIAPI
SpdmReadUint24 (
  IN UINT8  *Buffer
  );

/**
  Writes a 24-bit value to memory that may be unaligned.

  @param  Buffer  The pointer to a 24-bit value that may be unaligned.
  @param  Value   24-bit value to write to Buffer.

  @return The 24-bit value to write to Buffer.
**/
UINT32
EFIAPI
SpdmWriteUint24 (
  IN UINT8  *Buffer,
  IN UINT32 Value
  );

#endif