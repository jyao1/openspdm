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
  // Pre-shared Key Hint
  // If PSK is present, then PSK_EXCHANGE is used.
  // Otherwise, the KEY_EXCHANGE is used.
  //
  SpdmDataPskHint,
  //
  // Session Type
  //
  SpdmDataSessionType,
  //
  // Session State
  //
  SpdmDataSessionState,
  //
  // Export Master Secret
  //
  SpdmDataExportMasterSecret,
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
  // Sequence Number
  //
  SpdmDataRequestHandshakeSequenceNumber,
  SpdmDataResponseHandshakeSequenceNumber,
  SpdmDataRequestDataSequenceNumber,
  SpdmDataResponseDataSequenceNumber,
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
  // GET-only for debug purpose.
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
  //   SlotNum + MeasurementHashType for SpdmDataMutAuthRequested
  UINT8                AdditionalData[4];
} SPDM_DATA_PARAMETER;

typedef enum {
  SpdmSessionTypeNone,
  SpdmSessionTypeMacOnly,
  SpdmSessionTypeEncMac,
  SpdmSessionTypeMax,
} SPDM_SESSION_TYPE;

typedef enum {
  //
  // Before send KEY_EXCHANGE/PSK_EXCHANGE
  // or after END_SESSION
  //
  SpdmStateNotStarted,
  //
  // After send KEY_EXHCNAGE, before send FINISH
  //
  SpdmStateHandshaking,
  //
  // After send FINISH, before END_SESSION
  //
  SpdmStateEstablished,
  //
  // MAX
  //
  SpdmStateMax,
} SPDM_SESSION_STATE;

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
  Sign an SPDM message data.

  @param  IsResponder                  Indicates if it is a responder message.
  @param  AsymAlgo                     Indicates the signing algorithm.
                                       For responder, it must align with BaseAsymAlgo (SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_*)
                                       For requester, it must align with ReqBaseAsymAlgo (SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_*)
  @param  MessageHash                  A pointer to a message hash to be signed.
  @param  HashSize                     The size in bytes of the message hash to be signed.
  @param  Signature                    A pointer to a destination buffer to store the signature.
  @param  SigSize                      On input, indicates the size in bytes of the destination buffer to store the signature.
                                       On output, indicates the size in bytes of the signature in the buffer.

  @retval TRUE  signing success.
  @retval FALSE signing fail.
**/
typedef
BOOLEAN
(EFIAPI *SPDM_DATA_SIGN_FUNC) (
  IN      BOOLEAN      IsResponder,
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
     OUT  UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

/**
  Register SPDM data signing function.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SpdmDataSignFunc             The fuction to sign the SPDM data.
**/
VOID
EFIAPI
SpdmRegisterDataSignFunc (
  IN     VOID                      *SpdmContext,
  IN     SPDM_DATA_SIGN_FUNC       SpdmDataSignFunc
  );

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  HashAlgo                     Indicates the hash algorithm.
  @param  PskHint                      Pointer to the user-supplied PSK Hint.
  @param  PskHintSize                  PSK Hint size in bytes.
  @param  Info                         Pointer to the application specific info.
  @param  InfoSize                     Info size in bytes.
  @param  Out                          Pointer to buffer to receive hkdf value.
  @param  OutSize                      Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
typedef
BOOLEAN
(EFIAPI *SPDM_PSK_HKDF_EXPAND_FUNC) (
  IN      UINT32       HashAlgo,
  IN      CONST UINT8  *PskHint, OPTIONAL
  IN      UINTN        PskHintSize, OPTIONAL
  IN      CONST UINT8  *Info,
  IN      UINTN        InfoSize,
     OUT  UINT8        *Out,
  IN      UINTN        OutSize
  );

/**
  Register SPDM PSK HKDF_EXPAND function.

  @param  SpdmContext                             A pointer to the SPDM context.
  @param  SpdmPskHandshakeSecretHkdfExpandFunc    The fuction to HKDF_EXPAND key with PSK derived HandshakeSecret.
  @param  SpdmPskMasterSecretHkdfExpandFunc       The fuction to HKDF_EXPAND key with PSK derived MasterSecret.
**/
VOID
EFIAPI
SpdmRegisterPskHkdfExpandFunc (
  IN     VOID                      *SpdmContext,
  IN     SPDM_PSK_HKDF_EXPAND_FUNC SpdmPskHandshakeSecretHkdfExpandFunc,
  IN     SPDM_PSK_HKDF_EXPAND_FUNC SpdmPskMasterSecretHkdfExpandFunc
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

#endif