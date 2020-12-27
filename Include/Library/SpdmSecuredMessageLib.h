/** @file
  SPDM Secured Message library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_SECURED_MESSAGE_LIB_H__
#define __SPDM_SECURED_MESSAGE_LIB_H__

#include "SpdmLibConfig.h"

#include <Base.h>
#include <IndustryStandard/Spdm.h>
#include <IndustryStandard/SpdmSecuredMessage.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/SpdmCryptLib.h>

#define MAX_DHE_KEY_SIZE    512
#define MAX_ASYM_KEY_SIZE   512
#define MAX_HASH_SIZE       64
#define MAX_AEAD_KEY_SIZE   32
#define MAX_AEAD_IV_SIZE    12

#define BIN_CONCAT_LABEL "spdm1.1"
#define BIN_STR_0_LABEL  "derived"
#define BIN_STR_1_LABEL  "req hs data"
#define BIN_STR_2_LABEL  "rsp hs data"
#define BIN_STR_3_LABEL  "req app data"
#define BIN_STR_4_LABEL  "rsp app data"
#define BIN_STR_5_LABEL  "key"
#define BIN_STR_6_LABEL  "iv"
#define BIN_STR_7_LABEL  "finished"
#define BIN_STR_8_LABEL  "exp master"
#define BIN_STR_9_LABEL  "traffic upd"

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
  SpdmSessionStateNotStarted,
  //
  // After send KEY_EXHCNAGE, before send FINISH
  //
  SpdmSessionStateHandshaking,
  //
  // After send FINISH, before END_SESSION
  //
  SpdmSessionStateEstablished,
  //
  // MAX
  //
  SpdmSessionStateMax,
} SPDM_SESSION_STATE;

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  HashAlgo                     Indicates the hash algorithm.
                                       It must align with BaseHashAlgo (SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_*)
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

UINTN
EFIAPI
SpdmSecuredMessageGetContextSize (
  VOID
  );

VOID
EFIAPI
SpdmSecuredMessageInitContext (
  IN     VOID                     *SpdmSecuredMessageContext
  );

VOID
SpdmSecuredMessageSetUsePsk (
  IN VOID                         *SpdmSecuredMessageContext,
  IN BOOLEAN                      UsePsk
  );

VOID
SpdmSecuredMessageSetSessionState (
  IN VOID                         *SpdmSecuredMessageContext,
  IN SPDM_SESSION_STATE           SessionState
  );

SPDM_SESSION_STATE
SpdmSecuredMessageGetSessionState (
  IN VOID                         *SpdmSecuredMessageContext
  );

VOID
SpdmSecuredMessageSetSessionType (
  IN VOID                         *SpdmSecuredMessageContext,
  IN SPDM_SESSION_TYPE            SessionType
  );

VOID
SpdmSecuredMessageSetAlgorithms (
  IN VOID                         *SpdmSecuredMessageContext,
  IN UINT32                       BaseHashAlgo,
  IN UINT16                       DHENamedGroup,
  IN UINT16                       AEADCipherSuite,
  IN UINT16                       KeySchedule
  );

VOID
SpdmSecuredMessageSetPskHint (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *PskHint,
  IN UINTN                        PskHintSize
  );

VOID
EFIAPI
SpdmSecuredMessageRegisterPskHkdfExpandFunc (
  IN VOID                      *SpdmSecuredMessageContext,
  IN SPDM_PSK_HKDF_EXPAND_FUNC SpdmPskHandshakeSecretHkdfExpandFunc,
  IN SPDM_PSK_HKDF_EXPAND_FUNC SpdmPskMasterSecretHkdfExpandFunc
  );

VOID
SpdmSecuredMessageSetDheSecret (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *DheSecret,
  IN UINTN                        DheSecretSize
  );

VOID
SpdmSecuredMessageSetRequestFinishedKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *RequestFinishedKey,
  IN UINTN                        HashSize
  );

VOID
SpdmSecuredMessageSetResponseFinishedKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *Key,
  IN UINTN                        KeySize
  );

BOOLEAN
SpdmHmacAllWithRequestFinishedKey (
  IN   VOID                         *SpdmSecuredMessageContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HmacValue
  );

BOOLEAN
SpdmHmacAllWithResponseFinishedKey (
  IN   VOID                         *SpdmSecuredMessageContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HmacValue
  );

RETURN_STATUS
SpdmBinConcat (
  IN CHAR8     *Label,
  IN UINTN     LabelSize,
  IN UINT8     *Context,
  IN UINT16    Length,
  IN UINTN     HashSize,
  OUT UINT8    *OutBin,
  IN OUT UINTN *OutBinSize
  );

/**
  This function generates SPDM HandshakeKey for a session.

  @param  SecuredMessageContext               A pointer to the SPDM session context.
  @param  TH1HashData                  TH1 hash

  @retval RETURN_SUCCESS  SPDM HandshakeKey for a session is generated.
**/
RETURN_STATUS
SpdmGenerateSessionHandshakeKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN UINT8                        *TH1HashData
  );

/**
  This function generates SPDM DataKey for a session.

  @param  SecuredMessageContext               A pointer to the SPDM session context.
  @param  TH2HashData                  TH2 hash

  @retval RETURN_SUCCESS  SPDM DataKey for a session is generated.
**/
RETURN_STATUS
SpdmGenerateSessionDataKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN UINT8                        *TH2HashData
  );

typedef enum {
  SpdmKeyUpdateActionRequester = 0x1,
  SpdmKeyUpdateActionResponder = 0x2,
  SpdmKeyUpdateActionAll       = 0x3,
} SPDM_KEY_UPDATE_ACTION;

/**
  This function creates the updates of SPDM DataKey for a session.

  @param  SecuredMessageContext               A pointer to the SPDM session context.
  @param  Action                       Indicate of the key update action.

  @retval RETURN_SUCCESS  SPDM DataKey update is created.
**/
RETURN_STATUS
SpdmCreateUpdateSessionDataKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN SPDM_KEY_UPDATE_ACTION       Action
  );

/**
  This function activates the update of SPDM DataKey for a session.

  @param  SecuredMessageContext               A pointer to the SPDM session context.
  @param  Action                       Indicate of the key update action.
  @param  UseNewKey                    Indicate if the new key should be used.

  @retval RETURN_SUCCESS  SPDM DataKey update is activated.
**/
RETURN_STATUS
SpdmActivateUpdateSessionDataKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN SPDM_KEY_UPDATE_ACTION       Action,
  IN BOOLEAN                      UseNewKey
  );

/**
  Get sequence number in an SPDM secure message.

  This value is transport layer specific.

  @param SequenceNumber        The current sequence number used to encode or decode message.
  @param SequenceNumberBuffer  A buffer to hold the sequence number output used in the secured message.
                               The size in byte of the output buffer shall be 8.

  @return Size in byte of the SequenceNumberBuffer.
          It shall be no greater than 8.
          0 means no sequence number is required.
**/
typedef
UINT8
(EFIAPI *SPDM_SECURED_MESSAGE_GET_SEQUENCE_NUMBER) (
  IN     UINT64     SequenceNumber,
  IN OUT UINT8      *SequenceNumberBuffer
  );

/**
  Return max random number count in an SPDM secure message.

  This value is transport layer specific.

  @return Max random number count in an SPDM secured message.
          0 means no randum number is required.
**/
typedef
UINT32
(EFIAPI *SPDM_SECURED_MESSAGE_GET_MAX_RANDOM_NUMBER_COUNT) (
  VOID
  );

#define SPDM_SECURED_MESSAGE_CALLBACKS_VERSION 1

typedef struct {
  UINT32                                            Version;
  SPDM_SECURED_MESSAGE_GET_SEQUENCE_NUMBER          GetSequenceNumber;
  SPDM_SECURED_MESSAGE_GET_MAX_RANDOM_NUMBER_COUNT  GetMaxRandomNumberCount;
} SPDM_SECURED_MESSAGE_CALLBACKS;

/**
  Encode an application message to a secured message.

  @param  SecuredMessageContext               A pointer to the SPDM context.
  @param  SessionId                    The session ID of the SPDM session.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  AppMessageSize               Size in bytes of the application message data buffer.
  @param  AppMessage                   A pointer to a source buffer to store the application message.
  @param  SecuredMessageSize           Size in bytes of the secured message data buffer.
  @param  SecuredMessage               A pointer to a destination buffer to store the secured message.
  @param  SpdmSecuredMessageCallbacks  A pointer to a secured message callback functions structure.

  @retval RETURN_SUCCESS               The application message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
**/
RETURN_STATUS
EFIAPI
SpdmEncodeSecuredMessage (
  IN     VOID                           *SpdmSecuredMessageContext,
  IN     UINT32                         SessionId,
  IN     BOOLEAN                        IsRequester,
  IN     UINTN                          AppMessageSize,
  IN     VOID                           *AppMessage,
  IN OUT UINTN                          *SecuredMessageSize,
     OUT VOID                           *SecuredMessage,
  IN     SPDM_SECURED_MESSAGE_CALLBACKS *SpdmSecuredMessageCallbacks
  );

/**
  Decode an application message from a secured message.

  @param  SecuredMessageContext               A pointer to the SPDM context.
  @param  SessionId                    The session ID of the SPDM session.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  SecuredMessageSize           Size in bytes of the secured message data buffer.
  @param  SecuredMessage               A pointer to a source buffer to store the secured message.
  @param  AppMessageSize               Size in bytes of the application message data buffer.
  @param  AppMessage                   A pointer to a destination buffer to store the application message.
  @param  SpdmSecuredMessageCallbacks  A pointer to a secured message callback functions structure.

  @retval RETURN_SUCCESS               The application message is decoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
  @retval RETURN_UNSUPPORTED           The SecuredMessage is unsupported.
**/
RETURN_STATUS
EFIAPI
SpdmDecodeSecuredMessage (
  IN     VOID                           *SpdmSecuredMessageContext,
  IN     UINT32                         SessionId,
  IN     BOOLEAN                        IsRequester,
  IN     UINTN                          SecuredMessageSize,
  IN     VOID                           *SecuredMessage,
  IN OUT UINTN                          *AppMessageSize,
     OUT VOID                           *AppMessage,
  IN     SPDM_SECURED_MESSAGE_CALLBACKS *SpdmSecuredMessageCallbacks
  );

/**
  Return the size in bytes of opaque data supproted version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.

  @return the size in bytes of opaque data supproted version.
**/
UINTN
EFIAPI
SpdmGetOpaqueDataSupportedVersionDataSize (
  VOID
  );

/**
  Build opaque data supported version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.

  @param  DataOutSize                  Size in bytes of the DataOut.
                                       On input, it means the size in bytes of DataOut buffer.
                                       On output, it means the size in bytes of copied DataOut buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired DataOut buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  DataOut                      A pointer to the desination buffer to store the opaque data supported version.

  @retval RETURN_SUCCESS               The opaque data supported version is built successfully.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmBuildOpaqueDataSupportedVersionData (
  IN OUT UINTN                *DataOutSize,
     OUT VOID                 *DataOut
  );

/**
  Process opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response parsing in requester.

  @param  DataInSize                   Size in bytes of the DataIn.
  @param  DataIn                       A pointer to the buffer to store the opaque data version selection.

  @retval RETURN_SUCCESS               The opaque data version selection is processed successfully.
  @retval RETURN_UNSUPPORTED           The DataIn is NOT opaque data version selection.
**/
RETURN_STATUS
EFIAPI
SpdmProcessOpaqueDataVersionSelectionData (
  IN     UINTN                DataInSize,
  IN     VOID                 *DataIn
  );

/**
  Return the size in bytes of opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.

  @return the size in bytes of opaque data version selection.
**/
UINTN
EFIAPI
SpdmGetOpaqueDataVersionSelectionDataSize (
  VOID
  );

/**
  Build opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.

  @param  DataOutSize                  Size in bytes of the DataOut.
                                       On input, it means the size in bytes of DataOut buffer.
                                       On output, it means the size in bytes of copied DataOut buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired DataOut buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  DataOut                      A pointer to the desination buffer to store the opaque data version selection.

  @retval RETURN_SUCCESS               The opaque data version selection is built successfully.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmBuildOpaqueDataVersionSelectionData (
  IN OUT UINTN                *DataOutSize,
     OUT VOID                 *DataOut
  );

/**
  Process opaque data supported version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request parsing in responder.

  @param  DataInSize                   Size in bytes of the DataIn.
  @param  DataIn                       A pointer to the buffer to store the opaque data supported version.

  @retval RETURN_SUCCESS               The opaque data supported version is processed successfully.
  @retval RETURN_UNSUPPORTED           The DataIn is NOT opaque data supported version.
**/
RETURN_STATUS
EFIAPI
SpdmProcessOpaqueDataSupportedVersionData (
  IN     UINTN                DataInSize,
  IN     VOID                 *DataIn
  );

#endif