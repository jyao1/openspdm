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
#include <Library/SpdmDeviceSecretLib.h>

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

RETURN_STATUS
SpdmSecuredMessageImportDheSecret (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *DheSecret,
  IN UINTN                        DheSecretSize
  );

RETURN_STATUS
SpdmSecuredMessageExportMasterSecret (
  IN     VOID                         *SpdmSecuredMessageContext,
     OUT VOID                         *ExportMasterSecret,
  IN OUT UINTN                        *ExportMasterSecretSize
  );

#define SPDM_SECURE_SESSION_KEYS_STRUCT_VERSION  1

#pragma pack(1)
typedef struct {
  UINT32               Version;
  UINT32               AeadKeySize;
  UINT32               AeadIvSize;
//  UINT8                RequestDataEncryptionKey[AeadKeySize];
//  UINT8                RequestDataSalt[AeadIvSize];
//  UINT64               RequestDataSequenceNumber;
//  UINT8                ResponseDataEncryptionKey[AeadKeySize];
//  UINT8                ResponseDataSalt[AeadIvSize];
//  UINT64               ResponseDataSequenceNumber;
} SPDM_SECURE_SESSION_KEYS_STRUCT;
#pragma pack()

RETURN_STATUS
SpdmSecuredMessageExportSessionKeys (
  IN     VOID                         *SpdmSecuredMessageContext,
     OUT VOID                         *SessionKeys,
  IN OUT UINTN                        *SessionKeysSize
  );

RETURN_STATUS
SpdmSecuredMessageImportSessionKeys (
  IN     VOID                         *SpdmSecuredMessageContext,
  IN     VOID                         *SessionKeys,
  IN     UINTN                        SessionKeysSize
  );

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) Context for subsequent use,
  based upon negotiated DHE algorithm.
  
  @param  DHENamedGroup                SPDM DHENamedGroup

  @return  Pointer to the Diffie-Hellman Context that has been initialized.
**/
VOID *
SpdmSecuredMessageDheNew (
  IN   UINT16                       DHENamedGroup
  );

/**
  Release the specified DHE context,
  based upon negotiated DHE algorithm.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  DheContext                   Pointer to the DHE context to be released.
**/
VOID
SpdmSecuredMessageDheFree (
  IN   UINT16                       DHENamedGroup,
  IN   VOID                         *DheContext
  );

/**
  Generates DHE public key,
  based upon negotiated DHE algorithm.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter PublicKey and PublicKeySize. DH context is updated accordingly.
  If the PublicKey buffer is too small to hold the public key, FALSE is returned and
  PublicKeySize is set to the required buffer size to obtain the public key.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  DheContext                   Pointer to the DHE context.
  @param  PublicKey                    Pointer to the buffer to receive generated public key.
  @param  PublicKeySize                On input, the size of PublicKey buffer in bytes.
                                       On output, the size of data returned in PublicKey buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  PublicKeySize is not large enough.
**/
BOOLEAN
SpdmSecuredMessageDheGenerateKey (
  IN      UINT16                       DHENamedGroup,
  IN OUT  VOID                         *DheContext,
  OUT     UINT8                        *PublicKey,
  IN OUT  UINTN                        *PublicKeySize
  );

/**
  Computes exchanged common key,
  based upon negotiated DHE algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  DHENamedGroup                SPDM DHENamedGroup
  @param  DheContext                   Pointer to the DHE context.
  @param  PeerPublicKey                Pointer to the peer's public key.
  @param  PeerPublicKeySize            Size of peer's public key in bytes.
  @param  Key                          Pointer to the buffer to receive generated key.
  @param  KeySize                      On input, the size of Key buffer in bytes.
                                       On output, the size of data returned in Key buffer in bytes.

  @retval TRUE   DHE exchanged key generation succeeded.
  @retval FALSE  DHE exchanged key generation failed.
  @retval FALSE  KeySize is not large enough.
**/
BOOLEAN
SpdmSecuredMessageDheComputeKey (
  IN      UINT16                       DHENamedGroup,
  IN OUT  VOID                         *DheContext,
  IN      CONST UINT8                  *PeerPublic,
  IN      UINTN                        PeerPublicSize,
  IN OUT  VOID                         *SpdmSecuredMessageContext
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

#endif