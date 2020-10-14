/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_COMMON_LIB_INTERNAL_H__
#define __SPDM_COMMON_LIB_INTERNAL_H__

#include <Library/SpdmCommonLib.h>


typedef struct {
  UINT8                CTExponent;
  UINT32               Flags;
} SPDM_DEVICE_CAPABILITY;

typedef struct {
  UINT32               MeasurementHashAlgo;
  UINT32               BaseAsymAlgo;
  UINT32               BaseHashAlgo;
  UINT16               DHENamedGroup;
  UINT16               AEADCipherSuite;
  UINT16               ReqBaseAsymAlg;
  UINT16               KeySchedule;
} SPDM_DEVICE_ALGORITHM;

typedef struct {
  //
  // Local device info
  //
  UINT16                          SpdmVersion;
  SPDM_DEVICE_CAPABILITY          Capability;
  SPDM_DEVICE_ALGORITHM           Algorithm;
  //
  // My Certificate
  //
  VOID                            *CertificateChain[MAX_SPDM_SLOT_COUNT];
  UINTN                           CertificateChainSize[MAX_SPDM_SLOT_COUNT];
  UINT8                           SlotCount;
  // My provisioned certificate (for SlotNum - 0xFF, default 0)
  UINT8                           ProvisionedSlotNum;
  //
  // My Private Certificate
  //
  SPDM_DATA_SIGN_FUNC             SpdmDataSignFunc;
  //
  // Peer Root Certificate Hash
  //
  VOID                            *PeerRootCertHashProvision;
  UINTN                           PeerRootCertHashProvisionSize;
  //
  // Peer CertificateChain
  //
  VOID                            *PeerCertChainProvision;
  UINTN                           PeerCertChainProvisionSize;
  //
  // measurement collected in the responder
  // SPDM_MEASUREMENT_BLOCK + Hash
  //
  VOID                            *DeviceMeasurement;
  UINT8                           DeviceMeasurementCount;
  //
  // PSK provision locally
  //
  UINTN                           PskSize;
  UINT8                           *Psk;
  UINTN                           PskHintSize;
  UINT8                           *PskHint;
  //
  // OpaqueData provision locally
  //
  UINTN                           OpaqueChallengeAuthRspSize;
  UINT8                           *OpaqueChallengeAuthRsp;
  UINTN                           OpaqueMeasurementRspSize;
  UINT8                           *OpaqueMeasurementRsp;
  //
  // Responder policy
  //
  UINT8                           MutAuthRequested;
} SPDM_LOCAL_CONTEXT;

typedef struct {
  //
  // Peer device info (negotiated)
  //
  UINT8                           Version[MAX_SPDM_VERSION_COUNT];
  SPDM_DEVICE_CAPABILITY          Capability;
  SPDM_DEVICE_ALGORITHM           Algorithm;
  //
  // Peer CertificateChain
  //
  UINT8                           PeerCertChainBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                           PeerCertChainBufferSize;
  //
  // Local Used CertificateChain (for responder, or requester in mut auth)
  //
  UINT8                           *LocalUsedCertChainBuffer;
  UINTN                           LocalUsedCertChainBufferSize;
} SPDM_CONNECTION_INFO;


typedef struct {
  UINTN   MaxBufferSize;
  UINTN   BufferSize;
//UINT8   Buffer[MaxBufferSize];
} MANAGED_BUFFER;

typedef struct {
  UINTN   MaxBufferSize;
  UINTN   BufferSize;
  UINT8   Buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
} LARGE_MANAGED_BUFFER;

typedef struct {
  UINTN   MaxBufferSize;
  UINTN   BufferSize;
  UINT8   Buffer[MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE];
} SMALL_MANAGED_BUFFER;

typedef struct {
  //
  // Signature = Sign(SK, Hash(M1))
  // Verify(PK, Hash(M2), Signature)
  //
  // M1/M2 = Concatenate (A, B, C)
  // A = Concatenate (GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
  // B = Concatenate (GET_DIGEST, DIGEST, GET_CERTFICATE, CERTIFICATE)
  // C = Concatenate (CHALLENGE, CHALLENGE_AUTH\Signature)
  //
  // Mut M1/M2 = Concatenate (MutB, MutC)
  // MutB = Concatenate (GET_DIGEST, DIGEST, GET_CERTFICATE, CERTIFICATE)
  // MutC = Concatenate (CHALLENGE, CHALLENGE_AUTH\Signature)
  //
  SMALL_MANAGED_BUFFER            MessageA;
  LARGE_MANAGED_BUFFER            MessageB;
  SMALL_MANAGED_BUFFER            MessageC;
  LARGE_MANAGED_BUFFER            MessageMutB;
  SMALL_MANAGED_BUFFER            MessageMutC;
  LARGE_MANAGED_BUFFER            M1M2;
  //
  // Signature = Sign(SK, Hash(L1))
  // Verify(PK, Hash(L2), Signature)
  //
  // L1/L2 = Concatenate (GET_MEASUREMENT, MEASUREMENT\Signature)
  //
  LARGE_MANAGED_BUFFER            L1L2;
} SPDM_TRANSCRIPT;

typedef struct {
  //
  // TH for KEY_EXCHANGE response signature: Concatenate (A, Ct, K)
  // Ct = certificate chain
  // K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response\Signature+VerifyData)
  //
  // TH for KEY_EXCHANGE response HMAC: Concatenate (A, Ct, K)
  // Ct = certificate chain
  // K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response\VerifyData)
  //
  // TH for FINISH request signature: Concatenate (A, Ct, K, CM, F)
  // Ct = certificate chain
  // K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)
  // CM = mutual certificate chain *
  // F  = Concatenate (FINISH request\Signature+VerifyData)
  //
  // TH for FINISH response HMAC: Concatenate (A, Ct, K, CM, F)
  // Ct = certificate chain
  // K = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)
  // CM = mutual certificate chain *
  // F = Concatenate (FINISH request\VerifyData)
  //
  // TH1: Concatenate (A, Ct, K)
  // Ct = certificate chain
  // K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)
  //
  // TH2: Concatenate (A, Ct, K, CM, F)
  // Ct = certificate chain
  // K  = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)
  // CM = mutual certificate chain *
  // F  = Concatenate (FINISH request, FINISH response)
  //
  LARGE_MANAGED_BUFFER            MessageK;
  LARGE_MANAGED_BUFFER            MessageF;
  //
  // TH for PSK_EXCHANGE response HMAC: Concatenate (A, K)
  // K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response\VerifyData)
  //
  // TH for PSK_FINISH response HMAC: Concatenate (A, K, PF)
  // K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response)
  // F  = Concatenate (PSK_FINISH request\VerifyData)
  //
  // TH1_PSK1: Concatenate (A, K)
  // K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response\VerifyData)
  //
  // TH1_PSK2: Concatenate (A, K, F)
  // K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response)
  // F  = Concatenate (PSK_FINISH request\VerifyData)
  //
  // TH2_PSK: Concatenate (A, K, F)
  // K  = Concatenate (PSK_EXCHANGE request, PSK_EXCHANGE response)
  // F  = Concatenate (PSK_FINISH request, PSK_FINISH response)
  //
} SPDM_SESSION_TRANSCRIPT;

#define INVALID_SESSION_ID  0

typedef struct {
  UINT8                DheSecret[MAX_DHE_KEY_SIZE];
  UINT8                HandshakeSecret[MAX_HASH_SIZE];
  UINT8                RequestHandshakeSecret[MAX_HASH_SIZE];
  UINT8                ResponseHandshakeSecret[MAX_HASH_SIZE];
  UINT8                MasterSecret[MAX_HASH_SIZE];
  UINT8                ExportMasterSecret[MAX_HASH_SIZE];
  UINT8                RequestFinishedKey[MAX_HASH_SIZE];
  UINT8                ResponseFinishedKey[MAX_HASH_SIZE];
  UINT8                RequestHandshakeEncryptionKey[MAX_AEAD_KEY_SIZE];
  UINT8                RequestHandshakeSalt[MAX_AEAD_IV_SIZE];
  UINT64               RequestHandshakeSequenceNumber;
  UINT8                ResponseHandshakeEncryptionKey[MAX_AEAD_KEY_SIZE];
  UINT8                ResponseHandshakeSalt[MAX_AEAD_IV_SIZE];
  UINT64               ResponseHandshakeSequenceNumber;
} SPDM_SESSION_INFO_HANDSHAKE_SECRET;

typedef struct {
  UINT8                RequestDataSecret[MAX_HASH_SIZE];
  UINT8                ResponseDataSecret[MAX_HASH_SIZE];
  UINT8                RequestDataEncryptionKey[MAX_AEAD_KEY_SIZE];
  UINT8                RequestDataSalt[MAX_AEAD_IV_SIZE];
  UINT64               RequestDataSequenceNumber;
  UINT8                ResponseDataEncryptionKey[MAX_AEAD_KEY_SIZE];
  UINT8                ResponseDataSalt[MAX_AEAD_IV_SIZE];
  UINT64               ResponseDataSequenceNumber;
} SPDM_SESSION_INFO_APPLICATION_SECRET;

typedef struct {
  UINT32                               SessionId;
  BOOLEAN                              UsePsk;
  UINT8                                MutAuthRequested;
  SPDM_SESSION_STATE                   SessionState;
  UINTN                                DheKeySize;
  UINTN                                HashSize;
  UINTN                                AeadKeySize;
  UINTN                                AeadIvSize;
  SPDM_SESSION_INFO_HANDSHAKE_SECRET   HandshakeSecret;
  SPDM_SESSION_INFO_APPLICATION_SECRET ApplicationSecret;
  SPDM_SESSION_INFO_APPLICATION_SECRET ApplicationSecretBackup;
  SPDM_SESSION_TRANSCRIPT              SessionTranscript;
} SPDM_SESSION_INFO;

typedef struct {
  UINT32                               ErrorState;
  UINT32                               EncapState;
  UINT8                                SlotNum;
  UINT8                                MeasurementHashType;
  LARGE_MANAGED_BUFFER                 CertificateChainBuffer;
} SPDM_ENCAP_CONTEXT;

typedef enum {
  SpdmResponseStateNormal,
  SpdmResponseStateBusy,
  SpdmResponseStateNotReady,
  SpdmResponseStateNeedResync,
  SpdmResponseStateMax,
} SPDM_RESPONSE_STATE;

#define SPDM_DEVICE_CONTEXT_VERSION 0x1

///
/// SPDM request command receive Flags (responder only)
///
#define SPDM_GET_VERSION_RECEIVE_FLAG                   BIT0 // responder only
#define SPDM_GET_CAPABILITIES_RECEIVE_FLAG              BIT1
#define SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG          BIT2
#define SPDM_GET_DIGESTS_RECEIVE_FLAG                   BIT3
#define SPDM_GET_CERTIFICATE_RECEIVE_FLAG               BIT4
#define SPDM_CHALLENGE_RECEIVE_FLAG                     BIT5
#define SPDM_GET_MEASUREMENTS_RECEIVE_FLAG              BIT6

typedef struct {
  UINT32                          Version;
  //
  // IO information
  //
  SPDM_DEVICE_SEND_MESSAGE_FUNC     SendMessage;
  SPDM_DEVICE_RECEIVE_MESSAGE_FUNC  ReceiveMessage;
  //
  // Transport Layer infomration
  //
  SPDM_TRANSPORT_ENCODE_MESSAGE_FUNC  TransportEncodeMessage;
  SPDM_TRANSPORT_DECODE_MESSAGE_FUNC  TransportDecodeMessage;

  //
  // Command Status
  //
  UINT32                          ErrorState;
  //
  // Cached plain text command
  // If the command is cipher text, decrypt then cache it.
  //
  UINT8                           LastSpdmRequest[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                           LastSpdmRequestSize;
  //
  // Cache SessionId in this SpdmMessage, only valid for secured message.
  //
  UINT32                          LastSpdmRequestSessionId;
  BOOLEAN                         LastSpdmRequestSessionIdValid;

  //
  // Register GetResponse function (responder only)
  //
  UINTN                           GetResponseFunc;
  //
  // Register GetEncapResponse function (requester only)
  //
  UINTN                           GetEncapResponseFunc;
  SPDM_ENCAP_CONTEXT              EncapContext;

  SPDM_LOCAL_CONTEXT              LocalContext;

  SPDM_CONNECTION_INFO            ConnectionInfo;
  SPDM_TRANSCRIPT                 Transcript;

  SPDM_SESSION_INFO               SessionInfo[MAX_SPDM_SESSION_COUNT];
  //
  // Cache lastest session ID for HANDSHAKE_IN_THE_CLEAR
  //
  UINT32                          LatestSessionId;
  //
  // Register Spdm request command receive Status (responder only)
  //
  UINT64                          SpdmCmdReceiveState;
  //
  // Register for Responder state, be initial to Normal (responder only)
  //
  SPDM_RESPONSE_STATE             ResponseState;
  //
  // Cached data for SPDM_ERROR_CODE_RESPONSE_NOT_READY/SPDM_RESPOND_IF_READY
  //
  SPDM_ERROR_DATA_RESPONSE_NOT_READY  ErrorData;
  UINT8                           CachSpdmRequest[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                           CachSpdmRequestSize;
  UINT8                           CurrentToken;
  //
  // Register for the retry times when receive "BUSY" Error response (requester only)
  //
  UINT8                           RetryTimes;
} SPDM_DEVICE_CONTEXT;

/**

  This function dump raw data.

  @param  Data  raw data
  @param  Size  raw data size

**/
VOID
InternalDumpData (
  IN UINT8  *Data,
  IN UINTN  Size
  );

/**

  This function dump raw data with colume format.

  @param  Data  raw data
  @param  Size  raw data size

**/
VOID
InternalDumpHex (
  IN UINT8  *Data,
  IN UINTN  Size
  );

/**
  This function returns the SPDM hash size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM hash size
**/
UINT32
GetSpdmHashSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM asym size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM hash size
**/
UINT32
GetSpdmAsymSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM Request asym size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM hash size
**/
UINT32
GetSpdmReqAsymSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM measurement hash size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM measurement hash size
**/
UINT32
GetSpdmMeasurementHashSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

BOOLEAN
SpdmHashAll (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  );

BOOLEAN
SpdmMeasurementHashAll (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  );

BOOLEAN
SpdmHmacAll (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  IN   CONST UINT8                  *Key,
  IN   UINTN                        KeySize,
  OUT  UINT8                        *HmacValue
  );

BOOLEAN
SpdmHkdfExpand (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8                  *Prk,
  IN   UINTN                        PrkSize,
  IN   CONST UINT8                  *Info,
  IN   UINTN                        InfoSize,
  OUT  UINT8                        *Out,
  IN   UINTN                        OutSize
  );

/**
  This function returns the SPDM DHENamedGroup size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM DHENamedGroup size
**/
UINT32
GetSpdmDheKeySize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM AEAD key size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM AEAD key size
**/
UINT32
GetSpdmAeadKeySize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM AEAD iv size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM AEAD iv size
**/
UINT32
GetSpdmAeadIvSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM AEAD tag size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM AEAD iv size
**/
UINT32
GetSpdmAeadTagSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM AEAD block size.

  @param[in]  SpdmContext             The SPDM context for the device.

  @return TCG SPDM AEAD iv size
**/
UINT32
GetSpdmAeadBlockSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

BOOLEAN
SpdmAeadEncryption (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8*                 Key,
  IN   UINTN                        KeySize,
  IN   CONST UINT8*                 Iv,
  IN   UINTN                        IvSize,
  IN   CONST UINT8*                 AData,
  IN   UINTN                        ADataSize,
  IN   CONST UINT8*                 DataIn,
  IN   UINTN                        DataInSize,
  OUT  UINT8*                       TagOut,
  IN   UINTN                        TagSize,
  OUT  UINT8*                       DataOut,
  OUT  UINTN*                       DataOutSize
  );

BOOLEAN
SpdmAeadDecryption (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8*                 Key,
  IN   UINTN                        KeySize,
  IN   CONST UINT8*                 Iv,
  IN   UINTN                        IvSize,
  IN   CONST UINT8*                 AData,
  IN   UINTN                        ADataSize,
  IN   CONST UINT8*                 DataIn,
  IN   UINTN                        DataInSize,
  IN   CONST UINT8*                 Tag,
  IN   UINTN                        TagSize,
  OUT  UINT8*                       DataOut,
  OUT  UINTN*                       DataOutSize
  );

BOOLEAN
SpdmAsymGetPublicKeyFromX509 (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8                  *Cert,
  IN   UINTN                        CertSize,
  OUT  VOID                         **Context
  );

VOID
SpdmAsymFree (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context
  );

BOOLEAN
SpdmAsymVerify (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context,
  IN   CONST UINT8                  *MessageHash,
  IN   UINTN                        HashSize,
  IN   CONST UINT8                  *Signature,
  IN   UINTN                        SigSize
  );

BOOLEAN
SpdmReqAsymGetPublicKeyFromX509 (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8                  *Cert,
  IN   UINTN                        CertSize,
  OUT  VOID                         **Context
  );

VOID
SpdmReqAsymFree (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context
  );

BOOLEAN
SpdmReqAsymVerify (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context,
  IN   CONST UINT8                  *MessageHash,
  IN   UINTN                        HashSize,
  IN   CONST UINT8                  *Signature,
  IN   UINTN                        SigSize
  );

VOID *
SpdmDheNew (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext
  );

VOID
SpdmDheFree (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context
  );

BOOLEAN
SpdmDheGenerateKey (
  IN      SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN OUT  VOID                         *Context,
  OUT     UINT8                        *PublicKey,
  IN OUT  UINTN                        *PublicKeySize
  );

BOOLEAN
SpdmDheComputeKey (
  IN      SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN OUT  VOID                         *Context,
  IN      CONST UINT8                  *PeerPublic,
  IN      UINTN                        PeerPublicSize,
  OUT     UINT8                        *Key,
  IN OUT  UINTN                        *KeySize
  );

VOID
SpdmGetRandomNumber (
  IN  UINTN                     Size,
  OUT UINT8                     *Rand
  );

/**
  Append a new data buffer to the managed buffer.
**/
RETURN_STATUS
AppendManagedBuffer (
  IN OUT VOID            *ManagedBuffer,
  IN VOID                *Buffer,
  IN UINTN               BufferSize
  );

/**
  Shrink the size of the managed buffer.
**/
RETURN_STATUS
ShrinkManagedBuffer (
  IN OUT VOID            *MBuffer,
  IN UINTN               BufferSize
  );

/**
  Reset the managed buffer.
  The BufferSize is reset to 0.
  The MaxBufferSize is unchanged.
  The Buffer is not freed.
**/
VOID
ResetManagedBuffer (
  IN OUT VOID            *ManagedBuffer
  );

/**
  Return the size of buffer
**/
UINTN
GetManagedBufferSize (
  IN VOID                *ManagedBuffer
  );

/**
  Return the buffer
**/
VOID *
GetManagedBuffer (
  IN VOID                *ManagedBuffer
  );

/**
  Init the buffer
**/
VOID
InitManagedBuffer (
  IN OUT VOID            *MBuffer,
  IN UINTN               MaxBufferSize
  );

/**
  This function generate SPDM HandshakeKey.

  @param[in]  SpdmContext            The SPDM context for the device.
**/
RETURN_STATUS
SpdmGenerateSessionHandshakeKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester
  );

/**
  This function generate SPDM DataKey.

  @param[in]  SpdmContext            The SPDM context for the device.
**/
RETURN_STATUS
SpdmGenerateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester
  );

typedef enum {
  SpdmKeyUpdateActionRequester = 0x1,
  SpdmKeyUpdateActionResponder = 0x2,
  SpdmKeyUpdateActionAll       = 0x3,
} SPDM_KEY_UPDATE_ACTION;

/**
  This function update SPDM DataKey.

  @param[in]  SpdmContext            The SPDM context for the device.
**/
RETURN_STATUS
SpdmCreateUpdateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN SPDM_KEY_UPDATE_ACTION       Action
  );

/**
  This function activate the update of SPDM DataKey.

  @param[in]  SpdmContext            The SPDM context for the device.
**/
RETURN_STATUS
SpdmFinalizeUpdateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN SPDM_KEY_UPDATE_ACTION       Action,
  IN BOOLEAN                      UseNewKey
  );

SPDM_SESSION_INFO *
SpdmGetSessionInfoViaSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT32                    SessionId
  );

SPDM_SESSION_INFO *
SpdmAssignSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT32                    SessionId
  );

SPDM_SESSION_INFO *
SpdmFreeSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT32                    SessionId
  );

BOOLEAN
SpdmIsVersionSupported (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT8                     Version
  );

/**
  Retrieve the SubjectAltName from SubjectAltName Bytes
  @param[in]      Buffer           Pointer to subjectAltName oct bytes.
  @param[in]      Len              Size of Buffer in bytes.
  @param[out]     NameBuffer       Buffer to contain the retrieved certificate
                                   SubjectAltName. At most NameBufferSize bytes will be
                                   written. Maybe NULL in order to determine the size
                                   buffer needed.
  @param[in,out]  NameBufferSize   The size in bytes of the Name buffer on input,
                                   and the size of buffer returned Name on output.
                                   If NameBuffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.
  @param[out]     Oid              OID of otherName
  @param[in,out]  OidSize          the buffersize for required OID

  @retval RETURN_SUCCESS           The certificate Organization Name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If NameBufferSize is NULL.
                                   If NameBuffer is not NULL and *CommonNameSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the NameBuffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   NameBufferSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
RETURN_STATUS
EFIAPI
SpdmGetDMTFSubjectAltNameFromBytes (
  IN      CONST UINT8   *Buffer,
  IN      INTN          Len,
  OUT     CHAR8         *NameBuffer,  OPTIONAL
  IN OUT  UINTN         *NameBufferSize,
  OUT     UINT8         *Oid,         OPTIONAL
  IN OUT  UINTN         *OidSize
  );

/**
  Retrieve the SubjectAltName from one X.509 certificate.
  @param[in]      Cert             Pointer to the DER-encoded X509 certificate.
  @param[in]      CertSize         Size of the X509 certificate in bytes.
  @param[out]     NameBuffer       Buffer to contain the retrieved certificate
                                   SubjectAltName. At most NameBufferSize bytes will be
                                   written. Maybe NULL in order to determine the size
                                   buffer needed.
  @param[in,out]  NameBufferSize   The size in bytes of the Name buffer on input,
                                   and the size of buffer returned Name on output.
                                   If NameBuffer is NULL then the amount of space needed
                                   in buffer (including the final null) is returned.
  @param[out]     Oid              OID of otherName
  @param[in,out]  OidSize          the buffersize for required OID

  @retval RETURN_SUCCESS           The certificate Organization Name retrieved successfully.
  @retval RETURN_INVALID_PARAMETER If Cert is NULL.
                                   If NameBufferSize is NULL.
                                   If NameBuffer is not NULL and *CommonNameSize is 0.
                                   If Certificate is invalid.
  @retval RETURN_NOT_FOUND         If no SubjectAltName exists.
  @retval RETURN_BUFFER_TOO_SMALL  If the NameBuffer is NULL. The required buffer size
                                   (including the final null) is returned in the
                                   NameBufferSize parameter.
  @retval RETURN_UNSUPPORTED       The operation is not supported.
**/
RETURN_STATUS
SpdmGetDMTFSubjectAltName (
  IN      CONST UINT8   *Cert,
  IN      INTN          CertSize,
  OUT     CHAR8         *NameBuffer,  OPTIONAL
  IN OUT  UINTN         *NameBufferSize,
  OUT     UINT8         *Oid,         OPTIONAL
  IN OUT  UINTN         *OidSize
  );

/**
  Certificate Check for SPDM leaf cert.

  @param[in]  Cert            Pointer to the DER-encoded certificate data.
  @param[in]  CertSize        The size of certificate data in bytes.

  @retval  TRUE   Success.
  @retval  FALSE  Certificate is not valid
**/
BOOLEAN
SpdmX509CertificateCheck(
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize
  );

#endif
