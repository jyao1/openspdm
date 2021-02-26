/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_COMMON_LIB_INTERNAL_H__
#define __SPDM_COMMON_LIB_INTERNAL_H__

#include <Library/SpdmCommonLib.h>
#include <Library/SpdmSecuredMessageLib.h>

#define INVALID_SESSION_ID  0

typedef struct {
  UINT8                SpdmVersionCount;
  SPDM_VERSION_NUMBER  SpdmVersion[MAX_SPDM_VERSION_COUNT];
} SPDM_DEVICE_VERSION;

typedef struct {
  UINT8                CTExponent;
  UINT32               Flags;
} SPDM_DEVICE_CAPABILITY;

typedef struct {
  UINT8                MeasurementSpec;
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
  SPDM_DEVICE_VERSION             Version;
  SPDM_DEVICE_CAPABILITY          Capability;
  SPDM_DEVICE_ALGORITHM           Algorithm;
  SPDM_DEVICE_VERSION             SecuredMessageVersion;
  //
  // My Certificate
  //
  VOID                            *LocalCertChainProvision[MAX_SPDM_SLOT_COUNT];
  UINTN                           LocalCertChainProvisionSize[MAX_SPDM_SLOT_COUNT];
  UINT8                           SlotCount;
  // My provisioned certificate (for SlotNum - 0xFF, default 0)
  UINT8                           ProvisionedSlotNum;
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
  // PSK provision locally
  //
  UINTN                           PskHintSize;
  VOID                            *PskHint;
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
  BOOLEAN                         BasicMutAuthRequested;
  UINT8                           MutAuthRequested;
} SPDM_LOCAL_CONTEXT;

typedef struct {
  //
  // Connection State
  //
  SPDM_CONNECTION_STATE           ConnectionState;
  //
  // Peer device info (negotiated)
  //
  SPDM_DEVICE_VERSION             Version;
  SPDM_DEVICE_CAPABILITY          Capability;
  SPDM_DEVICE_ALGORITHM           Algorithm;
  SPDM_DEVICE_VERSION             SecuredMessageVersion;
  //
  // Peer CertificateChain
  //
  UINT8                           PeerUsedCertChainBuffer[MAX_SPDM_CERT_CHAIN_SIZE];
  UINTN                           PeerUsedCertChainBufferSize;
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
  //
  // Signature = Sign(SK, Hash(L1))
  // Verify(PK, Hash(L2), Signature)
  //
  // L1/L2 = Concatenate (M)
  // M = Concatenate (GET_MEASUREMENT, MEASUREMENT\Signature)
  //
  LARGE_MANAGED_BUFFER            MessageM;
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

typedef struct {
  UINT32                               SessionId;
  BOOLEAN                              UsePsk;
  UINT8                                MutAuthRequested;
  UINT8                                EndSessionAttributes;
  SPDM_SESSION_TRANSCRIPT              SessionTranscript;
  VOID                                 *SecuredMessageContext;
} SPDM_SESSION_INFO;

#define MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT 3
typedef struct {
  UINT32                               ErrorState;
  // Valid OpCode: GET_DIEGST/GET_CERTIFICATE/CHALLENGE/KEY_UPDATE
  // The last one is 0x00, as terminator.
  UINT8                                RequestOpCodeSequence[MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT + 1];
  UINT8                                RequestOpCodeCount;
  UINT8                                CurrentRequestOpCode;
  UINT8                                RequestId;
  UINT8                                ReqSlotNum;
  SPDM_MESSAGE_HEADER                  LastEncapRequestHeader;
  UINTN                                LastEncapRequestSize;
  LARGE_MANAGED_BUFFER                 CertificateChainBuffer;
} SPDM_ENCAP_CONTEXT;

#define SPDM_DEVICE_CONTEXT_VERSION 0x1

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
  // Cache the error in SpdmProcessRequest. It is handled in SpdmBuildResponse.
  //
  SPDM_ERROR_STRUCT               LastSpdmError;

  //
  // Register GetResponse function (responder only)
  //
  UINTN                           GetResponseFunc;
  //
  // Register GetEncapResponse function (requester only)
  //
  UINTN                           GetEncapResponseFunc;
  SPDM_ENCAP_CONTEXT              EncapContext;
  //
  // Register SpdmSessionStateCallback function (responder only)
  // Register can know the state after StartSession / EndSession.
  //
  UINTN                           SpdmSessionStateCallback[MAX_SPDM_SESSION_STATE_CALLBACK_NUM];
  //
  // Register SpdmConnectionStateCallback function (responder only)
  // Register can know the connection state such as negotiated.
  //
  UINTN                           SpdmConnectionStateCallback[MAX_SPDM_CONNECTION_STATE_CALLBACK_NUM];

  SPDM_LOCAL_CONTEXT              LocalContext;

  SPDM_CONNECTION_INFO            ConnectionInfo;
  SPDM_TRANSCRIPT                 Transcript;

  SPDM_SESSION_INFO               SessionInfo[MAX_SPDM_SESSION_COUNT];
  //
  // Cache lastest session ID for HANDSHAKE_IN_THE_CLEAR
  //
  UINT32                          LatestSessionId;
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
InternalDumpHexStr (
  IN UINT8  *Data,
  IN UINTN  Size
  );

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
  Append a new data buffer to the managed buffer.

  @param  ManagedBuffer                The managed buffer to be appended.
  @param  Buffer                       The address of the data buffer to be appended to the managed buffer.
  @param  BufferSize                   The size in bytes of the data buffer to be appended to the managed buffer.

  @retval RETURN_SUCCESS               The new data buffer is appended to the managed buffer.
  @retval RETURN_BUFFER_TOO_SMALL      The managed buffer is too small to be appended.
**/
RETURN_STATUS
AppendManagedBuffer (
  IN OUT VOID            *ManagedBuffer,
  IN VOID                *Buffer,
  IN UINTN               BufferSize
  );

/**
  Shrink the size of the managed buffer.

  @param  ManagedBuffer                The managed buffer to be shrinked.
  @param  BufferSize                   The size in bytes of the size of the buffer to be shrinked.

  @retval RETURN_SUCCESS               The managed buffer is shrinked.
  @retval RETURN_BUFFER_TOO_SMALL      The managed buffer is too small to be shrinked.
**/
RETURN_STATUS
ShrinkManagedBuffer (
  IN OUT VOID            *ManagedBuffer,
  IN UINTN               BufferSize
  );

/**
  Reset the managed buffer.
  The BufferSize is reset to 0.
  The MaxBufferSize is unchanged.
  The Buffer is not freed.

  @param  ManagedBuffer                The managed buffer to be shrinked.
**/
VOID
ResetManagedBuffer (
  IN OUT VOID            *ManagedBuffer
  );

/**
  Return the size of managed buffer.

  @param  ManagedBuffer                The managed buffer.

  @return the size of managed buffer.
**/
UINTN
GetManagedBufferSize (
  IN VOID                *ManagedBuffer
  );

/**
  Return the address of managed buffer.

  @param  ManagedBuffer                The managed buffer.

  @return the address of managed buffer.
**/
VOID *
GetManagedBuffer (
  IN VOID                *ManagedBuffer
  );

/**
  Init the managed buffer.

  @param  ManagedBuffer                The managed buffer.
  @param  MaxBufferSize                The maximum size in bytes of the managed buffer.
**/
VOID
InitManagedBuffer (
  IN OUT VOID            *ManagedBuffer,
  IN UINTN               MaxBufferSize
  );

/**
  This function initializes the session info.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
**/
VOID
SpdmSessionInfoInit (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     SPDM_SESSION_INFO       *SessionInfo,
  IN     UINT32                  SessionId,
  IN     BOOLEAN                 UsePsk
  );

/**
  This function allocates half of session ID for a requester.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return half of session ID for a requester.
**/
UINT16
SpdmAllocateReqSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext
  );

/**
  This function allocates half of session ID for a responder.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return half of session ID for a responder.
**/
UINT16
SpdmAllocateRspSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext
  );

/**
  This function returns if a given version is supported based upon the GET_VERSION/VERSION.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Version                      The SPDM Version.

  @retval TRUE  the version is supported.
  @retval FALSE the version is not supported.
**/
BOOLEAN
SpdmIsVersionSupported (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT8                     Version
  );

/**
  This function returns if a capablities flag is supported in current SPDM connection.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Is the function called from a requester.
  @param  RequesterCapabilitiesFlag    The requester capabilities flag to be checked
  @param  ResponderCapabilitiesFlag    The responder capabilities flag to be checked

  @retval TRUE  the capablities flag is supported.
  @retval FALSE the capablities flag is not supported.
**/
BOOLEAN
SpdmIsCapabilitiesFlagSupported (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     BOOLEAN                   IsRequester,
  IN     UINT32                    RequesterCapabilitiesFlag,
  IN     UINT32                    ResponderCapabilitiesFlag
  );

/*
  This function calculates M1M2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsMut                        Indicate if this is from mutual authentication.
  @param  M1M2BufferSize               Size in bytes of the M1M2
  @param  M1M2Buffer                   The buffer to store the M1M2

  @retval RETURN_SUCCESS  M1M2 is calculated.
*/
BOOLEAN
EFIAPI
SpdmCalculateM1M2 (
  IN     VOID                   *Context,
  IN     BOOLEAN                IsMut,
  IN OUT UINTN                  *M1M2BufferSize,
     OUT VOID                   *M1M2Buffer
  );

/*
  This function calculates L1L2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  L1L2BufferSize               Size in bytes of the L1L2
  @param  L1L2Buffer                   The buffer to store the L1L2

  @retval RETURN_SUCCESS  L1L2 is calculated.
*/
BOOLEAN
EFIAPI
SpdmCalculateL1L2 (
  IN     VOID                   *Context,
  IN OUT UINTN                  *L1L2BufferSize,
     OUT VOID                   *L1L2Buffer
  );

/**
  This function generates the certificate chain hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SlotIndex                    The slot index of the certificate chain.
  @param  Signature                    The buffer to store the certificate chain hash.

  @retval TRUE  certificate chain hash is generated.
  @retval FALSE certificate chain hash is not generated.
**/
BOOLEAN
SpdmGenerateCertChainHash (
  IN     SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN     UINTN                        SlotIndex,
     OUT UINT8                        *Hash
  );

/**
  This function verifies the digest.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Digest                       The digest data buffer.
  @param  DigestSize                   Size in bytes of the digest data buffer.

  @retval TRUE  digest verification pass.
  @retval FALSE digest verification fail.
**/
BOOLEAN
SpdmVerifyPeerDigests (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *Digest,
  IN UINTN                        DigestSize
  );

/**
  This function verifies peer certificate chain buffer including SPDM_CERT_CHAIN header.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertChainBuffer              Certitiface chain buffer including SPDM_CERT_CHAIN header.
  @param  CertChainBufferSize          Size in bytes of the certitiface chain buffer.

  @retval TRUE  Peer certificate chain buffer verification passed.
  @retval FALSE Peer certificate chain buffer verification failed.
**/
BOOLEAN
SpdmVerifyPeerCertChainBuffer (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *CertChainBuffer,
  IN UINTN                        CertChainBufferSize
  );

/**
  This function generates the challenge signature based upon M1M2 for authentication.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Indicate of the signature generation for a requester or a responder.
  @param  Signature                    The buffer to store the challenge signature.

  @retval TRUE  challenge signature is generated.
  @retval FALSE challenge signature is not generated.
**/
BOOLEAN
SpdmGenerateChallengeAuthSignature (
  IN     SPDM_DEVICE_CONTEXT        *SpdmContext,
  IN     BOOLEAN                    IsRequester,
     OUT UINT8                      *Signature
  );

/**
  This function verifies the certificate chain hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertificateChainHash         The certificate chain hash data buffer.
  @param  CertificateChainHashSize     Size in bytes of the certificate chain hash data buffer.

  @retval TRUE  hash verification pass.
  @retval FALSE hash verification fail.
**/
BOOLEAN
SpdmVerifyCertificateChainHash (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *CertificateChainHash,
  IN UINTN                        CertificateChainHashSize
  );

/**
  This function verifies the challenge signature based upon M1M2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Indicate of the signature verification for a requester or a responder.
  @param  SignData                     The signature data buffer.
  @param  SignDataSize                 Size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
BOOLEAN
SpdmVerifyChallengeAuthSignature (
  IN  SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN  BOOLEAN                      IsRequester,
  IN  VOID                         *SignData,
  IN  UINTN                        SignDataSize
  );

/**
  This function calculate the measurement summary hash size.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Is the function called from a requester.
  @param  MeasurementSummaryHashType   The type of the measurement summary hash.

  @return 0 measurement summary hash type is invalid, NO_MEAS hash type or no MEAS capabilities.
  @return measurement summary hash size according to type.
**/
UINT32
SpdmGetMeasurementSummaryHashSize (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     BOOLEAN              IsRequester,
  IN     UINT8                MeasurementSummaryHashType
  );

/**
  This function calculate the measurement summary hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Is the function called from a requester.
  @param  MeasurementSummaryHashType   The type of the measurement summary hash.
  @param  MeasurementSummaryHash       The buffer to store the measurement summary hash.

  @retval TRUE  measurement summary hash is generated or skipped.
  @retval FALSE measurement summary hash is not generated.
**/
BOOLEAN
SpdmGenerateMeasurementSummaryHash (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     BOOLEAN              IsRequester,
  IN     UINT8                MeasurementSummaryHashType,
     OUT UINT8                *MeasurementSummaryHash
  );

/**
  This function generates the measurement signature to response message based upon L1L2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Signature                    The buffer to store the Signature.

  @retval TRUE  measurement signature is created.
  @retval FALSE measurement signature is not created.
**/
BOOLEAN
SpdmGenerateMeasurementSignature (
  IN     SPDM_DEVICE_CONTEXT    *SpdmContext,
     OUT UINT8                  *Signature
  );

/**
  This function verifies the measurement signature based upon L1L2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SignData                     The signature data buffer.
  @param  SignDataSize                 Size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
BOOLEAN
SpdmVerifyMeasurementSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *SignData,
  IN UINTN                        SignDataSize
  );

/**
  This function generates the key exchange signature based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Signature                    The buffer to store the key exchange signature.

  @retval TRUE  key exchange signature is generated.
  @retval FALSE key exchange signature is not generated.
**/
BOOLEAN
SpdmGenerateKeyExchangeRspSignature (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
     OUT UINT8                     *Signature
  );

/**
  This function generates the key exchange HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Hmac                         The buffer to store the key exchange HMAC.

  @retval TRUE  key exchange HMAC is generated.
  @retval FALSE key exchange HMAC is not generated.
**/
BOOLEAN
SpdmGenerateKeyExchangeRspHmac (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
     OUT UINT8                     *Hmac
  );

/**
  This function verifies the key exchange signature based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  SignData                     The signature data buffer.
  @param  SignDataSize                 Size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
BOOLEAN
SpdmVerifyKeyExchangeRspSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN SPDM_SESSION_INFO            *SessionInfo,
  IN VOID                         *SignData,
  IN INTN                         SignDataSize
  );

/**
  This function verifies the key exchange HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  HmacData                     The HMAC data buffer.
  @param  HmacDataSize                 Size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
BOOLEAN
SpdmVerifyKeyExchangeRspHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
  IN     VOID                 *HmacData,
  IN     UINTN                HmacDataSize
  );

/**
  This function generates the finish signature based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Signature                    The buffer to store the finish signature.

  @retval TRUE  finish signature is generated.
  @retval FALSE finish signature is not generated.
**/
BOOLEAN
SpdmGenerateFinishReqSignature (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
     OUT UINT8                     *Signature
  );

/**
  This function generates the finish HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
BOOLEAN
SpdmGenerateFinishReqHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
     OUT VOID                 *Hmac
  );

/**
  This function verifies the finish signature based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  SignData                     The signature data buffer.
  @param  SignDataSize                 Size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
BOOLEAN
SpdmVerifyFinishReqSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN SPDM_SESSION_INFO            *SessionInfo,
  IN VOID                         *SignData,
  IN INTN                         SignDataSize
  );

/**
  This function verifies the finish HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  HmacData                     The HMAC data buffer.
  @param  HmacDataSize                 Size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
BOOLEAN
SpdmVerifyFinishReqHmac (
  IN  SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN  SPDM_SESSION_INFO    *SessionInfo,
  IN  UINT8                *Hmac,
  IN  UINTN                HmacSize
  );

/**
  This function generates the finish HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Hmac                         The buffer to store the finish HMAC.

  @retval TRUE  finish HMAC is generated.
  @retval FALSE finish HMAC is not generated.
**/
BOOLEAN
SpdmGenerateFinishRspHmac (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
     OUT UINT8                     *Hmac
  );

/**
  This function verifies the finish HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  HmacData                     The HMAC data buffer.
  @param  HmacDataSize                 Size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
BOOLEAN
SpdmVerifyFinishRspHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
  IN     VOID                 *HmacData,
  IN     UINTN                HmacDataSize
  );

/**
  This function generates the PSK exchange HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Hmac                         The buffer to store the PSK exchange HMAC.

  @retval TRUE  PSK exchange HMAC is generated.
  @retval FALSE PSK exchange HMAC is not generated.
**/
BOOLEAN
SpdmGeneratePskExchangeRspHmac (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     SPDM_SESSION_INFO         *SessionInfo,
     OUT UINT8                     *Hmac
  );

/**
  This function verifies the PSK exchange HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  HmacData                     The HMAC data buffer.
  @param  HmacDataSize                 Size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
BOOLEAN
SpdmVerifyPskExchangeRspHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     SPDM_SESSION_INFO    *SessionInfo,
  IN     VOID                 *HmacData,
  IN     UINTN                HmacDataSize
  );

/**
  This function generates the PSK finish HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  Hmac                         The buffer to store the finish HMAC.

  @retval TRUE  PSK finish HMAC is generated.
  @retval FALSE PSK finish HMAC is not generated.
**/
BOOLEAN
SpdmGeneratePskFinishReqHmac (
  IN     SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN     SPDM_SESSION_INFO            *SessionInfo,
     OUT VOID                         *Hmac
  );

/**
  This function verifies the PSK finish HMAC based upon TH.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionInfo                  The session info of an SPDM session.
  @param  HmacData                     The HMAC data buffer.
  @param  HmacDataSize                 Size in bytes of the HMAC data buffer.

  @retval TRUE  HMAC verification pass.
  @retval FALSE HMAC verification fail.
**/
BOOLEAN
SpdmVerifyPskFinishReqHmac (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN  SPDM_SESSION_INFO         *SessionInfo,
  IN  UINT8                     *Hmac,
  IN  UINTN                     HmacSize
  );

/**
  Return the size in bytes of opaque data supproted version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.

  @return the size in bytes of opaque data supproted version.
**/
UINTN
SpdmGetOpaqueDataSupportedVersionDataSize (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
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
SpdmBuildOpaqueDataSupportedVersionData (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
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
SpdmProcessOpaqueDataVersionSelectionData (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                DataInSize,
  IN     VOID                 *DataIn
  );

/**
  Return the size in bytes of opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.

  @return the size in bytes of opaque data version selection.
**/
UINTN
SpdmGetOpaqueDataVersionSelectionDataSize (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
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
SpdmBuildOpaqueDataVersionSelectionData (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
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
SpdmProcessOpaqueDataSupportedVersionData (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                DataInSize,
  IN     VOID                 *DataIn
  );

#endif
