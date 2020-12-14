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
  // Use my Private Certificate to sign
  //
  SPDM_DATA_SIGN_FUNC             SpdmRequesterDataSignFunc;
  SPDM_DATA_SIGN_FUNC             SpdmResponderDataSignFunc;
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
  UINTN                           PskHintSize;
  UINT8                           *PskHint;
  //
  // Use my PSK to HKDF
  //
  SPDM_PSK_HKDF_EXPAND_FUNC       SpdmPskHandshakeSecretHkdfExpandFunc;
  SPDM_PSK_HKDF_EXPAND_FUNC       SpdmPskMasterSecretHkdfExpandFunc;
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
  UINT8                MasterSecret[MAX_HASH_SIZE];
} SPDM_SESSION_INFO_MASTER_SECRET;

typedef struct {
  UINT8                RequestHandshakeSecret[MAX_HASH_SIZE];
  UINT8                ResponseHandshakeSecret[MAX_HASH_SIZE];
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
  SPDM_SESSION_INFO_MASTER_SECRET      MasterSecret;
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
#define SPDM_KEY_EXCHANGE_RECEIVE_FLAG                  BIT7


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
  Reads a 24-bit value from memory that may be unaligned.

  @param  Buffer  The pointer to a 24-bit value that may be unaligned.

  @return The 24-bit value read from Buffer.
**/
UINT32
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
SpdmWriteUint24 (
  IN UINT8  *Buffer,
  IN UINT32 Value
  );

/**
  This function returns the SPDM hash algorithm size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM hash algorithm size.
**/
UINT32
GetSpdmHashSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM asymmetric algorithm size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM asymmetric algorithm size.
**/
UINT32
GetSpdmAsymSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM requester asymmetric algorithm size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM requester asymmetric algorithm size.
**/
UINT32
GetSpdmReqAsymSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM measurement hash algorithm size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM measurement hash algorithm size.
**/
UINT32
GetSpdmMeasurementHashSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  Computes the hash of a input data buffer, based upon the negotiated hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
BOOLEAN
SpdmHashAll (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  );

/**
  Computes the hash of a input data buffer, based upon the negotiated measurement hash algorithm.

  This function performs the hash of a given data buffer, and return the hash value.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Data                         Pointer to the buffer containing the data to be hashed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  HashValue                    Pointer to a buffer that receives the hash value.

  @retval TRUE   Hash computation succeeded.
  @retval FALSE  Hash computation failed.
**/
BOOLEAN
SpdmMeasurementHashAll (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  OUT  UINT8                        *HashValue
  );

/**
  Computes the HMAC of a input data buffer, based upon the negotiated HMAC algorithm.

  This function performs the HMAC of a given data buffer, and return the hash value.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Data                         Pointer to the buffer containing the data to be HMACed.
  @param  DataSize                     Size of Data buffer in bytes.
  @param  Key                          Pointer to the user-supplied key.
  @param  KeySize                      Key size in bytes.
  @param  HashValue                    Pointer to a buffer that receives the HMAC value.

  @retval TRUE   HMAC computation succeeded.
  @retval FALSE  HMAC computation failed.
**/
BOOLEAN
SpdmHmacAll (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST VOID                   *Data,
  IN   UINTN                        DataSize,
  IN   CONST UINT8                  *Key,
  IN   UINTN                        KeySize,
  OUT  UINT8                        *HmacValue
  );

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Prk                          Pointer to the user-supplied key.
  @param  PrkSize                      Key size in bytes.
  @param  Info                         Pointer to the application specific info.
  @param  InfoSize                     Info size in bytes.
  @param  Out                          Pointer to buffer to receive hkdf value.
  @param  OutSize                      Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
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
  This function returns the SPDM DHE algorithm key size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM DHE algorithm key size.
**/
UINT32
GetSpdmDheKeySize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM AEAD algorithm key size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm key size.
**/
UINT32
GetSpdmAeadKeySize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM AEAD algorithm iv size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm iv size.
**/
UINT32
GetSpdmAeadIvSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM AEAD algorithm tag size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm tag size.
**/
UINT32
GetSpdmAeadTagSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM AEAD algorithm block size.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return SPDM AEAD algorithm block size.
**/
UINT32
GetSpdmAeadBlockSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  Performs AEAD authenticated encryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Key                          Pointer to the encryption key.
  @param  KeySize                      Size of the encryption key in bytes.
  @param  Iv                           Pointer to the IV value.
  @param  IvSize                       Size of the IV value in bytes.
  @param  AData                        Pointer to the additional authenticated data (AAD).
  @param  ADataSize                    Size of the additional authenticated data (AAD) in bytes.
  @param  DataIn                       Pointer to the input data buffer to be encrypted.
  @param  DataInSize                   Size of the input data buffer in bytes.
  @param  TagOut                       Pointer to a buffer that receives the authentication tag output.
  @param  TagSize                      Size of the authentication tag in bytes.
  @param  DataOut                      Pointer to a buffer that receives the encryption output.
  @param  DataOutSize                  Size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated encryption succeeded.
  @retval FALSE  AEAD authenticated encryption failed.
**/
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

/**
  Performs AEAD authenticated decryption on a data buffer and additional authenticated data (AAD),
  based upon negotiated AEAD algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Key                          Pointer to the encryption key.
  @param  KeySize                      Size of the encryption key in bytes.
  @param  Iv                           Pointer to the IV value.
  @param  IvSize                       Size of the IV value in bytes.
  @param  AData                        Pointer to the additional authenticated data (AAD).
  @param  ADataSize                    Size of the additional authenticated data (AAD) in bytes.
  @param  DataIn                       Pointer to the input data buffer to be decrypted.
  @param  DataInSize                   Size of the input data buffer in bytes.
  @param  Tag                          Pointer to a buffer that contains the authentication tag.
  @param  TagSize                      Size of the authentication tag in bytes.
  @param  DataOut                      Pointer to a buffer that receives the decryption output.
  @param  DataOutSize                  Size of the output data buffer in bytes.

  @retval TRUE   AEAD authenticated decryption succeeded.
  @retval FALSE  AEAD authenticated decryption failed.
**/
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

/**
  Retrieve the asymmetric Public Key from one DER-encoded X509 certificate,
  based upon negotiated asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Cert                         Pointer to the DER-encoded X509 certificate.
  @param  CertSize                     Size of the X509 certificate in bytes.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
BOOLEAN
SpdmAsymGetPublicKeyFromX509 (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8                  *Cert,
  IN   UINTN                        CertSize,
  OUT  VOID                         **Context
  );

/**
  Release the specified asymmetric context,
  based upon negotiated asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to the asymmetric context to be released.
**/
VOID
SpdmAsymFree (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context
  );

/**
  Verifies the asymmetric signature,
  based upon negotiated asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to asymmetric context for signature verification.
  @param  MessageHash                  Pointer to octet message hash to be checked.
  @param  HashSize                     Size of the message hash in bytes.
  @param  Signature                    Pointer to asymmetric signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
BOOLEAN
SpdmAsymVerify (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context,
  IN   CONST UINT8                  *MessageHash,
  IN   UINTN                        HashSize,
  IN   CONST UINT8                  *Signature,
  IN   UINTN                        SigSize
  );

/**
  Retrieve the asymmetric Public Key from one DER-encoded X509 certificate,
  based upon negotiated requester asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Cert                         Pointer to the DER-encoded X509 certificate.
  @param  CertSize                     Size of the X509 certificate in bytes.
  @param  Context                      Pointer to new-generated asymmetric context which contain the retrieved public key component.
                                       Use SpdmAsymFree() function to free the resource.

  @retval  TRUE   Public Key was retrieved successfully.
  @retval  FALSE  Fail to retrieve public key from X509 certificate.
**/
BOOLEAN
SpdmReqAsymGetPublicKeyFromX509 (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   CONST UINT8                  *Cert,
  IN   UINTN                        CertSize,
  OUT  VOID                         **Context
  );

/**
  Release the specified asymmetric context,
  based upon negotiated requester asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to the asymmetric context to be released.
**/
VOID
SpdmReqAsymFree (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context
  );

/**
  Verifies the asymmetric signature,
  based upon negotiated requester asymmetric algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to asymmetric context for signature verification.
  @param  MessageHash                  Pointer to octet message hash to be checked.
  @param  HashSize                     Size of the message hash in bytes.
  @param  Signature                    Pointer to asymmetric signature to be verified.
  @param  SigSize                      Size of signature in bytes.

  @retval  TRUE   Valid asymmetric signature.
  @retval  FALSE  Invalid asymmetric signature or invalid asymmetric context.
**/
BOOLEAN
SpdmReqAsymVerify (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context,
  IN   CONST UINT8                  *MessageHash,
  IN   UINTN                        HashSize,
  IN   CONST UINT8                  *Signature,
  IN   UINTN                        SigSize
  );

/**
  Allocates and Initializes one Diffie-Hellman Ephemeral (DHE) Context for subsequent use,
  based upon negotiated DHE algorithm.

  @return  Pointer to the Diffie-Hellman Context that has been initialized.
**/
VOID *
SpdmDheNew (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  Release the specified DHE context,
  based upon negotiated DHE algorithm.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to the DHE context to be released.
**/
VOID
SpdmDheFree (
  IN   SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN   VOID                         *Context
  );

/**
  Generates DHE public key,
  based upon negotiated DHE algorithm.

  This function generates random secret exponent, and computes the public key, which is
  returned via parameter PublicKey and PublicKeySize. DH context is updated accordingly.
  If the PublicKey buffer is too small to hold the public key, FALSE is returned and
  PublicKeySize is set to the required buffer size to obtain the public key.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to the DHE context.
  @param  PublicKey                    Pointer to the buffer to receive generated public key.
  @param  PublicKeySize                On input, the size of PublicKey buffer in bytes.
                                       On output, the size of data returned in PublicKey buffer in bytes.

  @retval TRUE   DHE public key generation succeeded.
  @retval FALSE  DHE public key generation failed.
  @retval FALSE  PublicKeySize is not large enough.
**/
BOOLEAN
SpdmDheGenerateKey (
  IN      SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN OUT  VOID                         *Context,
  OUT     UINT8                        *PublicKey,
  IN OUT  UINTN                        *PublicKeySize
  );

/**
  Computes exchanged common key,
  based upon negotiated DHE algorithm.

  Given peer's public key, this function computes the exchanged common key, based on its own
  context including value of prime modulus and random secret exponent.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Context                      Pointer to the DHE context.
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
SpdmDheComputeKey (
  IN      SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN OUT  VOID                         *Context,
  IN      CONST UINT8                  *PeerPublic,
  IN      UINTN                        PeerPublicSize,
  OUT     UINT8                        *Key,
  IN OUT  UINTN                        *KeySize
  );

/**
  Generates a random byte stream of the specified size.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Size                         Size of random bytes to generate.
  @param  Rand                         Pointer to buffer to receive random value.
**/
VOID
SpdmGetRandomNumber (
  IN  UINTN                     Size,
  OUT UINT8                     *Rand
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

RETURN_STATUS
BinConcat (
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

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.

  @retval RETURN_SUCCESS  SPDM HandshakeKey for a session is generated.
**/
RETURN_STATUS
SpdmGenerateSessionHandshakeKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester
  );

/**
  This function generates SPDM DataKey for a session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
  @param  IsRequester                  Indicate of the key generation for a requester or a responder.

  @retval RETURN_SUCCESS  SPDM DataKey for a session is generated.
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
  This function creates the updates of SPDM DataKey for a session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
  @param  Action                       Indicate of the key update action.

  @retval RETURN_SUCCESS  SPDM DataKey update is created.
**/
RETURN_STATUS
SpdmCreateUpdateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN SPDM_KEY_UPDATE_ACTION       Action
  );

/**
  This function activates the update of SPDM DataKey for a session.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
  @param  Action                       Indicate of the key update action.
  @param  UseNewKey                    Indicate if the new key should be used.

  @retval RETURN_SUCCESS  SPDM DataKey update is activated.
**/
RETURN_STATUS
SpdmActivateUpdateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN SPDM_KEY_UPDATE_ACTION       Action,
  IN BOOLEAN                      UseNewKey
  );

/**
  This function gets the session info via session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return session info.
**/
SPDM_SESSION_INFO *
SpdmGetSessionInfoViaSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT32                    SessionId
  );

/**
  This function assigns a new session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return session info associated with this new session ID.
**/
SPDM_SESSION_INFO *
SpdmAssignSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT32                    SessionId
  );

/**
  This function frees a session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return freed session info assicated with this session ID.
**/
SPDM_SESSION_INFO *
SpdmFreeSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT32                    SessionId
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
  Retrieve the SubjectAltName from SubjectAltName Bytes.

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
SpdmX509CertificateCheck (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize
  );

#endif
