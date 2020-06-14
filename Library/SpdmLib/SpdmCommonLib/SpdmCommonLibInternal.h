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
  UINT16               KeySchedule;
} SPDM_DEVICE_ALGORITHM;

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
} SPDM_STATE;

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
  //
  // My Private Certificate
  //
  VOID                            *PrivatePem;
  UINTN                           PrivatePemSize;
  //
  // measurement collected in the responder
  // SPDM_MEASUREMENT_BLOCK + Hash
  //
  VOID                            *DeviceMeasurement;
  UINT8                           DeviceMeasurementCount;
  //
  // Peer Certificate
  //
  VOID                            *SpdmCertChainVarBuffer;
  UINTN                           SpdmCertChainVarBufferSize;
  //
  // PSK provision locally
  //
  UINTN                           PskSize;
  UINT8                           *Psk;
  //
  // Responder policy
  //
  UINT8                           MutAuthRequested;
} SPDM_LOCAL_CONTEXT;

typedef struct {
  //
  // Peer device info (negotiated)
  //
  UINT16                          Version;
  SPDM_DEVICE_CAPABILITY          Capability;
  SPDM_DEVICE_ALGORITHM           Algorithm;
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
  // Responder: Signature = Sign(SK, Hash(M1))
  // Requester: Verify(PK, Hash(M2), Signature)
  //
  // M1/M2 = Concatenate (A, B, C)
  // A = Concatenate (GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
  // B = Concatenate (GET_DIGEST, DIGEST, GET_CERTFICATE, CERTIFICATE)
  // C = Concatenate (CHALLENGE, CHALLENGE_AUTH\Signature)
  //
  SMALL_MANAGED_BUFFER            MessageA;
  LARGE_MANAGED_BUFFER            MessageB;
  SMALL_MANAGED_BUFFER            MessageC;
  LARGE_MANAGED_BUFFER            M1M2;
  //
  // Signature = Sign(SK, Hash(L1))
  // Verify(PK, Hash(L2), Signature)
  //
  // L1/L2 = Concatenate (GET_MEASUREMENT, MEASUREMENT\Signature)
  //
  BOOLEAN                         GetMeasurementWithSign;
  SMALL_MANAGED_BUFFER            L1L2;
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
  SMALL_MANAGED_BUFFER            MessageF;
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
  UINT8                                SessionId;
  BOOLEAN                              UsePsk;
  UINT8                                MutAuthRequested;
  SPDM_STATE                           SessionState;
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
  UINT32                               EncapState;
  UINT8                                SlotNum;
  LARGE_MANAGED_BUFFER                 CertificateChainBuffer;
} SPDM_ENCAP_CONTEXT;

#define SPDM_DEVICE_CONTEXT_VERSION 0x1

typedef struct {
  UINT32                          Version;
  SPDM_IO_PROTOCOL                *SpdmIo;
  //
  // IO information
  //
  SPDM_IO_SECURE_MESSAGING_TYPE   SecureMessageType;
  UINT32                          Alignment;
  
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
  // Register GetResponse function (responder only)
  //
  UINTN                           GetResponseFunc;
  UINTN                           GetResponseSessionFunc;
  //
  // Register GetEncapResponse function (requester only)
  //
  UINTN                           GetEncapResponseFunc;
  SPDM_ENCAP_CONTEXT              EncapContext;

  SPDM_LOCAL_CONTEXT              LocalContext;

  SPDM_CONNECTION_INFO            ConnectionInfo;
  SPDM_TRANSCRIPT                 Transcript;

  SPDM_SESSION_INFO               SessionInfo[MAX_SPDM_SESSION_COUNT];
} SPDM_DEVICE_CONTEXT;

typedef
BOOLEAN
(EFIAPI *HASH_ALL) (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  );

typedef
BOOLEAN
(EFIAPI *HMAC_ALL) (
  IN   CONST VOID   *Data,
  IN   UINTN        DataSize,
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize,
  OUT  UINT8        *HmacValue
  );

typedef
BOOLEAN
(EFIAPI *HKDF_EXPAND) (
  IN   CONST UINT8  *Prk,
  IN   UINTN        PrkSize,
  IN   CONST UINT8  *Info,
  IN   UINTN        InfoSize,
  OUT  UINT8        *Out,
  IN   UINTN        OutSize
  );

typedef
BOOLEAN
(EFIAPI *AEAD_ENCRYPT) (
  IN   CONST UINT8* Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8* Iv,
  IN   UINTN        IvSize,
  IN   CONST UINT8* AData,
  IN   UINTN        ADataSize,
  IN   CONST UINT8* DataIn,
  IN   UINTN        DataInSize,
  OUT  UINT8*       TagOut,
  IN   UINTN        TagSize,
  OUT  UINT8*       DataOut,
  OUT  UINTN*       DataOutSize
  );

typedef
BOOLEAN
(EFIAPI *AEAD_DECRYPT) (
  IN   CONST UINT8* Key,
  IN   UINTN        KeySize,
  IN   CONST UINT8* Iv,
  IN   UINTN        IvSize,
  IN   CONST UINT8* AData,
  IN   UINTN        ADataSize,
  IN   CONST UINT8* DataIn,
  IN   UINTN        DataInSize,
  IN   CONST UINT8* Tag,
  IN   UINTN        TagSize,
  OUT  UINT8*       DataOut,
  OUT  UINTN*       DataOutSize
  );

typedef
BOOLEAN
(EFIAPI *ASYM_GET_PUBLIC_KEY_FROM_X509) (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize,
  OUT  VOID         **Context
  );

typedef
BOOLEAN
(EFIAPI *ASYM_GET_PRIVATE_KEY_FROM_PEM) (
  IN   CONST UINT8  *PemData,
  IN   UINTN        PemSize,
  IN   CONST CHAR8  *Password,
  OUT  VOID         **Context
  );

typedef
VOID
(EFIAPI *ASYM_FREE) (
  IN  VOID         *Context
  );

typedef
BOOLEAN
(EFIAPI *ASYM_SIGN) (
  IN      VOID         *Context,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

typedef
BOOLEAN
(EFIAPI *ASYM_VERIFY) (
  IN  VOID         *Context,
  IN  CONST UINT8  *MessageHash,
  IN  UINTN        HashSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
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
  This function returns the SPDM hash size.

  @param[in]  SpdmContext             The SPDM context for the device.
  
  @return TCG SPDM hash size
**/
UINT32
GetSpdmHashSize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM hash size.

  @param[in]  SpdmContext             The SPDM context for the device.
  
  @return TCG SPDM hash size
**/
UINT32
GetSpdmAsymSize (
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

HASH_ALL
GetSpdmHashFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

HASH_ALL
GetSpdmMeasurementHashFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

HMAC_ALL
GetSpdmHmacFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

HKDF_EXPAND
GetSpdmHkdfExpandFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

/**
  This function returns the SPDM DHENamedGroup size.

  @param[in]  SpdmContext             The SPDM context for the device.
  
  @return TCG SPDM DHENamedGroup size
**/
UINT32
GetSpdmDHEKeySize (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

UINTN
GetSpdmDHENid (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

BOOLEAN
IsSpdmECDHE (
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

AEAD_ENCRYPT
GetSpdmAeadEncFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

AEAD_DECRYPT
GetSpdmAeadDecFunc (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

ASYM_GET_PUBLIC_KEY_FROM_X509
GetSpdmAsymGetPublicKeyFromX509 (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

ASYM_GET_PRIVATE_KEY_FROM_PEM
GetSpdmAsymGetPrivateKeyFromPem (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

ASYM_FREE
GetSpdmAsymFree (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

ASYM_SIGN
GetSpdmAsymSign (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

ASYM_VERIFY
GetSpdmAsymVerify (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext
  );

VOID
GetRandomNumber (
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
  Reset the managed buffer.
  The BufferSize is reset to 0.
  The MaxBufferSize is unchanged.
  The Buffer is not freed.
**/
RETURN_STATUS
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
  This function generate SPDM HandshakeKey.
  
  @param[in]  SpdmContext            The SPDM context for the device.
**/
RETURN_STATUS
SpdmGenerateSessionHandshakeKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        SessionId,
  IN BOOLEAN                      IsRequester
  );

/**
  This function generate SPDM DataKey.
  
  @param[in]  SpdmContext            The SPDM context for the device.
**/
RETURN_STATUS
SpdmGenerateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        SessionId,
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
  IN UINT8                        SessionId,
  IN SPDM_KEY_UPDATE_ACTION       Action
  );

/**
  This function activate the update of SPDM DataKey.

  @param[in]  SpdmContext            The SPDM context for the device.
**/
RETURN_STATUS
SpdmFinalizeUpdateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT8                        SessionId,
  IN SPDM_KEY_UPDATE_ACTION       Action,
  IN BOOLEAN                      UseNewKey
  );

VOID
GenerateDHESelfKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINTN                        SelfKeySize,
  OUT VOID                        *SelfPubKey,
  OUT VOID                        **Context
  );

VOID
ComputeDHEFinalKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *Context,
  IN UINTN                        PeerKeySize,
  IN VOID                         *PeerPubKey,
  IN OUT UINTN                    *FinalKeySize,
  OUT VOID                        *FinalKey
  );

SPDM_SESSION_INFO *
SpdmGetSessionInfoViaSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT8                     SessionId
  );

#endif