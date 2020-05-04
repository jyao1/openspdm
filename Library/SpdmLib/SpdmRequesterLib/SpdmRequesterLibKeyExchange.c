/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

#pragma pack(1)

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT32               DHE_Named_Group;
  UINT8                RandomData[SPDM_RANDOM_DATA_SIZE];
  UINT8                ExchangeData[MAX_DHE_KEY_SIZE];
} SPDM_KEY_EXCHANGE_REQUEST_MINE;

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               Length;
  UINT8                Mut_Auth_Requested;
  UINT8                Reserved;
  UINT8                RandomData[SPDM_RANDOM_DATA_SIZE];
  UINT8                ExchangeData[MAX_DHE_KEY_SIZE];
  UINT8                MeasurementSummaryHash[MAX_HASH_SIZE];
  UINT8                Signature[MAX_ASYM_KEY_SIZE];
  UINT8                VerifyData[MAX_HASH_SIZE];
} SPDM_KEY_EXCHANGE_RESPONSE_MAX;

#pragma pack()

RETURN_STATUS
VerifyKeyExchangeSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *SignData,
  IN INTN                         SignDataSize
  )
{
  HASH_ALL                                  HashAll;
  UINTN                                     HashSize;
  UINT8                                     HashData[MAX_HASH_SIZE];
  BOOLEAN                                   Result;
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  VOID                                      *RsaContext;
  LARGE_MANAGED_BUFFER                      THCurr = {MAX_SPDM_MESSAGE_BUFFER_SIZE};

  HashAll = GetSpdmHashFunc (SpdmContext);
  ASSERT(HashAll != NULL);
  HashSize = GetSpdmHashSize (SpdmContext);

  if ((SpdmContext->LocalContext.SpdmCertChainVarBuffer == NULL) || (SpdmContext->LocalContext.SpdmCertChainVarBufferSize == 0)) {
    return RETURN_SECURITY_VIOLATION;
  }
  CertBuffer = (UINT8 *)SpdmContext->LocalContext.SpdmCertChainVarBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->LocalContext.SpdmCertChainVarBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK) - SignDataSize);

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBuffer, CertBufferSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK) - SignDataSize);

  HashAll (GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
  DEBUG((DEBUG_INFO, "THCurr Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Result = RsaGetPublicKeyFromX509 (CertBuffer, CertBufferSize, &RsaContext);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }

  Result = RsaPkcs1Verify (
             RsaContext,
             HashData,
             HashSize,
             SignData,
             SignDataSize
             );
  RsaFree (RsaContext);
  if (!Result) {
    DEBUG((DEBUG_INFO, "!!! VerifyKeyExchangeSignature - FAIL !!!\n"));
    return RETURN_SECURITY_VIOLATION;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyKeyExchangeSignature - PASS !!!\n"));

  return RETURN_SUCCESS;
}

RETURN_STATUS
VerifyKeyExchangeHmac (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     VOID                 *HmacData,
  IN     UINTN                HmacDataSize
  )
{
  HMAC_ALL                                  HmacAll;
  UINTN                                     HashSize;
  UINT8                                     CalcHmacData[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  LARGE_MANAGED_BUFFER                      THCurr = {MAX_SPDM_MESSAGE_BUFFER_SIZE};
  SPDM_SESSION_INFO                         *SessionInfo;
  
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return RETURN_UNSUPPORTED;
  }

  HmacAll = GetSpdmHmacFunc (SpdmContext);
  ASSERT(HmacAll != NULL);
  HashSize = GetSpdmHashSize (SpdmContext);
  ASSERT(HashSize == HmacDataSize);

  if ((SpdmContext->LocalContext.SpdmCertChainVarBuffer == NULL) || (SpdmContext->LocalContext.SpdmCertChainVarBufferSize == 0)) {
    return RETURN_SECURITY_VIOLATION;
  }
  CertBuffer = (UINT8 *)SpdmContext->LocalContext.SpdmCertChainVarBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->LocalContext.SpdmCertChainVarBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBuffer, CertBufferSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK));

  ASSERT(SessionInfo->HashSize != 0);
  HmacAll (GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->ResponseHandshakeSecret, SessionInfo->HashSize, CalcHmacData);
  DEBUG((DEBUG_INFO, "THCurr Hmac - "));
  InternalDumpData (CalcHmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (CompareMem (CalcHmacData, HmacData, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyKeyExchangeHmac - FAIL !!!\n"));
    return RETURN_SECURITY_VIOLATION;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyKeyExchangeHmac - PASS !!!\n"));

  return RETURN_SUCCESS;
}

/**
  This function executes SPDM key change.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceiveKeyExchange (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementHashType,
  IN     UINT8                SlotNum,
     OUT UINT8                *HeartbeatPeriod,
     OUT UINT8                *SessionId,
     OUT VOID                 *MeasurementHash
  )
{
  RETURN_STATUS                             Status;
  SPDM_KEY_EXCHANGE_REQUEST_MINE            SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_KEY_EXCHANGE_RESPONSE_MAX            SpdmResponse;
  UINTN                                     SpdmResponseSize;
  UINT32                                    DHEKeySize;
  UINT32                                    HashSize;
  UINT32                                    SignatureSize;
  UINT32                                    HmacSize;
  UINT8                                     *Ptr;
  VOID                                      *MeasurementSummaryHash;
  UINT8                                     *Signature;
  UINT8                                     *VerifyData;
  VOID                                      *DHEContext;
  UINT8                                     FinalKey[MAX_DHE_KEY_SIZE];
  UINTN                                     FinalKeySize;
  SPDM_SESSION_INFO                         *SessionInfo;

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmRequest.Header.RequestResponseCode = SPDM_KEY_EXCHANGE;
  SpdmRequest.Header.Param1 = MeasurementHashType;
  SpdmRequest.Header.Param2 = SlotNum;
  SpdmRequest.DHE_Named_Group = SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup;
  GetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmRequest.RandomData);
  DEBUG((DEBUG_INFO, "ClientRandomData (0x%x) - ", SPDM_RANDOM_DATA_SIZE));
  InternalDumpData (SpdmRequest.RandomData, SPDM_RANDOM_DATA_SIZE);
  DEBUG((DEBUG_INFO, "\n"));

  DHEKeySize = GetSpdmDHEKeySize (SpdmContext);
  GenerateDHESelfKey (SpdmContext, DHEKeySize, SpdmRequest.ExchangeData, &DHEContext);
  DEBUG((DEBUG_INFO, "ClientKey (0x%x):\n", DHEKeySize));
  InternalDumpHex (SpdmRequest.ExchangeData, DHEKeySize);
  SpdmRequestSize = sizeof(SPDM_KEY_EXCHANGE_REQUEST) + DHEKeySize;
  Status = SpdmSendRequest (SpdmContext, SpdmRequestSize, &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveResponse (SpdmContext, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_KEY_EXCHANGE_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_KEY_EXCHANGE_RSP) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Mut_Auth_Requested != 0) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_NO_MUTUAL_AUTH;
    return RETURN_DEVICE_ERROR;
  }
  if (HeartbeatPeriod != NULL) {
    *HeartbeatPeriod = SpdmResponse.Header.Param1;
  }
  *SessionId = SpdmResponse.Header.Param2;
  SessionInfo = SpdmAssignSessionId (SpdmContext, *SessionId);
  SessionInfo->UsePsk = FALSE;

  SignatureSize = GetSpdmAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);
  HmacSize = GetSpdmHashSize (SpdmContext);

  if (SpdmResponseSize != sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
                          DHEKeySize +
                          HashSize +
                          SignatureSize +
                          HmacSize) {
    return RETURN_DEVICE_ERROR;
  }

  DEBUG((DEBUG_INFO, "ServerRandomData (0x%x) - ", SPDM_RANDOM_DATA_SIZE));
  InternalDumpData (SpdmResponse.RandomData, SPDM_RANDOM_DATA_SIZE);
  DEBUG((DEBUG_INFO, "\n"));

  DEBUG((DEBUG_INFO, "ServerKey (0x%x):\n", DHEKeySize));
  InternalDumpHex (SpdmResponse.ExchangeData, DHEKeySize);

  Ptr = SpdmResponse.ExchangeData;
  Ptr += DHEKeySize;
  
  MeasurementSummaryHash = Ptr;
  DEBUG((DEBUG_INFO, "MeasurementSummaryHash (0x%x) - ", HashSize));
  InternalDumpData (MeasurementSummaryHash, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  Ptr += HashSize;

  Signature = Ptr;
  DEBUG((DEBUG_INFO, "Signature (0x%x):\n", SignatureSize));
  InternalDumpHex (Signature, SignatureSize);
  Ptr += SignatureSize;  
  Status = VerifyKeyExchangeSignature (SpdmContext, Signature, SignatureSize);
  if (RETURN_ERROR(Status)) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return Status;
  }

  //
  // Fill data to calc Secret for HMAC verification
  //
  FinalKeySize = sizeof(FinalKey);
  ComputeDHEFinalKey (SpdmContext, DHEContext, DHEKeySize, SpdmResponse.ExchangeData, &FinalKeySize, FinalKey);
  DEBUG((DEBUG_INFO, "FinalKey (0x%x):\n", FinalKeySize));
  InternalDumpHex (FinalKey, FinalKeySize);

  ASSERT (FinalKeySize <= sizeof(SessionInfo->DheSecret));
  SessionInfo->DheKeySize = FinalKeySize;
  CopyMem (SessionInfo->DheSecret, FinalKey, FinalKeySize);
  SessionInfo->Mut_Auth_Requested = SpdmResponse.Mut_Auth_Requested;

  Status = SpdmGenerateSessionHandshakeKey (SpdmContext, *SessionId);
  if (RETURN_ERROR(Status)) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return Status;
  }

  VerifyData = Ptr;
  DEBUG((DEBUG_INFO, "VerifyData (0x%x):\n", HmacSize));
  InternalDumpHex (VerifyData, HmacSize);
  Status = VerifyKeyExchangeHmac (SpdmContext, *SessionId, VerifyData, HmacSize);
  if (RETURN_ERROR(Status)) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_KEY_EXCHANGE_FAILURE;
    return Status;
  }

  if (MeasurementHash != NULL) {
    CopyMem (MeasurementHash, MeasurementSummaryHash, HashSize);
  }

  SessionInfo->SessionState = SpdmStateHandshaking;
  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  
  return RETURN_SUCCESS;
}

