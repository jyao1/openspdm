/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

#define BIN_CONCAT_LABEL      "spdm1.1 "
#define BIN_STR_0_LABEL       "derived"
#define BIN_STR_2_LABEL       "rsp hs data"

STATIC UINTN                  LocalBufferSize;
STATIC UINT8                  LocalBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

STATIC GLOBAL_REMOVE_IF_UNREFERENCED UINT8  mZeroFilledBuffer[64];

UINTN
SpdmTestGetKeyExchangeRequestSize (
  IN VOID    *SpdmContext,
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_KEY_EXCHANGE_REQUEST  *SpdmRequest;
  UINTN                      MessageSize;
  UINTN                      DheKeySize;
  UINT16                     OpaqueLength;

  SpdmRequest = Buffer;
  MessageSize = sizeof(SPDM_MESSAGE_HEADER);
  if (BufferSize < MessageSize) {
    return BufferSize;
  }

  if (SpdmRequest->Header.RequestResponseCode != SPDM_KEY_EXCHANGE) {
    return BufferSize;
  }

  MessageSize = sizeof(SPDM_KEY_EXCHANGE_REQUEST);
  if (BufferSize < MessageSize) {
    return BufferSize;
  }

  DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
  MessageSize += DheKeySize + sizeof(UINT16);
  if (BufferSize < MessageSize) {
    return BufferSize;
  }

  OpaqueLength = *(UINT16 *)((UINTN)Buffer + sizeof(SPDM_KEY_EXCHANGE_REQUEST) + DheKeySize);
  MessageSize += OpaqueLength;
  if (BufferSize < MessageSize) {
    return BufferSize;
  }

  // Good message, return actual size
  return MessageSize;
}

RETURN_STATUS
EFIAPI
SpdmRequesterKeyExchangeTestSendMessage (
  IN     VOID                    *SpdmContext,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;
  UINTN                   HeaderSize;
  UINTN                   MessageSize;

  SpdmTestContext = GetSpdmTestContext ();
  HeaderSize = sizeof(TEST_MESSAGE_HEADER);
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;
  case 0x2:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetKeyExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x3:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetKeyExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x4:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetKeyExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x5:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetKeyExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x6:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetKeyExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x7:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetKeyExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x8:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetKeyExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x9:
  {
    STATIC UINTN SubIndex = 0;
    if (SubIndex == 0) {
      LocalBufferSize = 0;
      MessageSize = SpdmTestGetKeyExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
      CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
      LocalBufferSize += MessageSize;
      SubIndex ++;
    }
  }
    return RETURN_SUCCESS;
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmRequesterKeyExchangeTestReceiveMessage (
  IN     VOID                    *SpdmContext,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = GetSpdmTestContext ();
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;

  case 0x2:
  {
    SPDM_KEY_EXCHANGE_RESPONSE    *SpdmResponse;
    UINTN                         DheKeySize;
    UINT32                        HashSize;
    UINTN                         SignatureSize;
    UINT32                        HmacSize;
    UINT8                         *Ptr;
    VOID                          *DHEContext;
    UINT8                         FinalKey[MAX_DHE_KEY_SIZE];
    UINTN                         FinalKeySize;
    UINTN                         OpaqueKeyExchangeRspSize;
    VOID                          *Data;
    UINTN                         DataSize; 
    UINT8                         HashData[MAX_HASH_SIZE];
    UINT8                         *CertBuffer;
    UINTN                         CertBufferSize;
    UINT8                         CertBufferHash[MAX_HASH_SIZE];
    LARGE_MANAGED_BUFFER          THCurr;
    UINT8                         THCurrHashData[64];
    UINT8                         BinStr0[128];
    UINTN                         BinStr0Size;
    UINT8                         BinStr2[128];
    UINTN                         BinStr2Size;
    UINT8                         BinStr7[128];
    UINTN                         BinStr7Size;
    UINT8                         HandshakeSecret[MAX_HASH_SIZE];
    UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
    UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SignatureSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    HashSize = GetSpdmHashSize (mUseHashAlgo);
    HmacSize = GetSpdmHashSize (mUseHashAlgo);
    DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
    OpaqueKeyExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
    TempBufSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
              DheKeySize +
              0 +
              sizeof(UINT16) +
              OpaqueKeyExchangeRspSize +
              SignatureSize +
              HmacSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_KEY_EXCHANGE_RSP;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->RspSessionID = SpdmAllocateRspSessionId (SpdmContext);
    SpdmResponse->MutAuthRequested = 0;
    SpdmResponse->ReqSlotIDParam = 0;
    SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmResponse->RandomData);
    Ptr = (VOID *)(SpdmResponse + 1);
    DHEContext = SpdmDheNew (mUseDheAlgo);
    SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
    FinalKeySize = sizeof(FinalKey);
    SpdmDheComputeKey (mUseDheAlgo, DHEContext, (UINT8 *)&LocalBuffer[0] + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DheKeySize, FinalKey, &FinalKeySize);
    SpdmDheFree (mUseDheAlgo, DHEContext);
    Ptr += DheKeySize;
    // ZeroMem (Ptr, HashSize);
    // Ptr += HashSize;
    *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeRspSize;
    Ptr += sizeof(UINT16);
    SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaqueKeyExchangeRspSize, Ptr);
    Ptr += OpaqueKeyExchangeRspSize;
    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
    CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
    // Transcript.MessageA size is 0
    AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
    AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
    free(Data);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), Ptr, &SignatureSize);
    CopyMem (&LocalBuffer[LocalBufferSize], Ptr, SignatureSize);
    LocalBufferSize += SignatureSize;
    AppendManagedBuffer (&THCurr, Ptr, SignatureSize);
    Ptr += SignatureSize;
    SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), THCurrHashData);
    BinStr0Size = sizeof(BinStr0);
    SpdmBinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
    SpdmHmacAll (mUseHashAlgo, mZeroFilledBuffer, HashSize, FinalKey, FinalKeySize, HandshakeSecret);
    BinStr2Size = sizeof(BinStr2);
    SpdmBinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1, THCurrHashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
    SpdmHkdfExpand (mUseHashAlgo, HandshakeSecret, HashSize, BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
    BinStr7Size = sizeof(BinStr7);
    SpdmBinConcat (BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr7, &BinStr7Size);
    SpdmHkdfExpand (mUseHashAlgo, ResponseHandshakeSecret, HashSize, BinStr7, BinStr7Size, ResponseFinishedKey, HashSize);
    SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseFinishedKey, HashSize, Ptr);
    Ptr += HmacSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_KEY_EXCHANGE_RESPONSE    *SpdmResponse;
    UINTN                         DheKeySize;
    UINT32                        HashSize;
    UINTN                         SignatureSize;
    UINT32                        HmacSize;
    UINT8                         *Ptr;
    VOID                          *DHEContext;
    UINT8                         FinalKey[MAX_DHE_KEY_SIZE];
    UINTN                         FinalKeySize;
    UINTN                         OpaqueKeyExchangeRspSize;
    VOID                          *Data;
    UINTN                         DataSize; 
    UINT8                         HashData[MAX_HASH_SIZE];
    UINT8                         *CertBuffer;
    UINTN                         CertBufferSize;
    UINT8                         CertBufferHash[MAX_HASH_SIZE];
    LARGE_MANAGED_BUFFER          THCurr;
    UINT8                         THCurrHashData[64];
    UINT8                         BinStr0[128];
    UINTN                         BinStr0Size;
    UINT8                         BinStr2[128];
    UINTN                         BinStr2Size;
    UINT8                         BinStr7[128];
    UINTN                         BinStr7Size;
    UINT8                         HandshakeSecret[MAX_HASH_SIZE];
    UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
    UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SignatureSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    HashSize = GetSpdmHashSize (mUseHashAlgo);
    HmacSize = GetSpdmHashSize (mUseHashAlgo);
    DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
    OpaqueKeyExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
    TempBufSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
              DheKeySize +
              0 +
              sizeof(UINT16) +
              OpaqueKeyExchangeRspSize +
              SignatureSize +
              HmacSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_KEY_EXCHANGE_RSP;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->RspSessionID = SpdmAllocateRspSessionId (SpdmContext);
    SpdmResponse->MutAuthRequested = 0;
    SpdmResponse->ReqSlotIDParam = 0;
    SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmResponse->RandomData);
    Ptr = (VOID *)(SpdmResponse + 1);
    DHEContext = SpdmDheNew (mUseDheAlgo);
    SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
    FinalKeySize = sizeof(FinalKey);
    SpdmDheComputeKey (mUseDheAlgo, DHEContext, (UINT8 *)&LocalBuffer[0] + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DheKeySize, FinalKey, &FinalKeySize);
    SpdmDheFree (mUseDheAlgo, DHEContext);
    Ptr += DheKeySize;
    // ZeroMem (Ptr, HashSize);
    // Ptr += HashSize;
    *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeRspSize;
    Ptr += sizeof(UINT16);
    SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaqueKeyExchangeRspSize, Ptr);
    Ptr += OpaqueKeyExchangeRspSize;
    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
    CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
    // Transcript.MessageA size is 0
    AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
    AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
    free(Data);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), Ptr, &SignatureSize);
    CopyMem (&LocalBuffer[LocalBufferSize], Ptr, SignatureSize);
    LocalBufferSize += SignatureSize;
    AppendManagedBuffer (&THCurr, Ptr, SignatureSize);
    Ptr += SignatureSize;
    SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), THCurrHashData);
    BinStr0Size = sizeof(BinStr0);
    SpdmBinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
    SpdmHmacAll (mUseHashAlgo, mZeroFilledBuffer, HashSize, FinalKey, FinalKeySize, HandshakeSecret);
    BinStr2Size = sizeof(BinStr2);
    SpdmBinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1, THCurrHashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
    SpdmHkdfExpand (mUseHashAlgo, HandshakeSecret, HashSize, BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
    BinStr7Size = sizeof(BinStr7);
    SpdmBinConcat (BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr7, &BinStr7Size);
    SpdmHkdfExpand (mUseHashAlgo, ResponseHandshakeSecret, HashSize, BinStr7, BinStr7Size, ResponseFinishedKey, HashSize);
    SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseFinishedKey, HashSize, Ptr);
    Ptr += HmacSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x4:
  {
    SPDM_ERROR_RESPONSE    SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x5:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x6:
  {
    STATIC UINTN SubIndex1 = 0;
    if (SubIndex1 == 0) {
      SPDM_ERROR_RESPONSE  SpdmResponse;

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
      SpdmResponse.Header.Param2 = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex1 ++;
    } else if (SubIndex1 == 1) {
      SPDM_KEY_EXCHANGE_RESPONSE    *SpdmResponse;
      UINTN                         DheKeySize;
      UINT32                        HashSize;
      UINTN                         SignatureSize;
      UINT32                        HmacSize;
      UINT8                         *Ptr;
      VOID                          *DHEContext;
      UINT8                         FinalKey[MAX_DHE_KEY_SIZE];
      UINTN                         FinalKeySize;
      UINTN                         OpaqueKeyExchangeRspSize;
      VOID                          *Data;
      UINTN                         DataSize; 
      UINT8                         HashData[MAX_HASH_SIZE];
      UINT8                         *CertBuffer;
      UINTN                         CertBufferSize;
      UINT8                         CertBufferHash[MAX_HASH_SIZE];
      LARGE_MANAGED_BUFFER          THCurr;
      UINT8                         THCurrHashData[64];
      UINT8                         BinStr0[128];
      UINTN                         BinStr0Size;
      UINT8                         BinStr2[128];
      UINTN                         BinStr2Size;
      UINT8                         BinStr7[128];
      UINTN                         BinStr7Size;
      UINT8                         HandshakeSecret[MAX_HASH_SIZE];
      UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
      UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
      SignatureSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
      HashSize = GetSpdmHashSize (mUseHashAlgo);
      HmacSize = GetSpdmHashSize (mUseHashAlgo);
      DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
      OpaqueKeyExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
      TempBufSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
              DheKeySize +
              0 +
              sizeof(UINT16) +
              OpaqueKeyExchangeRspSize +
              SignatureSize +
              HmacSize;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse->Header.RequestResponseCode = SPDM_KEY_EXCHANGE_RSP;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->RspSessionID = SpdmAllocateRspSessionId (SpdmContext);
      SpdmResponse->MutAuthRequested = 0;
      SpdmResponse->ReqSlotIDParam = 0;
      SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmResponse->RandomData);
      Ptr = (VOID *)(SpdmResponse + 1);
      DHEContext = SpdmDheNew (mUseDheAlgo);
      SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
      FinalKeySize = sizeof(FinalKey);
      SpdmDheComputeKey (mUseDheAlgo, DHEContext, (UINT8 *)&LocalBuffer[0] + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DheKeySize, FinalKey, &FinalKeySize);
      SpdmDheFree (mUseDheAlgo, DHEContext);
      Ptr += DheKeySize;
      // ZeroMem (Ptr, HashSize);
      // Ptr += HashSize;
      *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeRspSize;
      Ptr += sizeof(UINT16);
      SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaqueKeyExchangeRspSize, Ptr);
      Ptr += OpaqueKeyExchangeRspSize;
      ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
      InternalDumpHex (LocalBuffer, LocalBufferSize);
      InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
      CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
      // Transcript.MessageA size is 0
      AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
      AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
      SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
      free(Data);
      SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), Ptr, &SignatureSize);
      CopyMem (&LocalBuffer[LocalBufferSize], Ptr, SignatureSize);
      LocalBufferSize += SignatureSize;
      AppendManagedBuffer (&THCurr, Ptr, SignatureSize);
      Ptr += SignatureSize;
      SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), THCurrHashData);
      BinStr0Size = sizeof(BinStr0);
      SpdmBinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
      SpdmHmacAll (mUseHashAlgo, mZeroFilledBuffer, HashSize, FinalKey, FinalKeySize, HandshakeSecret);
      BinStr2Size = sizeof(BinStr2);
      SpdmBinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1, THCurrHashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
      SpdmHkdfExpand (mUseHashAlgo, HandshakeSecret, HashSize, BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
      BinStr7Size = sizeof(BinStr7);
      SpdmBinConcat (BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr7, &BinStr7Size);
      SpdmHkdfExpand (mUseHashAlgo, ResponseHandshakeSecret, HashSize, BinStr7, BinStr7Size, ResponseFinishedKey, HashSize);
      SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseFinishedKey, HashSize, Ptr);
      Ptr += HmacSize;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
  }
    return RETURN_SUCCESS;

  case 0x7:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x8:
  {
    SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.ExtendErrorData.RDTExponent = 1;
    SpdmResponse.ExtendErrorData.RDTM = 1;
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_KEY_EXCHANGE;
    SpdmResponse.ExtendErrorData.Token = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x9:
  {
    STATIC UINTN SubIndex2 = 0;
    if (SubIndex2 == 0) {
      SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.ExtendErrorData.RDTExponent = 1;
      SpdmResponse.ExtendErrorData.RDTM = 1;
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_KEY_EXCHANGE;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex2 ++;
    } else if (SubIndex2 == 1) {
      SPDM_KEY_EXCHANGE_RESPONSE    *SpdmResponse;
      UINTN                         DheKeySize;
      UINT32                        HashSize;
      UINTN                         SignatureSize;
      UINT32                        HmacSize;
      UINT8                         *Ptr;
      VOID                          *DHEContext;
      UINT8                         FinalKey[MAX_DHE_KEY_SIZE];
      UINTN                         FinalKeySize;
      UINTN                         OpaqueKeyExchangeRspSize;
      VOID                          *Data;
      UINTN                         DataSize; 
      UINT8                         HashData[MAX_HASH_SIZE];
      UINT8                         *CertBuffer;
      UINTN                         CertBufferSize;
      UINT8                         CertBufferHash[MAX_HASH_SIZE];
      LARGE_MANAGED_BUFFER          THCurr;
      UINT8                         THCurrHashData[64];
      UINT8                         BinStr0[128];
      UINTN                         BinStr0Size;
      UINT8                         BinStr2[128];
      UINTN                         BinStr2Size;
      UINT8                         BinStr7[128];
      UINTN                         BinStr7Size;
      UINT8                         HandshakeSecret[MAX_HASH_SIZE];
      UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
      UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
      SignatureSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
      HashSize = GetSpdmHashSize (mUseHashAlgo);
      HmacSize = GetSpdmHashSize (mUseHashAlgo);
      DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
      OpaqueKeyExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
      TempBufSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
              DheKeySize +
              0 +
              sizeof(UINT16) +
              OpaqueKeyExchangeRspSize +
              SignatureSize +
              HmacSize;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse->Header.RequestResponseCode = SPDM_KEY_EXCHANGE_RSP;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->RspSessionID = SpdmAllocateRspSessionId (SpdmContext);
      SpdmResponse->MutAuthRequested = 0;
      SpdmResponse->ReqSlotIDParam = 0;
      SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmResponse->RandomData);
      Ptr = (VOID *)(SpdmResponse + 1);
      DHEContext = SpdmDheNew (mUseDheAlgo);
      SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
      FinalKeySize = sizeof(FinalKey);
      SpdmDheComputeKey (mUseDheAlgo, DHEContext, (UINT8 *)&LocalBuffer[0] + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DheKeySize, FinalKey, &FinalKeySize);
      SpdmDheFree (mUseDheAlgo, DHEContext);
      Ptr += DheKeySize;
      // ZeroMem (Ptr, HashSize);
      // Ptr += HashSize;
      *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeRspSize;
      Ptr += sizeof(UINT16);
      SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaqueKeyExchangeRspSize, Ptr);
      Ptr += OpaqueKeyExchangeRspSize;
      ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
      InternalDumpHex (LocalBuffer, LocalBufferSize);
      InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
      CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
      // Transcript.MessageA size is 0
      AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
      AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
      SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
      free(Data);
      SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), Ptr, &SignatureSize);
      CopyMem (&LocalBuffer[LocalBufferSize], Ptr, SignatureSize);
      LocalBufferSize += SignatureSize;
      AppendManagedBuffer (&THCurr, Ptr, SignatureSize);
      Ptr += SignatureSize;
      SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), THCurrHashData);
      BinStr0Size = sizeof(BinStr0);
      SpdmBinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
      SpdmHmacAll (mUseHashAlgo, mZeroFilledBuffer, HashSize, FinalKey, FinalKeySize, HandshakeSecret);
      BinStr2Size = sizeof(BinStr2);
      SpdmBinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1, THCurrHashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
      SpdmHkdfExpand (mUseHashAlgo, HandshakeSecret, HashSize, BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
      BinStr7Size = sizeof(BinStr7);
      SpdmBinConcat (BIN_STR_7_LABEL, sizeof(BIN_STR_7_LABEL) - 1, NULL, (UINT16)HashSize, HashSize, BinStr7, &BinStr7Size);
      SpdmHkdfExpand (mUseHashAlgo, ResponseHandshakeSecret, HashSize, BinStr7, BinStr7Size, ResponseFinishedKey, HashSize);
      SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseFinishedKey, HashSize, Ptr);
      Ptr += HmacSize;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

void TestSpdmRequesterKeyExchangeCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  UINT8                SlotIdParam; 
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);  
  assert_int_equal (Status, RETURN_UNSUPPORTED);
  free(Data);
}

void TestSpdmRequesterKeyExchangeCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SessionId, 0xFFFFFFFF);
  assert_int_equal (SpdmSecuredMessageGetSessionState (SpdmContext->SessionInfo[0].SecuredMessageContext), SpdmSessionStateHandshaking);
  free(Data);
}

void TestSpdmRequesterKeyExchangeCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_UNSUPPORTED);  
  free(Data);
}

void TestSpdmRequesterKeyExchangeCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterKeyExchangeCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  free(Data);
}

void TestSpdmRequesterKeyExchangeCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SessionId, 0xFFFEFFFE);
  assert_int_equal (SpdmSecuredMessageGetSessionState (SpdmContext->SessionInfo[0].SecuredMessageContext), SpdmSessionStateHandshaking);
  free(Data);
}

void TestSpdmRequesterKeyExchangeCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->ConnectionInfo.ConnectionState, SpdmConnectionStateNotStarted);
  free(Data);
}

void TestSpdmRequesterKeyExchangeCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterKeyExchangeCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  UINT8                SlotIdParam;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SessionId, 0xFFFDFFFD);
  assert_int_equal (SpdmSecuredMessageGetSessionState (SpdmContext->SessionInfo[0].SecuredMessageContext), SpdmSessionStateHandshaking);
  free(Data);
}

SPDM_TEST_CONTEXT       mSpdmRequesterKeyExchangeTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterKeyExchangeTestSendMessage,
  SpdmRequesterKeyExchangeTestReceiveMessage,
};

int SpdmRequesterKeyExchangeTestMain(void) {
  const struct CMUnitTest SpdmRequesterKeyExchangeTests[] = {
      // SendRequest failed
      cmocka_unit_test(TestSpdmRequesterKeyExchangeCase1),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterKeyExchangeCase2),
      // ConnectionState check failed
      cmocka_unit_test(TestSpdmRequesterKeyExchangeCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterKeyExchangeCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterKeyExchangeCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterKeyExchangeCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterKeyExchangeCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterKeyExchangeCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterKeyExchangeCase9),
  };
  
  SetupSpdmTestContext (&mSpdmRequesterKeyExchangeTestContext);

  return cmocka_run_group_tests(SpdmRequesterKeyExchangeTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
