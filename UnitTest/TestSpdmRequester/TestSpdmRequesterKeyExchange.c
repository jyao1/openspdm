/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

#define BIN_CONCAT_LABEL      "spdm1.1"
#define BIN_STR_0_LABEL       "derived"
#define BIN_STR_2_LABEL       "rsp hs data"

STATIC UINTN                  LocalBufferSize;
STATIC UINT8                  LocalBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

STATIC GLOBAL_REMOVE_IF_UNREFERENCED UINT8  mZeroFilledBuffer[64];

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
  UINT8                   *Ptr;

  SpdmTestContext = GetSpdmTestContext ();
  Ptr = (UINT8 *)Request;
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;
  case 0x2:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x3:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x4:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x5:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x6:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x7:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x8:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x9:
  {
    STATIC UINTN SubIndex = 0;
    if (SubIndex == 0) {
      LocalBufferSize = 0;
      CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
      LocalBufferSize += (RequestSize - 1);
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
    VOID                          *Context;
    UINT8                         THCurrHashData[64];
    UINT8                         Secret0[64];
    UINT8                         Salt0[64];
    UINT8                         BinStr0[128];
    UINTN                         BinStr0Size;
    UINT8                         BinStr2[128];
    UINTN                         BinStr2Size;
    UINT8                         HandshakeSecret[MAX_HASH_SIZE];
    UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = USE_MEASUREMENT_HASH_ALGO;
    SignatureSize = GetSpdmAsymSize (SpdmContext);
    HashSize = GetSpdmHashSize (SpdmContext);
    HmacSize = GetSpdmHashSize (SpdmContext);
    DheKeySize = GetSpdmDheKeySize (SpdmContext);
    OpaqueKeyExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
    TempBufSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
              DheKeySize +
              HashSize +
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
    SpdmResponse->SlotIDParam = 0;
    SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmResponse->RandomData);
    Ptr = (VOID *)(SpdmResponse + 1);
    DHEContext = SpdmDheNew (SpdmContext);
    SpdmDheGenerateKey (SpdmContext, DHEContext, Ptr, &DheKeySize);
    FinalKeySize = sizeof(FinalKey);
    SpdmDheComputeKey (SpdmContext, DHEContext, (UINT8 *)&LocalBuffer[0] + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DheKeySize, FinalKey, &FinalKeySize);
    SpdmDheFree (SpdmContext, DHEContext);
    Ptr += DheKeySize;
    ZeroMem (Ptr, HashSize);
    Ptr += HashSize;
    *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeRspSize;
    Ptr += sizeof(UINT16);
    SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaqueKeyExchangeRspSize, Ptr);
    Ptr += OpaqueKeyExchangeRspSize;
    ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
    CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);
    // Transcript.MessageA size is 0
    AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
    AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
    SpdmHashAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
    free(Data);
    ReadResponderPrivateCertificate (&Data, &DataSize);
    TestSpdmAsymGetPrivateKeyFromPem (USE_ASYM_ALGO, Data, DataSize, NULL, &Context);
    TestSpdmAsymSign (USE_ASYM_ALGO, Context, HashData, GetSpdmHashSize(SpdmContext), Ptr, &SignatureSize);
    TestSpdmAsymFree (USE_ASYM_ALGO, Context);
    free(Data);
    CopyMem (&LocalBuffer[LocalBufferSize], Ptr, SignatureSize);
    LocalBufferSize += SignatureSize;
    AppendManagedBuffer (&THCurr, Ptr, SignatureSize);
    Ptr += SignatureSize;
    SpdmHashAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), THCurrHashData);
    SpdmHmacAll (SpdmContext, mZeroFilledBuffer, HashSize, mZeroFilledBuffer, HashSize, Secret0);
    BinStr0Size = sizeof(BinStr0);
    BinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
    SpdmHkdfExpand (SpdmContext, Secret0, HashSize, BinStr0, BinStr0Size, Salt0, HashSize);
    SpdmHmacAll (SpdmContext, Salt0, HashSize, FinalKey, FinalKeySize, HandshakeSecret);
    BinStr2Size = sizeof(BinStr2);
    BinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL), THCurrHashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
    SpdmHkdfExpand (SpdmContext, HandshakeSecret, HashSize, BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
    SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseHandshakeSecret, HashSize, Ptr);
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
    VOID                          *Context;
    UINT8                         THCurrHashData[64];
    UINT8                         Secret0[64];
    UINT8                         Salt0[64];
    UINT8                         BinStr0[128];
    UINTN                         BinStr0Size;
    UINT8                         BinStr2[128];
    UINTN                         BinStr2Size;
    UINT8                         HandshakeSecret[MAX_HASH_SIZE];
    UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = USE_MEASUREMENT_HASH_ALGO;
    SignatureSize = GetSpdmAsymSize (SpdmContext);
    HashSize = GetSpdmHashSize (SpdmContext);
    HmacSize = GetSpdmHashSize (SpdmContext);
    DheKeySize = GetSpdmDheKeySize (SpdmContext);
    OpaqueKeyExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
    TempBufSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
              DheKeySize +
              HashSize +
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
    SpdmResponse->SlotIDParam = 0;
    SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmResponse->RandomData);
    Ptr = (VOID *)(SpdmResponse + 1);
    DHEContext = SpdmDheNew (SpdmContext);
    SpdmDheGenerateKey (SpdmContext, DHEContext, Ptr, &DheKeySize);
    FinalKeySize = sizeof(FinalKey);
    SpdmDheComputeKey (SpdmContext, DHEContext, (UINT8 *)&LocalBuffer[0] + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DheKeySize, FinalKey, &FinalKeySize);
    SpdmDheFree (SpdmContext, DHEContext);
    Ptr += DheKeySize;
    ZeroMem (Ptr, HashSize);
    Ptr += HashSize;
    *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeRspSize;
    Ptr += sizeof(UINT16);
    SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaqueKeyExchangeRspSize, Ptr);
    Ptr += OpaqueKeyExchangeRspSize;
    ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
    CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);
    // Transcript.MessageA size is 0
    AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
    AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
    SpdmHashAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
    free(Data);
    ReadResponderPrivateCertificate (&Data, &DataSize);
    TestSpdmAsymGetPrivateKeyFromPem (USE_ASYM_ALGO, Data, DataSize, NULL, &Context);
    TestSpdmAsymSign (USE_ASYM_ALGO, Context, HashData, GetSpdmHashSize(SpdmContext), Ptr, &SignatureSize);
    TestSpdmAsymFree (USE_ASYM_ALGO, Context);
    free(Data);
    CopyMem (&LocalBuffer[LocalBufferSize], Ptr, SignatureSize);
    LocalBufferSize += SignatureSize;
    AppendManagedBuffer (&THCurr, Ptr, SignatureSize);
    Ptr += SignatureSize;
    SpdmHashAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), THCurrHashData);
    SpdmHmacAll (SpdmContext, mZeroFilledBuffer, HashSize, mZeroFilledBuffer, HashSize, Secret0);
    BinStr0Size = sizeof(BinStr0);
    BinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
    SpdmHkdfExpand (SpdmContext, Secret0, HashSize, BinStr0, BinStr0Size, Salt0, HashSize);
    SpdmHmacAll (SpdmContext, Salt0, HashSize, FinalKey, FinalKeySize, HandshakeSecret);
    BinStr2Size = sizeof(BinStr2);
    BinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL), THCurrHashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
    SpdmHkdfExpand (SpdmContext, HandshakeSecret, HashSize, BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
    SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseHandshakeSecret, HashSize, Ptr);
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
      VOID                          *Context;
      UINT8                         THCurrHashData[64];
      UINT8                         Secret0[64];
      UINT8                         Salt0[64];
      UINT8                         BinStr0[128];
      UINTN                         BinStr0Size;
      UINT8                         BinStr2[128];
      UINTN                         BinStr2Size;
      UINT8                         HandshakeSecret[MAX_HASH_SIZE];
      UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = USE_MEASUREMENT_HASH_ALGO;
      SignatureSize = GetSpdmAsymSize (SpdmContext);
      HashSize = GetSpdmHashSize (SpdmContext);
      HmacSize = GetSpdmHashSize (SpdmContext);
      DheKeySize = GetSpdmDheKeySize (SpdmContext);
      OpaqueKeyExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
      TempBufSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
              DheKeySize +
              HashSize +
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
      SpdmResponse->SlotIDParam = 0;
      SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmResponse->RandomData);
      Ptr = (VOID *)(SpdmResponse + 1);
      DHEContext = SpdmDheNew (SpdmContext);
      SpdmDheGenerateKey (SpdmContext, DHEContext, Ptr, &DheKeySize);
      FinalKeySize = sizeof(FinalKey);
      SpdmDheComputeKey (SpdmContext, DHEContext, (UINT8 *)&LocalBuffer[0] + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DheKeySize, FinalKey, &FinalKeySize);
      SpdmDheFree (SpdmContext, DHEContext);
      Ptr += DheKeySize;
      ZeroMem (Ptr, HashSize);
      Ptr += HashSize;
      *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeRspSize;
      Ptr += sizeof(UINT16);
      SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaqueKeyExchangeRspSize, Ptr);
      Ptr += OpaqueKeyExchangeRspSize;
      ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
      InternalDumpHex (LocalBuffer, LocalBufferSize);
      InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
      CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);
      // Transcript.MessageA size is 0
      AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
      AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
      SpdmHashAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
      free(Data);
      ReadResponderPrivateCertificate (&Data, &DataSize);
      TestSpdmAsymGetPrivateKeyFromPem (USE_ASYM_ALGO, Data, DataSize, NULL, &Context);
      TestSpdmAsymSign (USE_ASYM_ALGO, Context, HashData, GetSpdmHashSize(SpdmContext), Ptr, &SignatureSize);
      TestSpdmAsymFree (USE_ASYM_ALGO, Context);
      free(Data);
      CopyMem (&LocalBuffer[LocalBufferSize], Ptr, SignatureSize);
      LocalBufferSize += SignatureSize;
      AppendManagedBuffer (&THCurr, Ptr, SignatureSize);
      Ptr += SignatureSize;
      SpdmHashAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), THCurrHashData);
      SpdmHmacAll (SpdmContext, mZeroFilledBuffer, HashSize, mZeroFilledBuffer, HashSize, Secret0);
      BinStr0Size = sizeof(BinStr0);
      BinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
      SpdmHkdfExpand (SpdmContext, Secret0, HashSize, BinStr0, BinStr0Size, Salt0, HashSize);
      SpdmHmacAll (SpdmContext, Salt0, HashSize, FinalKey, FinalKeySize, HandshakeSecret);
      BinStr2Size = sizeof(BinStr2);
      BinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL), THCurrHashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
      SpdmHkdfExpand (SpdmContext, HandshakeSecret, HashSize, BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
      SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseHandshakeSecret, HashSize, Ptr);
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
      VOID                          *Context;
      UINT8                         THCurrHashData[64];
      UINT8                         Secret0[64];
      UINT8                         Salt0[64];
      UINT8                         BinStr0[128];
      UINTN                         BinStr0Size;
      UINT8                         BinStr2[128];
      UINTN                         BinStr2Size;
      UINT8                         HandshakeSecret[MAX_HASH_SIZE];
      UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = USE_MEASUREMENT_HASH_ALGO;
      SignatureSize = GetSpdmAsymSize (SpdmContext);
      HashSize = GetSpdmHashSize (SpdmContext);
      HmacSize = GetSpdmHashSize (SpdmContext);
      DheKeySize = GetSpdmDheKeySize (SpdmContext);
      OpaqueKeyExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
      TempBufSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
              DheKeySize +
              HashSize +
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
      SpdmResponse->SlotIDParam = 0;
      SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmResponse->RandomData);
      Ptr = (VOID *)(SpdmResponse + 1);
      DHEContext = SpdmDheNew (SpdmContext);
      SpdmDheGenerateKey (SpdmContext, DHEContext, Ptr, &DheKeySize);
      FinalKeySize = sizeof(FinalKey);
      SpdmDheComputeKey (SpdmContext, DHEContext, (UINT8 *)&LocalBuffer[0] + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DheKeySize, FinalKey, &FinalKeySize);
      SpdmDheFree (SpdmContext, DHEContext);
      Ptr += DheKeySize;
      ZeroMem (Ptr, HashSize);
      Ptr += HashSize;
      *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeRspSize;
      Ptr += sizeof(UINT16);
      SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaqueKeyExchangeRspSize, Ptr);
      Ptr += OpaqueKeyExchangeRspSize;
      ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
      InternalDumpHex (LocalBuffer, LocalBufferSize);
      InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
      CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);
      // Transcript.MessageA size is 0
      AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
      AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
      SpdmHashAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
      free(Data);
      ReadResponderPrivateCertificate (&Data, &DataSize);
      TestSpdmAsymGetPrivateKeyFromPem (USE_ASYM_ALGO, Data, DataSize, NULL, &Context);
      TestSpdmAsymSign (USE_ASYM_ALGO, Context, HashData, GetSpdmHashSize(SpdmContext), Ptr, &SignatureSize);
      TestSpdmAsymFree (USE_ASYM_ALGO, Context);
      free(Data);
      CopyMem (&LocalBuffer[LocalBufferSize], Ptr, SignatureSize);
      LocalBufferSize += SignatureSize;
      AppendManagedBuffer (&THCurr, Ptr, SignatureSize);
      Ptr += SignatureSize;
      SpdmHashAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), THCurrHashData);
      SpdmHmacAll (SpdmContext, mZeroFilledBuffer, HashSize, mZeroFilledBuffer, HashSize, Secret0);
      BinStr0Size = sizeof(BinStr0);
      BinConcat (BIN_STR_0_LABEL, sizeof(BIN_STR_0_LABEL), NULL, (UINT16)HashSize, HashSize, BinStr0, &BinStr0Size);
      SpdmHkdfExpand (SpdmContext, Secret0, HashSize, BinStr0, BinStr0Size, Salt0, HashSize);
      SpdmHmacAll (SpdmContext, Salt0, HashSize, FinalKey, FinalKeySize, HandshakeSecret);
      BinStr2Size = sizeof(BinStr2);
      BinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL), THCurrHashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
      SpdmHkdfExpand (SpdmContext, HandshakeSecret, HashSize, BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
      SpdmHmacAll (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), ResponseHandshakeSecret, HashSize, Ptr);
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = USE_AEAD_ALGO;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);  
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = USE_AEAD_ALGO;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SessionId, 0xFFFFFFFF);
  assert_int_equal (SpdmContext->SessionInfo[0].SessionState, SpdmStateHandshaking);
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->SpdmCmdReceiveState = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = USE_AEAD_ALGO;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);  
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = USE_AEAD_ALGO;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = USE_AEAD_ALGO;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = USE_AEAD_ALGO;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SessionId, 0xFFFEFFFE);
  assert_int_equal (SpdmContext->SessionInfo[0].SessionState, SpdmStateHandshaking);
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = USE_AEAD_ALGO;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->SpdmCmdReceiveState, 0);
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = USE_AEAD_ALGO;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;  
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = USE_DHE_ALGO; 
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = USE_AEAD_ALGO;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceiveKeyExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             0, &SessionId, &HeartbeatPeriod, &SlotIdParam, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SessionId, 0xFFFDFFFD);
  assert_int_equal (SpdmContext->SessionInfo[0].SessionState, SpdmStateHandshaking);
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
      // SpdmCmdReceiveState check failed
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
