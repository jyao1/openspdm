/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

#define BIN_STR_2_LABEL       "rsp hs data"
#define BIN_STR_7_LABEL       "finished"

STATIC UINTN                  LocalBufferSize;
STATIC UINT8                  LocalBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
STATIC UINT8                  LocalPskHint[32];

UINTN
SpdmTestGetPskExchangeRequestSize (
  IN VOID    *SpdmContext,
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{ 
  SPDM_PSK_EXCHANGE_REQUEST  *SpdmRequest;
  UINTN                      MessageSize;

  SpdmRequest = Buffer;
  MessageSize = sizeof(SPDM_MESSAGE_HEADER);
  if (BufferSize < MessageSize) {
    return BufferSize;
  }

  if (SpdmRequest->Header.RequestResponseCode != SPDM_PSK_EXCHANGE) {
    return BufferSize;
  }

  MessageSize = sizeof(SPDM_PSK_EXCHANGE_REQUEST);
  if (BufferSize < MessageSize) {
    return BufferSize;
  }

  MessageSize += SpdmRequest->PSKHintLength + SpdmRequest->RequesterContextLength + SpdmRequest->OpaqueLength;
  if (BufferSize < MessageSize) {
    return BufferSize;
  }

  // Good message, return actual size
  return MessageSize;
}

RETURN_STATUS
EFIAPI
SpdmRequesterPskExchangeTestSendMessage (
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
    MessageSize = SpdmTestGetPskExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x3:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetPskExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x4:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetPskExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x5:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetPskExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x6:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetPskExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x7:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetPskExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x8:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetPskExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x9:
  {
    STATIC UINTN SubIndex = 0;
    if (SubIndex == 0) {
      LocalBufferSize = 0;
      MessageSize = SpdmTestGetPskExchangeRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
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
SpdmRequesterPskExchangeTestReceiveMessage (
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
    SPDM_PSK_EXCHANGE_RESPONSE    *SpdmResponse; 
    UINT32                        HashSize;
    UINT32                        HmacSize;
    UINT8                         *Ptr;
    UINTN                         OpaquePskExchangeRspSize;
    VOID                          *Data;
    UINTN                         DataSize; 
    UINT8                         HashData[MAX_HASH_SIZE];
    UINT8                         *CertBuffer;
    UINTN                         CertBufferSize;
    UINT8                         CertBufferHash[MAX_HASH_SIZE];
    LARGE_MANAGED_BUFFER          THCurr;
    UINT8                         BinStr2[128];
    UINTN                         BinStr2Size;
    UINT8                         BinStr7[128];
    UINTN                         BinStr7Size;
    UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
    UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    HashSize = GetSpdmHashSize (mUseHashAlgo);
    HmacSize = GetSpdmHashSize (mUseHashAlgo);
    OpaquePskExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
    TempBufSize = sizeof(SPDM_PSK_EXCHANGE_RESPONSE) +
              0 +
              DEFAULT_CONTEXT_LENGTH +
              OpaquePskExchangeRspSize +
              HmacSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_PSK_EXCHANGE_RSP;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->RspSessionID = SpdmAllocateRspSessionId (SpdmContext);
    SpdmResponse->Reserved = 0;
    SpdmResponse->ResponderContextLength = DEFAULT_CONTEXT_LENGTH;
    SpdmResponse->OpaqueLength = (UINT16)OpaquePskExchangeRspSize;
    Ptr = (VOID *)(SpdmResponse + 1);
    // ZeroMem (Ptr, HashSize);
    // Ptr += HashSize;
    SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
    Ptr += DEFAULT_CONTEXT_LENGTH;
    SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaquePskExchangeRspSize, Ptr);
    Ptr += OpaquePskExchangeRspSize;
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
    // Transcript.MessageA size is 0
    AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
    free(Data);
    BinStr2Size = sizeof(BinStr2);
    SpdmBinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1, HashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
    ZeroMem (LocalPskHint, 32);
    CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    SpdmPskHandshakeSecretHkdfExpandFunc (mUseHashAlgo, LocalPskHint, sizeof(TEST_PSK_HINT_STRING), BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
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
    SPDM_PSK_EXCHANGE_RESPONSE    *SpdmResponse; 
    UINT32                        HashSize;
    UINT32                        HmacSize;
    UINT8                         *Ptr;
    UINTN                         OpaquePskExchangeRspSize;
    VOID                          *Data;
    UINTN                         DataSize; 
    UINT8                         HashData[MAX_HASH_SIZE];
    UINT8                         *CertBuffer;
    UINTN                         CertBufferSize;
    UINT8                         CertBufferHash[MAX_HASH_SIZE];
    LARGE_MANAGED_BUFFER          THCurr;
    UINT8                         BinStr2[128];
    UINTN                         BinStr2Size;
    UINT8                         BinStr7[128];
    UINTN                         BinStr7Size;
    UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
    UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    HashSize = GetSpdmHashSize (mUseHashAlgo);
    HmacSize = GetSpdmHashSize (mUseHashAlgo);
    OpaquePskExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
    TempBufSize = sizeof(SPDM_PSK_EXCHANGE_RESPONSE) +
              0 +
              DEFAULT_CONTEXT_LENGTH +
              OpaquePskExchangeRspSize +
              HmacSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_PSK_EXCHANGE_RSP;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->RspSessionID = SpdmAllocateRspSessionId (SpdmContext);
    SpdmResponse->Reserved = 0;
    SpdmResponse->ResponderContextLength = DEFAULT_CONTEXT_LENGTH;
    SpdmResponse->OpaqueLength = (UINT16)OpaquePskExchangeRspSize;
    Ptr = (VOID *)(SpdmResponse + 1);
    // ZeroMem (Ptr, HashSize);
    // Ptr += HashSize;
    SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
    Ptr += DEFAULT_CONTEXT_LENGTH;
    SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaquePskExchangeRspSize, Ptr);
    Ptr += OpaquePskExchangeRspSize;
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
    SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
    // Transcript.MessageA size is 0
    AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
    free(Data);
    BinStr2Size = sizeof(BinStr2);
    SpdmBinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1, HashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
    ZeroMem (LocalPskHint, 32);
    CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    SpdmPskHandshakeSecretHkdfExpandFunc (mUseHashAlgo, LocalPskHint, sizeof(TEST_PSK_HINT_STRING), BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
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
      SPDM_PSK_EXCHANGE_RESPONSE    *SpdmResponse; 
      UINT32                        HashSize;
      UINT32                        HmacSize;
      UINT8                         *Ptr;
      UINTN                         OpaquePskExchangeRspSize;
      VOID                          *Data;
      UINTN                         DataSize; 
      UINT8                         HashData[MAX_HASH_SIZE];
      UINT8                         *CertBuffer;
      UINTN                         CertBufferSize;
      UINT8                         CertBufferHash[MAX_HASH_SIZE];
      LARGE_MANAGED_BUFFER          THCurr;
      UINT8                         BinStr2[128];
      UINTN                         BinStr2Size;
      UINT8                         BinStr7[128];
      UINTN                         BinStr7Size;
      UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
      UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
      HashSize = GetSpdmHashSize (mUseHashAlgo);
      HmacSize = GetSpdmHashSize (mUseHashAlgo);
      OpaquePskExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
      TempBufSize = sizeof(SPDM_PSK_EXCHANGE_RESPONSE) +
              0 +
              DEFAULT_CONTEXT_LENGTH +
              OpaquePskExchangeRspSize +
              HmacSize;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse->Header.RequestResponseCode = SPDM_PSK_EXCHANGE_RSP;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->RspSessionID = SpdmAllocateRspSessionId (SpdmContext);
      SpdmResponse->Reserved = 0;
      SpdmResponse->ResponderContextLength = DEFAULT_CONTEXT_LENGTH;
      SpdmResponse->OpaqueLength = (UINT16)OpaquePskExchangeRspSize;
      Ptr = (VOID *)(SpdmResponse + 1);
      // ZeroMem (Ptr, HashSize);
      // Ptr += HashSize;
      SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
      Ptr += DEFAULT_CONTEXT_LENGTH;
      SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaquePskExchangeRspSize, Ptr);
      Ptr += OpaquePskExchangeRspSize;
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
      InternalDumpHex (LocalBuffer, LocalBufferSize);
      InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
      ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
      CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
      // Transcript.MessageA size is 0
      AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
      SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
      free(Data);
      BinStr2Size = sizeof(BinStr2);
      SpdmBinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1, HashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
      ZeroMem (LocalPskHint, 32);
      CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
      SpdmPskHandshakeSecretHkdfExpandFunc (mUseHashAlgo, LocalPskHint, sizeof(TEST_PSK_HINT_STRING), BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
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
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_PSK_EXCHANGE;
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
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_PSK_EXCHANGE;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex2 ++;
    } else if (SubIndex2 == 1) {
      SPDM_PSK_EXCHANGE_RESPONSE    *SpdmResponse; 
      UINT32                        HashSize;
      UINT32                        HmacSize;
      UINT8                         *Ptr;
      UINTN                         OpaquePskExchangeRspSize;
      VOID                          *Data;
      UINTN                         DataSize; 
      UINT8                         HashData[MAX_HASH_SIZE];
      UINT8                         *CertBuffer;
      UINTN                         CertBufferSize;
      UINT8                         CertBufferHash[MAX_HASH_SIZE];
      LARGE_MANAGED_BUFFER          THCurr;
      UINT8                         BinStr2[128];
      UINTN                         BinStr2Size;
      UINT8                         BinStr7[128];
      UINTN                         BinStr7Size;
      UINT8                         ResponseHandshakeSecret[MAX_HASH_SIZE];
      UINT8                         ResponseFinishedKey[MAX_HASH_SIZE];
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
      HashSize = GetSpdmHashSize (mUseHashAlgo);
      HmacSize = GetSpdmHashSize (mUseHashAlgo);
      OpaquePskExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
      TempBufSize = sizeof(SPDM_PSK_EXCHANGE_RESPONSE) +
              0 +
              DEFAULT_CONTEXT_LENGTH +
              OpaquePskExchangeRspSize +
              HmacSize;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse->Header.RequestResponseCode = SPDM_PSK_EXCHANGE_RSP;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->RspSessionID = SpdmAllocateRspSessionId (SpdmContext);
      SpdmResponse->Reserved = 0;
      SpdmResponse->ResponderContextLength = DEFAULT_CONTEXT_LENGTH;
      SpdmResponse->OpaqueLength = (UINT16)OpaquePskExchangeRspSize;
      Ptr = (VOID *)(SpdmResponse + 1);
      // ZeroMem (Ptr, HashSize);
      // Ptr += HashSize;
      SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
      Ptr += DEFAULT_CONTEXT_LENGTH;
      SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaquePskExchangeRspSize, Ptr);
      Ptr += OpaquePskExchangeRspSize;
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
      InternalDumpHex (LocalBuffer, LocalBufferSize);
      InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
      ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
      CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
      CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
      SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
      // Transcript.MessageA size is 0
      AppendManagedBuffer (&THCurr, LocalBuffer, LocalBufferSize);
      SpdmHashAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), HashData);
      free(Data);
      BinStr2Size = sizeof(BinStr2);
      SpdmBinConcat (BIN_STR_2_LABEL, sizeof(BIN_STR_2_LABEL) - 1, HashData, (UINT16)HashSize, HashSize, BinStr2, &BinStr2Size);
      ZeroMem (LocalPskHint, 32);
      CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
      SpdmPskHandshakeSecretHkdfExpandFunc (mUseHashAlgo, LocalPskHint, sizeof(TEST_PSK_HINT_STRING), BinStr2, BinStr2Size, ResponseHandshakeSecret, HashSize);
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

void TestSpdmRequesterPskExchangeCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE]; 
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceivePskExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           &SessionId, &HeartbeatPeriod, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterPskExchangeCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;
  
  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceivePskExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           &SessionId, &HeartbeatPeriod, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SessionId, 0xFFFFFFFF);
  assert_int_equal (SpdmSecuredMessageGetSessionState (SpdmContext->SessionInfo[0].SecuredMessageContext), SpdmSessionStateHandshaking);
  free(Data);
}

void TestSpdmRequesterPskExchangeCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;
  
  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceivePskExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           &SessionId, &HeartbeatPeriod, MeasurementHash);
  assert_int_equal (Status, RETURN_UNSUPPORTED);  
  free(Data);
}

void TestSpdmRequesterPskExchangeCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;
  
  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceivePskExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           &SessionId, &HeartbeatPeriod, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterPskExchangeCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceivePskExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           &SessionId, &HeartbeatPeriod, MeasurementHash);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  free(Data);
}

void TestSpdmRequesterPskExchangeCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceivePskExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           &SessionId, &HeartbeatPeriod, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SessionId, 0xFFFEFFFE);
  assert_int_equal (SpdmSecuredMessageGetSessionState (SpdmContext->SessionInfo[0].SecuredMessageContext), SpdmSessionStateHandshaking);
  free(Data);
}

void TestSpdmRequesterPskExchangeCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceivePskExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           &SessionId, &HeartbeatPeriod, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->ConnectionInfo.ConnectionState, SpdmConnectionStateNotStarted);
  free(Data);
}

void TestSpdmRequesterPskExchangeCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceivePskExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           &SessionId, &HeartbeatPeriod, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterPskExchangeCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT32               SessionId;
  UINT8                HeartbeatPeriod;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmSendReceivePskExchange (SpdmContext, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
           &SessionId, &HeartbeatPeriod, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SessionId, 0xFFFDFFFD);
  assert_int_equal (SpdmSecuredMessageGetSessionState (SpdmContext->SessionInfo[0].SecuredMessageContext), SpdmSessionStateHandshaking);
  free(Data);
}

SPDM_TEST_CONTEXT       mSpdmRequesterPskExchangeTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterPskExchangeTestSendMessage,
  SpdmRequesterPskExchangeTestReceiveMessage,
};

int SpdmRequesterPskExchangeTestMain(void) {
  const struct CMUnitTest SpdmRequesterPskExchangeTests[] = {
      // SendRequest failed
      cmocka_unit_test(TestSpdmRequesterPskExchangeCase1),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterPskExchangeCase2),
      // ConnectionState check failed
      cmocka_unit_test(TestSpdmRequesterPskExchangeCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterPskExchangeCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterPskExchangeCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterPskExchangeCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterPskExchangeCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterPskExchangeCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterPskExchangeCase9),
  };
  
  SetupSpdmTestContext (&mSpdmRequesterPskExchangeTestContext);

  return cmocka_run_group_tests(SpdmRequesterPskExchangeTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
