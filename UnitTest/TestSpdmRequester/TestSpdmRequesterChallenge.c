/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

STATIC UINTN                  LocalBufferSize;
STATIC UINT8                  LocalBuffer[MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE];

RETURN_STATUS
EFIAPI
SpdmRequesterChallengeTestSendMessage (
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
  case 0xA:
  case 0xB:
  case 0xC:
  case 0xD:
  case 0xE:
  case 0xF:
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
  case 0x14:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmRequesterChallengeTestReceiveMessage (
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

  case 0x2: //correct CHALLENGE_AUTH message
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponse = (VOID *)TempBuf;
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
    // Ptr += GetSpdmHashSize (mUseHashAlgo);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n", GetSpdmHashSize (mUseHashAlgo)));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x3: //correct CHALLENGE_AUTH message
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponse = (VOID *)TempBuf;
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
    // Ptr += GetSpdmHashSize (mUseHashAlgo);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x4: //correct ERROR message (invalid request)
  {
    SPDM_ERROR_RESPONSE    SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x5: //correct ERROR message (busy)
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x6: //correct ERROR message (busy) + correct CHALLENGE_AUTH message
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
      SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
      VOID                          *Data;
      UINTN                         DataSize;
      UINT8                         *Ptr;
      UINT8                         HashData[MAX_HASH_SIZE];
      UINTN                         SigSize;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
      SpdmResponse = (VOID *)TempBuf;
      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = (1 << 0);
      Ptr = (VOID *)(SpdmResponse + 1);
      SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
      free(Data);
      Ptr += GetSpdmHashSize (mUseHashAlgo);
      SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
      Ptr += SPDM_NONCE_SIZE;
      // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
      // Ptr += GetSpdmHashSize (mUseHashAlgo);
      *(UINT16 *)Ptr = 0;
      Ptr += sizeof(UINT16);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
      SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
      SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
      Ptr += SigSize;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
  }
    return RETURN_SUCCESS;

  case 0x7: //correct ERROR message (request resync)
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x8: //correct ERROR message (response net ready)
  {
    SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.ExtendErrorData.RDTExponent = 1;
    SpdmResponse.ExtendErrorData.RDTM = 1;
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_CHALLENGE;
    SpdmResponse.ExtendErrorData.Token = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x9: //correct ERROR message (response not ready) + correct CHALLENGE_AUTH message
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
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_CHALLENGE;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex2 ++;
    } else if (SubIndex2 == 1) {
      SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
      VOID                          *Data;
      UINTN                         DataSize;
      UINT8                         *Ptr;
      UINT8                         HashData[MAX_HASH_SIZE];
      UINTN                         SigSize;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
      SpdmResponse = (VOID *)TempBuf;
      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = (1 << 0);
      Ptr = (VOID *)(SpdmResponse + 1);
      SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
      free(Data);
      Ptr += GetSpdmHashSize (mUseHashAlgo);
      SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
      Ptr += SPDM_NONCE_SIZE;
      // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
      // Ptr += GetSpdmHashSize (mUseHashAlgo);
      *(UINT16 *)Ptr = 0;
      Ptr += sizeof(UINT16);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
      SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
      SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
      Ptr += SigSize;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
  }
    return RETURN_SUCCESS;

  case 0xA:  //correct CHALLENGE_AUTH message
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
    // Ptr += GetSpdmHashSize (mUseHashAlgo);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xB: //CHALLENGE_AUTH message smaller than a SPDM header
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    SpdmResponse = (VOID *)TempBuf;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) - 1; //smaller than standard message size

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xC: //CHALLENGE_AUTH message with wrong version (1.0)
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              GetSpdmHashSize (mUseHashAlgo) +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10; //wrong version
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
    // Ptr += GetSpdmHashSize (mUseHashAlgo);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xD: //SPDM (mostly CHALLENGE_AUTH) message with wrong response code (0x83)
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE; //wrong response code
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
    // Ptr += GetSpdmHashSize (mUseHashAlgo);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xE:  //correct CHALLENGE_AUTH message with wrong slot number
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 1;
    SpdmResponse->Header.Param2 = (1 << 1); //wrong slot number
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
    // Ptr += GetSpdmHashSize (mUseHashAlgo);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xF: //CHALLENGE_AUTH message with slot number overflow
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 8; //slot number overflow
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
    // Ptr += GetSpdmHashSize (mUseHashAlgo);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x10: //correct CHALLENGE_AUTH message with "openspdm" opaque data
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(UINT16) + 8 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
    // Ptr += GetSpdmHashSize (mUseHashAlgo);
    *(UINT16 *)Ptr = 8;
    Ptr += sizeof(UINT16);
    CopyMem (Ptr, "openspdm", 8);
    Ptr += 8;
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x11: //correct CHALLENGE_AUTH message with invalid signature
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              0 +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    // ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
    // Ptr += GetSpdmHashSize (mUseHashAlgo);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    SpdmHashAll (mUseHashAlgo, HashData, GetSpdmHashSize (mUseHashAlgo), HashData);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, HashData, GetSpdmHashSize (mUseHashAlgo), Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x12:  //correct CHALLENGE_AUTH message
  case 0x13:  //correct CHALLENGE_AUTH message
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (mUseHashAlgo) +
              SPDM_NONCE_SIZE +
              GetSpdmHashSize (mUseHashAlgo) +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponse = (VOID *)TempBuf;
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvision[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.LocalCertChainProvisionSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    ZeroMem (Ptr, GetSpdmHashSize (mUseHashAlgo));
    Ptr += GetSpdmHashSize (mUseHashAlgo);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x14:
  {
    STATIC UINT16 ErrorCode = SPDM_ERROR_CODE_RESERVED_00;

    SPDM_ERROR_RESPONSE    SpdmResponse;

    if(ErrorCode <= 0xff) {
      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = (UINT8) ErrorCode;
      SpdmResponse.Header.Param2 = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }

    ErrorCode++;
    if(ErrorCode == SPDM_ERROR_CODE_BUSY) { //busy is treated in cases 5 and 6
      ErrorCode = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
    }
    if(ErrorCode == SPDM_ERROR_CODE_RESERVED_0D) { //skip some reserved error codes (0d to 3e)
      ErrorCode = SPDM_ERROR_CODE_RESERVED_3F;
    }
    if(ErrorCode == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { //skip response not ready, request resync, and some reserved codes (44 to fc)
      ErrorCode = SPDM_ERROR_CODE_RESERVED_FD;
    }
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

/**
  Test 1: when no CHALLENGE_AUTH message is received, and the client returns a
  device error.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterChallengeCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

/**
  Test 2: the requester is setup correctly to send a CHALLENGE message:
  - it has flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, and the use of challenges.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (Param1=0) and do not request measurements (Param2=0).
  The received CHALLENGE_AUTH message correctly responds to the challenge, with
  no opaque data and a signature on the sent nonce.
  Expected behavior: client returns a Status of RETURN_SUCCESS.
**/
void TestSpdmRequesterChallengeCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  free(Data);
}

/**
  Test 3: the requester is not setup correctly to send a CHALLENGE message:
  - it has *no* flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, GET_DIGESTS); but
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, and the use of challenges.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (Param1=0) and do not request measurements (Param2=0).
  The received CHALLENGE_AUTH message correctly responds to the challenge, with
  no opaque data and a signature on the sent nonce.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the "C"
  transcript buffer is not set.
**/
void TestSpdmRequesterChallengeCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_UNSUPPORTED);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

/**
  Test 4: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating InvalidParameters.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the "C"
  transcript buffer is reset.
**/
void TestSpdmRequesterChallengeCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

/**
  Test 5: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating the Busy status of the responder.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the "C"
  transcript buffer is reset.
**/
void TestSpdmRequesterChallengeCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

/**
  Test 6: the requester is setup correctly (see Test 2), but, on the first try,
  receiving a Busy ERROR message, and on retry, receiving a correct CHALLENGE_AUTH
  message to the challenge, with no opaque data and a signature on the sent nonce.
  Expected behavior: client returns a Status of RETURN_SUCCESS.
**/
void TestSpdmRequesterChallengeCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  free(Data);
}

/**
  Test 7: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating the RequestResynch status of the responder.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, the "C"
  transcript buffer is reset, and the communication is reset to expect a new
  GET_VERSION message.
**/
void TestSpdmRequesterChallengeCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->ConnectionInfo.ConnectionState, SpdmConnectionStateNotStarted);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

/**
  Test 8: the requester is setup correctly (see Test 2), but receives an ERROR
  message indicating the ResponseNotReady status of the responder.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the "C"
  buffer stores only the request.
**/
void TestSpdmRequesterChallengeCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 4 + SPDM_NONCE_SIZE);
  free(Data);
}

/**
  Test 9: the requester is setup correctly (see Test 2), but, on the first try,
  receiving a ResponseNotReady ERROR message, and on retry, receiving a correct
  CHALLENGE_AUTH message to the challenge, with no opaque data and a signature
  on the sent nonce.
  Expected behavior: client returns a Status of RETURN_SUCCESS.
**/
void TestSpdmRequesterChallengeCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  free(Data);
}

/**
  Test 10: the requester is not setup correctly to send a CHALLENGE message.
  Specifically, it has *not* received the capability for challenge, although it
  has received capability for executing both hash and signature algorithms.
  The remaining setup and message exchange were executed correctly (see Test 2).
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the "C"
  transcript buffer is not set.
**/
void TestSpdmRequesterChallengeCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  // SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_UNSUPPORTED);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

/**
  Test 11: the requester is setup correctly (see Test 2), but receives a malformed
  response message, smaller then a standard SPDM message header.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR,.
**/
void TestSpdmRequesterChallengeCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xB;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

/**
  Test 12: the requester is setup correctly (see Test 2), but receives a malformed
  response message, with version (1.0) different from the request (1.1).
  The remaining message data is as a correct CHALLENGE_AUTH message.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterChallengeCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xC;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

/**
  Test 13: the requester is setup correctly (see Test 2), but receives a malformed
  response message, with wrong RequestResponseCode (CHALLENGE 0x83 instead of
  CHALLENGE_AUTH 0x03).
  The remaining message data is as a correct CHALLENGE_AUTH message.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterChallengeCase13(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xD;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

/**
  Test 14: the requester is setup correctly (see Test 2), but receives a malformed
  response message, with a slot number different from the requested.
  The remaining message data is as a correct CHALLENGE_AUTH message.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterChallengeCase14(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xE;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

/**
  Test 15: the requester is not setup correctly to send a CHALLENGE message.
  Specifically, it attemps to request a certificate at a slot number larger than
  the one supported by the specification.
  The remaining setup and message exchange were executed correctly (see Test 2).
  Expected behavior: client returns a Status of RETURN_INVALID_PARAMETER.
**/
void TestSpdmRequesterChallengeCase15(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xF;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, MAX_SPDM_SLOT_COUNT, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_INVALID_PARAMETER);;
  free(Data);
}

/**
  Test 16: the requester is setup correctly to send a CHALLENGE message:
  - it has flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, and the use of challenges.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (Param1=0) and do not request measurements (Param2=0).
  The received CHALLENGE_AUTH message correctly responds to the challenge, opaque
  data with bytes from the string "openspdm", and a signature on the sent nonce.
  Expected behavior: client returns a Status of RETURN_SUCCESS.
**/
void TestSpdmRequesterChallengeCase16(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x10;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  free(Data);
}

/**
  Test 17: the requester is setup correctly to send a CHALLENGE message:
  - it has flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, and the use of challenges.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (Param1=0) and do not request measurements (Param2=0).
  The received CHALLENGE_AUTH message correctly responds to the challenge, 
  but with an invalid signature.
  Expected behavior: client returns a Status of RETURN_SECURITY_VIOLATION.
**/
void TestSpdmRequesterChallengeCase17(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x11;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  free(Data);
}

/**
  Test 18: the requester is setup correctly to send a CHALLENGE message:
  - it has flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, the use of challenges, and of measurements.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (Param1=0) and request TCB measurements (Param2=1).
  The received CHALLENGE_AUTH message correctly responds to the challenge, with
  no opaque data and a signature on the sent nonce.
  Expected behavior: client returns a Status of RETURN_SUCCESS.
**/
void TestSpdmRequesterChallengeCase18(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x12;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; //additional measurement capability
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
}

/**
  Test 19: the requester is setup correctly to send a CHALLENGE message:
  - it has flags indicating that the previous messages were sent
  (GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, and GET_DIGESTS).
  - it received the CAPABILITIES message, allowing the use of hash and digital
  signature algorithms, the use of challenges, and of measurements.
  - it has the responder's certificate chain.
  The CHALLENGE message requests usage of the first certificate in the chain
  (Param1=0) and request TCB measurements (Param2=1).
  The received CHALLENGE_AUTH message correctly responds to the challenge, with
  no opaque data and a signature on the sent nonce.
  Expected behavior: client returns a Status of RETURN_SUCCESS.
**/
void TestSpdmRequesterChallengeCase19(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x13;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP; //additional measurement capability
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
}

/**
  Test 20: receiving an unexpected ERROR message from the responder.
  There are tests for all named codes, including some reserved ones
  (namely, 0x00, 0x0b, 0x0c, 0x3f, 0xfd, 0xfe).
  However, for having specific test cases, it is excluded from this case:
  Busy (0x03), ResponseNotReady (0x42), and RequestResync (0x43).
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterChallengeCase20(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                MeasurementHash[MAX_HASH_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  UINT16                ErrorCode;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x14;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);

  ErrorCode = SPDM_ERROR_CODE_RESERVED_00;
  while(ErrorCode <= 0xff) {
    SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
    SpdmContext->Transcript.MessageA.BufferSize = 0;
    SpdmContext->Transcript.MessageB.BufferSize = 0;
    SpdmContext->Transcript.MessageC.BufferSize = 0;

    ZeroMem (MeasurementHash, sizeof(MeasurementHash));
    Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
    // assert_int_equal (Status, RETURN_DEVICE_ERROR);
    // assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
    ASSERT_INT_EQUAL_CASE (Status, RETURN_DEVICE_ERROR, ErrorCode);
    ASSERT_INT_EQUAL_CASE (SpdmContext->Transcript.MessageC.BufferSize, 0, ErrorCode);

    ErrorCode++;
    if(ErrorCode == SPDM_ERROR_CODE_BUSY) { //busy is treated in cases 5 and 6
      ErrorCode = SPDM_ERROR_CODE_UNEXPECTED_REQUEST;
    }
    if(ErrorCode == SPDM_ERROR_CODE_RESERVED_0D) { //skip some reserved error codes (0d to 3e)
      ErrorCode = SPDM_ERROR_CODE_RESERVED_3F;
    }
    if(ErrorCode == SPDM_ERROR_CODE_RESPONSE_NOT_READY) { //skip response not ready, request resync, and some reserved codes (44 to fc)
      ErrorCode = SPDM_ERROR_CODE_RESERVED_FD;
    }
  }

  free(Data);
}

SPDM_TEST_CONTEXT       mSpdmRequesterChallengeTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterChallengeTestSendMessage,
  SpdmRequesterChallengeTestReceiveMessage,
};

int SpdmRequesterChallengeTestMain(void) {
  const struct CMUnitTest SpdmRequesterChallengeTests[] = {
      // SendRequest failed
      cmocka_unit_test(TestSpdmRequesterChallengeCase1),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterChallengeCase2),
      // SpdmCmdReceiveState check failed
      cmocka_unit_test(TestSpdmRequesterChallengeCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterChallengeCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterChallengeCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterChallengeCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterChallengeCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterChallengeCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterChallengeCase9),
      // SpdmCmdReceiveState check failed
      cmocka_unit_test(TestSpdmRequesterChallengeCase10),
      // Successful response + device error
      cmocka_unit_test(TestSpdmRequesterChallengeCase11),
      cmocka_unit_test(TestSpdmRequesterChallengeCase12),
      cmocka_unit_test(TestSpdmRequesterChallengeCase13),
      cmocka_unit_test(TestSpdmRequesterChallengeCase14),
      // Invalid parameter
      cmocka_unit_test(TestSpdmRequesterChallengeCase15),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterChallengeCase16),
      // Signature check failed
      cmocka_unit_test(TestSpdmRequesterChallengeCase17),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterChallengeCase18),
      cmocka_unit_test(TestSpdmRequesterChallengeCase19),
      // Unexpected errors
      cmocka_unit_test(TestSpdmRequesterChallengeCase20),
  };

  SetupSpdmTestContext (&mSpdmRequesterChallengeTestContext);

  return cmocka_run_group_tests(SpdmRequesterChallengeTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
