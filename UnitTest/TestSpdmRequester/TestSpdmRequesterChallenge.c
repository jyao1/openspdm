/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>
#include "SpdmTest.h"

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

  case 0x2:
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;  
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    VOID                          *Context;
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChainSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChain[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (SpdmContext) +
              SPDM_NONCE_SIZE +
              GetSpdmHashSize (SpdmContext) +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSize (SpdmContext);
    SpdmResponse = (VOID *)TempBuf;
    
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (SpdmContext, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChain[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChainSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (SpdmContext);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    ZeroMem (Ptr, GetSpdmHashSize (SpdmContext));
    Ptr += GetSpdmHashSize (SpdmContext);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmHashAll (SpdmContext, LocalBuffer, LocalBufferSize, HashData);
    DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n", GetSpdmHashSize(SpdmContext)));
    InternalDumpHex (HashData, GetSpdmHashSize(SpdmContext));
    SigSize = GetSpdmAsymSize (SpdmContext);
    ReadResponderPrivateCertificate (&Data, &DataSize);
    TestSpdmAsymGetPrivateKeyFromPem (USE_ASYM_ALGO, Data, DataSize, NULL, &Context);
    TestSpdmAsymSign (USE_ASYM_ALGO, Context, HashData, GetSpdmHashSize(SpdmContext), Ptr, &SigSize);
    TestSpdmAsymFree (USE_ASYM_ALGO, Context);
    Ptr += SigSize;
    free(Data);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
    VOID                          *Data;
    UINTN                         DataSize;  
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    VOID                          *Context;
    UINTN                         SigSize;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChainSize[0] = DataSize;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChain[0] = Data;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
    TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (SpdmContext) +
              SPDM_NONCE_SIZE +
              GetSpdmHashSize (SpdmContext) +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSize (SpdmContext);
    SpdmResponse = (VOID *)TempBuf;
    
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = (1 << 0);
    Ptr = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (SpdmContext, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChain[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChainSize[0], Ptr);
    free(Data);
    Ptr += GetSpdmHashSize (SpdmContext);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    ZeroMem (Ptr, GetSpdmHashSize (SpdmContext));
    Ptr += GetSpdmHashSize (SpdmContext);
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    SpdmHashAll (SpdmContext, LocalBuffer, LocalBufferSize, HashData);
    SigSize = GetSpdmAsymSize (SpdmContext);
    ReadResponderPrivateCertificate (&Data, &DataSize);
    TestSpdmAsymGetPrivateKeyFromPem (USE_ASYM_ALGO, Data, DataSize, NULL, &Context);
    TestSpdmAsymSign (USE_ASYM_ALGO, Context, HashData, GetSpdmHashSize(SpdmContext), Ptr, &SigSize);
    TestSpdmAsymFree (USE_ASYM_ALGO, Context);
    Ptr += SigSize;
    free(Data);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x4:
  {
    SPDM_ERROR_RESPONSE    SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x5:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x6:
  {
    STATIC UINTN SubIndex1 = 0;
    if (SubIndex1 == 0) {
      SPDM_ERROR_RESPONSE  SpdmResponse;

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
      SpdmResponse.Header.Param2 = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex1 ++;
    } else if (SubIndex1 == 1) {
      SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
      VOID                          *Data;
      UINTN                         DataSize;  
      UINT8                         *Ptr;
      UINT8                         HashData[MAX_HASH_SIZE];
      VOID                          *Context;
      UINTN                         SigSize;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChainSize[0] = DataSize;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChain[0] = Data;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
      TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (SpdmContext) +
              SPDM_NONCE_SIZE +
              GetSpdmHashSize (SpdmContext) +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSize (SpdmContext);
      SpdmResponse = (VOID *)TempBuf;
    
      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = (1 << 0);
      Ptr = (VOID *)(SpdmResponse + 1);
      SpdmHashAll (SpdmContext, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChain[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChainSize[0], Ptr);
      free(Data);
      Ptr += GetSpdmHashSize (SpdmContext);
      SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
      Ptr += SPDM_NONCE_SIZE;
      ZeroMem (Ptr, GetSpdmHashSize (SpdmContext));
      Ptr += GetSpdmHashSize (SpdmContext);
      *(UINT16 *)Ptr = 0;
      Ptr += sizeof(UINT16);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      SpdmHashAll (SpdmContext, LocalBuffer, LocalBufferSize, HashData);
      SigSize = GetSpdmAsymSize (SpdmContext);
      ReadResponderPrivateCertificate (&Data, &DataSize);
      TestSpdmAsymGetPrivateKeyFromPem (USE_ASYM_ALGO, Data, DataSize, NULL, &Context);
      TestSpdmAsymSign (USE_ASYM_ALGO, Context, HashData, GetSpdmHashSize(SpdmContext), Ptr, &SigSize);
      TestSpdmAsymFree (USE_ASYM_ALGO, Context);
      Ptr += SigSize;
      free(Data);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
  }
    return RETURN_SUCCESS;

  case 0x7:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x8:
  {
    SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.ExtendErrorData.RDTExponent = 1;
    SpdmResponse.ExtendErrorData.RDTM = 1;
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_CHALLENGE;
    SpdmResponse.ExtendErrorData.Token = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x9:
  {
    STATIC UINTN SubIndex2 = 0;
    if (SubIndex2 == 0) {
      SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.ExtendErrorData.RDTExponent = 1;
      SpdmResponse.ExtendErrorData.RDTM = 1;
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_CHALLENGE;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex2 ++;
    } else if (SubIndex2 == 1) {
      SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
      VOID                          *Data;
      UINTN                         DataSize;  
      UINT8                         *Ptr;
      UINT8                         HashData[MAX_HASH_SIZE];
      VOID                          *Context;
      UINTN                         SigSize;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChainSize[0] = DataSize;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChain[0] = Data;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = USE_ASYM_ALGO;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
      TempBufSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              GetSpdmHashSize (SpdmContext) +
              SPDM_NONCE_SIZE +
              GetSpdmHashSize (SpdmContext) +
              sizeof(UINT16) + 0 +
              GetSpdmAsymSize (SpdmContext);
      SpdmResponse = (VOID *)TempBuf;
    
      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = (1 << 0);
      Ptr = (VOID *)(SpdmResponse + 1);
      SpdmHashAll (SpdmContext, ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChain[0], ((SPDM_DEVICE_CONTEXT*)SpdmContext)->LocalContext.CertificateChainSize[0], Ptr);
      free(Data);
      Ptr += GetSpdmHashSize (SpdmContext);
      SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
      Ptr += SPDM_NONCE_SIZE;
      ZeroMem (Ptr, GetSpdmHashSize (SpdmContext));
      Ptr += GetSpdmHashSize (SpdmContext);
      *(UINT16 *)Ptr = 0;
      Ptr += sizeof(UINT16);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      SpdmHashAll (SpdmContext, LocalBuffer, LocalBufferSize, HashData);
      SigSize = GetSpdmAsymSize (SpdmContext);
      ReadResponderPrivateCertificate (&Data, &DataSize);
      TestSpdmAsymGetPrivateKeyFromPem (USE_ASYM_ALGO, Data, DataSize, NULL, &Context);
      TestSpdmAsymSign (USE_ASYM_ALGO, Context, HashData, GetSpdmHashSize(SpdmContext), Ptr, &SigSize);
      TestSpdmAsymFree (USE_ASYM_ALGO, Context);
      Ptr += SigSize;
      free(Data);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.M1M2.BufferSize, 0);
  free(Data);
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->SpdmCmdReceiveState = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  
  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.M1M2.BufferSize, 0);
  free(Data);
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->SpdmCmdReceiveState, 0);
  assert_int_equal (SpdmContext->Transcript.MessageC.BufferSize, 0);
  free(Data);
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->Transcript.MessageC.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);

  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmChallenge (SpdmContext, 0, SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, MeasurementHash);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.M1M2.BufferSize, 0);
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
  };
  
  SetupSpdmTestContext (&mSpdmRequesterChallengeTestContext);

  return cmocka_run_group_tests(SpdmRequesterChallengeTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
