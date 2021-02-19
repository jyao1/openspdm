/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

STATIC UINT8                  LocalCertificateChain[MAX_SPDM_MESSAGE_BUFFER_SIZE];

RETURN_STATUS
EFIAPI
SpdmRequesterGetDigestTestSendMessage (
  IN     VOID                    *SpdmContext,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = GetSpdmTestContext ();
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;
  case 0x2:
    return RETURN_SUCCESS;
  case 0x3:
    return RETURN_SUCCESS;
  case 0x4:
    return RETURN_SUCCESS;
  case 0x5:
    return RETURN_SUCCESS;
  case 0x6:
    return RETURN_SUCCESS;
  case 0x7:
    return RETURN_SUCCESS;
  case 0x8:
    return RETURN_SUCCESS;
  case 0x9:
    return RETURN_SUCCESS;
  case 0xA:
    return RETURN_SUCCESS;
  case 0xB:
    return RETURN_SUCCESS;
  case 0xC:
    return RETURN_SUCCESS;
  case 0xD:
    return RETURN_SUCCESS;
  case 0xE:
    return RETURN_SUCCESS;
  case 0xF:
    return RETURN_SUCCESS;
  case 0x10:
    return RETURN_SUCCESS;
  case 0x11:
    return RETURN_SUCCESS;
  case 0x12:
    return RETURN_SUCCESS;
  case 0x13:
    return RETURN_SUCCESS;
  case 0x14:
    return RETURN_SUCCESS;
  case 0x15:
    return RETURN_SUCCESS;
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmRequesterGetDigestTestReceiveMessage (
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
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    UINT8                    *Digest;
    UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                    TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (mUseHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

    Digest = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
    SpdmResponse->Header.Param2 |= (1 << 0);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    UINT8                    *Digest;
    UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                    TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (mUseHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

    Digest = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
    SpdmResponse->Header.Param2 |= (1 << 0);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x4:
  {
    SPDM_ERROR_RESPONSE    SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x5:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
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

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
      SpdmResponse.Header.Param2 = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    } else if (SubIndex1 == 1) {
      SPDM_DIGESTS_RESPONSE    *SpdmResponse;
      UINT8                    *Digest;
      UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                    TempBufSize;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (mUseHashAlgo);
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
      SpdmResponse->Header.Param2 = 0;
      SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

      Digest = (VOID *)(SpdmResponse + 1);
      SpdmHashAll (mUseHashAlgo, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
      SpdmResponse->Header.Param2 |= (1 << 0);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
    SubIndex1 ++;
  }
    return RETURN_SUCCESS;

  case 0x7:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
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
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_GET_DIGESTS;
    SpdmResponse.ExtendErrorData.Token = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
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
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_GET_DIGESTS;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    } else if (SubIndex2 == 1) {
      SPDM_DIGESTS_RESPONSE    *SpdmResponse;
      UINT8                    *Digest;
      UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                    TempBufSize;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (mUseHashAlgo);
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
      SpdmResponse->Header.Param2 = 0;
      SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

      Digest = (VOID *)(SpdmResponse + 1);
      SpdmHashAll (mUseHashAlgo, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
      SpdmResponse->Header.Param2 |= (1 << 0);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
    SubIndex2 ++;
  }
    return RETURN_SUCCESS;

  case 0xA:
    return RETURN_SUCCESS;

  case 0xB:
    return RETURN_DEVICE_ERROR;

  case 0xC:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                    TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = 2;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xD:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    UINT8                    *Digest;
    UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                    TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (mUseHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_CERTIFICATE;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

    Digest = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
    SpdmResponse->Header.Param2 |= (1 << 0);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xE:
  {
    SPDM_DIGESTS_RESPONSE    SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xF:
    return RETURN_SUCCESS;

  case 0x10:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    UINT8                    *Digest;
    UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                    TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (mUseHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

    Digest = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
    SpdmResponse->Header.Param2 |= (1 << 0);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x11:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    UINT8                    *Digest;
    UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                    TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (mUseHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

    Digest = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
    Digest[GetSpdmHashSize (mUseHashAlgo) - 1] = 0;
    SpdmResponse->Header.Param2 |= (1 << 0);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x12:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    UINT8                    *Digest;
    UINTN                    DigestCount;
    UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                    TempBufSize;
    UINTN                    Index;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    DigestCount = 4;
    TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (mUseHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

    Digest = (VOID *)(SpdmResponse + 1);
    
    SpdmHashAll (mUseHashAlgo, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
    for (Index = 0; Index < DigestCount; Index++) {
      SpdmResponse->Header.Param2 |= (1 << Index);
    }

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x13:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    UINT8                    *Digest;
    UINTN                    DigestCount;
    UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                    TempBufSize;
    UINTN                    Index;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    DigestCount = 4;
    TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + DigestCount * GetSpdmHashSize (mUseHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

    Digest = (VOID *)(SpdmResponse + 1);
    
    for (Index = 0; Index < DigestCount; Index++) {
      SpdmHashAll (mUseHashAlgo, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[Index * GetSpdmHashSize (mUseHashAlgo)]);
      SpdmResponse->Header.Param2 |= (1 << Index);
      if (Index == 0) continue;
      Digest[(Index + 1) * GetSpdmHashSize (mUseHashAlgo) - 1] = 0;
    }

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x14:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                    TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = 5;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x15:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    UINT8                    *Digest;
    UINT8                    TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                    TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    TempBufSize = sizeof(SPDM_MESSAGE_HEADER) + MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT + 1;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

    Digest = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (mUseHashAlgo, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
    SpdmResponse->Header.Param2 |= (1 << 0);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

/**
  Test 1: a failure occurs during the sending of the request message
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
**/
void TestSpdmRequesterGetDigestCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
}

/**
  Test 2: a request message is successfully sent and a response message is successfully received
  Expected Behavior: requester returns the status RETURN_SUCCESS and a DIGESTS message is received
**/
void TestSpdmRequesterGetDigestCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST) + sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo));
}

/**
  Test 3: ConnectionState equals to zero and makes the check fail, meaning that steps 
  GET_CAPABILITIES-CAPABILITIES and NEGOTIATE_ALGORITHMS-ALGORITHMS of the protocol were not previously completed
  Expected Behavior: requester returns the status RETURN_UNSUPPORTED, with no DIGESTS message received
**/
void TestSpdmRequesterGetDigestCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_UNSUPPORTED);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
}

/**
  Test 4: a request message is successfully sent and an ERROR response message with error code = InvalidRequest is received
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
**/
void TestSpdmRequesterGetDigestCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
}

/**
  Test 5: request messages are successfully sent and ERROR response messages with error code = Busy are received in all attempts 
  Expected Behavior: requester returns the status RETURN_NO_RESPONSE, with no DIGESTS message received
**/
void TestSpdmRequesterGetDigestCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  
  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
}

/**
  Test 6: request messages are successfully sent and an ERROR response message with error code = Busy is received in the 
  first attempt followed by a successful response
  Expected Behavior: requester returns the status RETURN_SUCCESS and a DIGESTS message is received
**/
void TestSpdmRequesterGetDigestCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST) + sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo));
}

/**
  Test 7: a request message is successfully sent and an ERROR response message with error code = RequestResynch 
  (Meaning Responder is requesting Requester to reissue GET_VERSION to resynchronize) is received
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received
**/
void TestSpdmRequesterGetDigestCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->ConnectionInfo.ConnectionState, SpdmConnectionStateNotStarted);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
}

/**
  Test 8: request messages are successfully sent and ERROR response messages with error code = ResponseNotReady 
  are received in all attempts 
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR
**/
void TestSpdmRequesterGetDigestCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

/**
  Test 9: request messages are successfully sent and an ERROR response message with error code = ResponseNotReady 
  is received in the first attempt followed by a successful response to RESPOND_IF_READY
  Expected Behavior: requester returns the status RETURN_SUCCESS and a DIGESTS message is received
**/
void TestSpdmRequesterGetDigestCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST) + sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo));
}

/**
  Test 10: flag CERT_CAP from CAPABILITIES is not setted meaning the Requester does not support DIGESTS and 
  CERTIFICATE response messages
  Expected Behavior: requester returns the status RETURN_UNSUPPORTED, with no DIGESTS message received
**/
void TestSpdmRequesterGetDigestCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_UNSUPPORTED);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
}

/**
  Test 11: a request message is successfully sent but a failure occurs during the receiving of the response message
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received (managed buffer not shrinked)
**/
void TestSpdmRequesterGetDigestCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xB;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST));
}

/**
  Test 12: a request message is successfully sent but the size of the response message is smaller than the size of the SPDM message header, 
  meaning it is an invalid response message
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no successful DIGESTS message received (managed buffer not shrinked)
**/
void TestSpdmRequesterGetDigestCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xC;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST));
}

/**
  Test 13: a request message is successfully sent but the RequestResponseCode from the response message is different than the code of SPDM_DIGESTS
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no DIGESTS message received (managed buffer not shrinked)
**/
void TestSpdmRequesterGetDigestCase13(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xD;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST));
}

/**
  Test 14: a request message is successfully sent but the number of digests in the response message is equal to zero
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no successful DIGESTS message received (managed buffer not shrinked)
**/
void TestSpdmRequesterGetDigestCase14(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xE;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST));
}

/**
  Test 15: a request message is successfully sent but it cannot be appended to the internal cache since the internal cache is full
  Expected Behavior: requester returns the status RETURN_SECURITY_VIOLATION
**/
void TestSpdmRequesterGetDigestCase15(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xF;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = SpdmContext->Transcript.MessageB.MaxBufferSize;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

/**
  Test 16: a request message is successfully sent but the response message cannot be appended to the internal cache since the internal cache is full
  Expected Behavior: requester returns the status RETURN_SECURITY_VIOLATION
**/
void TestSpdmRequesterGetDigestCase16(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x10;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = SpdmContext->Transcript.MessageB.MaxBufferSize - (sizeof(SPDM_DIGESTS_RESPONSE));

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

/**
  Test 17: a request message is successfully sent but the single digest received in the response message is invalid
  Expected Behavior: requester returns the status RETURN_SECURITY_VIOLATION, with error state SPDM_STATUS_ERROR_CERTIFICATE_FAILURE
**/
void TestSpdmRequesterGetDigestCase17(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x11;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->ErrorState, SPDM_STATUS_ERROR_CERTIFICATE_FAILURE);
}

/**
  Test 18: a request message is successfully sent but the number of digests received in the response message is different than 
  the number of bits set in Param2 - Slot mask
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no successful DIGESTS message received (managed buffer not shrinked)
**/
void TestSpdmRequesterGetDigestCase18(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x12;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST));
}

/**
  Test 19: a request message is successfully sent but several digests (except the first) received in the response message are invalid
  Expected Behavior: requester returns the status RETURN_SECURITY_VIOLATION, with error state SPDM_STATUS_ERROR_CERTIFICATE_FAILURE
**/
void TestSpdmRequesterGetDigestCase19(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x13;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->ErrorState, SPDM_STATUS_ERROR_CERTIFICATE_FAILURE);
}

/**
  Test 20: a request message is successfully sent but the size of the response message is smaller than the minimum size of a SPDM DIGESTS response, 
  meaning it is an invalid response message.
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no successful DIGESTS message received (managed buffer not shrinked)
**/
void TestSpdmRequesterGetDigestCase20(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x14;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST));
}

/**
  Test 21: a request message is successfully sent but the size of the response message is bigger than the maximum size of a SPDM DIGESTS response, 
  meaning it is an invalid response message.
  Expected Behavior: requester returns the status RETURN_DEVICE_ERROR, with no successful DIGESTS message received (managed buffer not shrinked)
**/
void TestSpdmRequesterGetDigestCase21(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x15;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST));
}

SPDM_TEST_CONTEXT       mSpdmRequesterGetDigestTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterGetDigestTestSendMessage,
  SpdmRequesterGetDigestTestReceiveMessage,
};

int SpdmRequesterGetDigestTestMain(void) {
  const struct CMUnitTest SpdmRequesterGetDigestTests[] = {
      // SendRequest failed
      cmocka_unit_test(TestSpdmRequesterGetDigestCase1),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterGetDigestCase2),
      // ConnectionState check failed
      cmocka_unit_test(TestSpdmRequesterGetDigestCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterGetDigestCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterGetDigestCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetDigestCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterGetDigestCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterGetDigestCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetDigestCase9),
      // Capability flags check failed
      cmocka_unit_test(TestSpdmRequesterGetDigestCase10),
      // ReceiveResponse failed
      cmocka_unit_test(TestSpdmRequesterGetDigestCase11),
      // Size of response < SPDM_MESSAGE_HEADER
      //cmocka_unit_test(TestSpdmRequesterGetDigestCase12),
      // RequestResponseCode wrong in response
      cmocka_unit_test(TestSpdmRequesterGetDigestCase13),
      // Zero digests received
      cmocka_unit_test(TestSpdmRequesterGetDigestCase14),
      // Internal cache full (request message)
      cmocka_unit_test(TestSpdmRequesterGetDigestCase15),
      // Internal cache full (response message)
      cmocka_unit_test(TestSpdmRequesterGetDigestCase16),
      // Invalid digest
      cmocka_unit_test(TestSpdmRequesterGetDigestCase17),
      // Slot mask != number of digests
      cmocka_unit_test(TestSpdmRequesterGetDigestCase18),
      // Several invalid digests
      //cmocka_unit_test(TestSpdmRequesterGetDigestCase19),
      // Size of response < SPDM_DIGESTS_RESPONSE
      //cmocka_unit_test(TestSpdmRequesterGetDigestCase20),
      // Size of response > Max size of SPDM DIGESTS response
      //cmocka_unit_test(TestSpdmRequesterGetDigestCase21),
  };
  
  SetupSpdmTestContext (&mSpdmRequesterGetDigestTestContext);

  return cmocka_run_group_tests(SpdmRequesterGetDigestTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
