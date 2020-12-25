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
    TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

    Digest = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (SpdmContext, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
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
    TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

    Digest = (VOID *)(SpdmResponse + 1);
    SpdmHashAll (SpdmContext, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
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
      TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext);
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
      SpdmResponse->Header.Param2 = 0;
      SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

      Digest = (VOID *)(SpdmResponse + 1);
      SpdmHashAll (SpdmContext, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
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
      TempBufSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext);
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
      SpdmResponse->Header.Param2 = 0;
      SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));

      Digest = (VOID *)(SpdmResponse + 1);
      SpdmHashAll (SpdmContext, LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
      SpdmResponse->Header.Param2 |= (1 << 0);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
    SubIndex2 ++;
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

void TestSpdmRequesterGetDigestCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
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

void TestSpdmRequesterGetDigestCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST) + sizeof(SPDM_DIGESTS_RESPONSE) + 32);
}

void TestSpdmRequesterGetDigestCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->SpdmCmdReceiveState = 0;
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

void TestSpdmRequesterGetDigestCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
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

void TestSpdmRequesterGetDigestCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
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

void TestSpdmRequesterGetDigestCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST) + sizeof(SPDM_DIGESTS_RESPONSE) + 32);
}

void TestSpdmRequesterGetDigestCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->SpdmCmdReceiveState, 0);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
}

void TestSpdmRequesterGetDigestCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
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

void TestSpdmRequesterGetDigestCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.PeerCertChainProvision = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->Transcript.MessageB.BufferSize = 0;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  Status = SpdmGetDigest (SpdmContext, &SlotMask, &TotalDigestBuffer);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_DIGESTS_REQUEST) + sizeof(SPDM_DIGESTS_RESPONSE) + 32);
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
      // SpdmCmdReceiveState check failed
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
  };
  
  SetupSpdmTestContext (&mSpdmRequesterGetDigestTestContext);

  return cmocka_run_group_tests(SpdmRequesterGetDigestTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
