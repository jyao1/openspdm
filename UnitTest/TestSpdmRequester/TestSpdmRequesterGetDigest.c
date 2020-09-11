/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

#define DEFAULT_HASH_ALGO     SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256

STATIC UINT8                  LocalCertificateChain[MAX_SPDM_MESSAGE_BUFFER_SIZE];

RETURN_STATUS
EFIAPI
SpdmRequesterGetDigestTestSendMessage (
  IN     VOID                    *SpdmContext,
  IN     UINT32                  *SessionId,
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
     OUT UINT32                  **SessionId,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  *SessionId = NULL;

  SpdmTestContext = GetSpdmTestContext ();
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;

  case 0x2:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    HASH_ALL                  HashFunc;
	UINT8                    *Digest;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
    *ResponseSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext);
    *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
    SpdmResponse = Response;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
    HashFunc = GetSpdmHashFunc (SpdmContext);
    Digest = (VOID *)(SpdmResponse + 1);
    HashFunc (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
    SpdmResponse->Header.Param2 |= (1 << 0);
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_DIGESTS_RESPONSE    *SpdmResponse;
    HASH_ALL                  HashFunc;
	UINT8                    *Digest;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
    *ResponseSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext);
    *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
    SpdmResponse = Response;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
    SpdmResponse->Header.Param2 = 0;
    SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
    HashFunc = GetSpdmHashFunc (SpdmContext);
    Digest = (VOID *)(SpdmResponse + 1);
    HashFunc (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
    SpdmResponse->Header.Param2 |= (1 << 0);
  }
    return RETURN_SUCCESS;

  case 0x4:
  {
    SPDM_ERROR_RESPONSE    *SpdmResponse;

    *ResponseSize = sizeof(SPDM_ERROR_RESPONSE);
    *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
    SpdmResponse = Response;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse->Header.Param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    SpdmResponse->Header.Param2 = 0;
  }
    return RETURN_SUCCESS;

  case 0x5:
  {
    SPDM_ERROR_RESPONSE	 *SpdmResponse;

    *ResponseSize = sizeof(SPDM_ERROR_RESPONSE);
    *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
    SpdmResponse = Response;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse->Header.Param1 = SPDM_ERROR_CODE_BUSY;
    SpdmResponse->Header.Param2 = 0;
  }
    return RETURN_SUCCESS;

  case 0x6:
  {
    STATIC UINTN SubIndex1 = 0;
    if (SubIndex1 == 0) {
      SPDM_ERROR_RESPONSE	 *SpdmResponse;

      *ResponseSize = sizeof(SPDM_ERROR_RESPONSE);
      *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
      SpdmResponse = Response;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse->Header.Param1 = SPDM_ERROR_CODE_BUSY;
      SpdmResponse->Header.Param2 = 0;
    } else if (SubIndex1 == 1) {
      SPDM_DIGESTS_RESPONSE    *SpdmResponse;
      HASH_ALL                  HashFunc;
	  UINT8                    *Digest;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
      *ResponseSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext);
      *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
      SpdmResponse = Response;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
      SpdmResponse->Header.Param2 = 0;
      SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
      HashFunc = GetSpdmHashFunc (SpdmContext);
      Digest = (VOID *)(SpdmResponse + 1);
      HashFunc (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
      SpdmResponse->Header.Param2 |= (1 << 0);
    }
    SubIndex1 ++;
  }
    return RETURN_SUCCESS;

  case 0x7:
  {
    SPDM_ERROR_RESPONSE  *SpdmResponse;

    *ResponseSize = sizeof(SPDM_ERROR_RESPONSE);
    *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
    SpdmResponse = Response;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse->Header.Param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
    SpdmResponse->Header.Param2 = 0;
  }
    return RETURN_SUCCESS;

  case 0x8:
  {
    SPDM_ERROR_RESPONSE                  *SpdmResponse;
    SPDM_ERROR_DATA_RESPONSE_NOT_READY   *ExtendErrorData;

    SpdmResponse = Response;
    ExtendErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(SpdmResponse + 1);
    *ResponseSize = sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY);
    *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse->Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    SpdmResponse->Header.Param2 = 0;
    ExtendErrorData->RDTExponent = 1;
    ExtendErrorData->RDTM = 1;
    ExtendErrorData->RequestCode = SPDM_GET_DIGESTS;
    ExtendErrorData->Token = 0;
  }
    return RETURN_SUCCESS;

  case 0x9:
  {
    STATIC UINTN SubIndex2 = 0;
    if (SubIndex2 == 0) {
      SPDM_ERROR_RESPONSE	 *SpdmResponse;
      SPDM_ERROR_DATA_RESPONSE_NOT_READY   *ExtendErrorData;

      SpdmResponse = Response;
      ExtendErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(SpdmResponse + 1);
      *ResponseSize = sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY);
      *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse->Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
      SpdmResponse->Header.Param2 = 0;
      ExtendErrorData->RDTExponent = 1;
      ExtendErrorData->RDTM = 1;
      ExtendErrorData->RequestCode = SPDM_GET_DIGESTS;
      ExtendErrorData->Token = 1;
    } else if (SubIndex2 == 1) {
      SPDM_DIGESTS_RESPONSE    *SpdmResponse;
      HASH_ALL                  HashFunc;
	  UINT8                    *Digest;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
      *ResponseSize = sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize (SpdmContext);
      *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
      SpdmResponse = Response;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
      SpdmResponse->Header.Param2 = 0;
      SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
      HashFunc = GetSpdmHashFunc (SpdmContext);
      Digest = (VOID *)(SpdmResponse + 1);
      HashFunc (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, &Digest[0]);
      SpdmResponse->Header.Param2 |= (1 << 0);
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
  SpdmContext->LocalContext.PeerCertChainVarBuffer = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainVarBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
  SpdmContext->LocalContext.PeerCertChainVarBuffer = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainVarBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->SpdmCmdReceiveState = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
  SpdmContext->LocalContext.PeerCertChainVarBuffer = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainVarBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
  SpdmContext->LocalContext.PeerCertChainVarBuffer = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainVarBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
  SpdmContext->LocalContext.PeerCertChainVarBuffer = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainVarBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
  SpdmContext->LocalContext.PeerCertChainVarBuffer = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainVarBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
  SpdmContext->LocalContext.PeerCertChainVarBuffer = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainVarBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
  SpdmContext->LocalContext.PeerCertChainVarBuffer = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainVarBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = DEFAULT_HASH_ALGO;
  SpdmContext->LocalContext.PeerCertChainVarBuffer = LocalCertificateChain;
  SpdmContext->LocalContext.PeerCertChainVarBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
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
