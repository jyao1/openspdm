/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

// #define TEST_DEBUG
#ifdef TEST_DEBUG
#define TEST_DEBUG_PRINT(format, ...) printf(format, ##__VA_ARGS__)
#else
#define TEST_DEBUG_PRINT(...)
#endif

SPDM_GET_CERTIFICATE_REQUEST    mSpdmGetCertificateRequest1 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_CERTIFICATE,
    0,
    0
  },
  0,
  MAX_SPDM_CERT_CHAIN_BLOCK_LEN
};
UINTN mSpdmGetCertificateRequest1Size = sizeof(mSpdmGetCertificateRequest1);

SPDM_GET_CERTIFICATE_REQUEST    mSpdmGetCertificateRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_CERTIFICATE,
    0,
    0
  },
  0,
  MAX_SPDM_CERT_CHAIN_BLOCK_LEN
};
UINTN mSpdmGetCertificateRequest2Size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

SPDM_GET_CERTIFICATE_REQUEST    mSpdmGetCertificateRequest3 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_CERTIFICATE,
    0,
    0
  },
  0,
  0
};
UINTN mSpdmGetCertificateRequest3Size = sizeof(mSpdmGetCertificateRequest3);

/**
  Test 1: Request the first MAX_SPDM_CERT_CHAIN_BLOCK_LEN bytes of the certificate chain
  Expected Behavior: generate a correctly formed Certficate message, including its PortionLength and RemainderLength fields
**/
void TestSpdmResponderCertificateCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest1Size, &mSpdmGetCertificateRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CERTIFICATE_RESPONSE) + MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CERTIFICATE);
  assert_int_equal (SpdmResponse->Header.Param1, 0);
  assert_int_equal (SpdmResponse->PortionLength, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
  assert_int_equal (SpdmResponse->RemainderLength, DataSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
  free(Data);
}

/**
  Test 2: Wrong GET_CERTIFICATE message size (larger than expected)
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_INVALID_REQUEST
**/
void TestSpdmResponderCertificateCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest2Size, &mSpdmGetCertificateRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data);
}

/**
  Test 3: Force ResponseState = SpdmResponseStateBusy when asked GET_CERTIFICATE
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_BUSY
**/
void TestSpdmResponderCertificateCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest1Size, &mSpdmGetCertificateRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
  free(Data);
}

/**
  Test 4: Force ResponseState = SpdmResponseStateNeedResync when asked GET_CERTIFICATE
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_REQUEST_RESYNCH
**/
void TestSpdmResponderCertificateCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest1Size, &mSpdmGetCertificateRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
  free(Data);
}

/**
  Test 5: Force ResponseState = SpdmResponseStateNotReady when asked GET_CERTIFICATE
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_RESPONSE_NOT_READY and correct ErrorData
**/
void TestSpdmResponderCertificateCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest1Size, &mSpdmGetCertificateRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(&SpdmResponse->PortionLength);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_GET_CERTIFICATE);
  free(Data);
}

/**
  Test 6: simulate wrong ConnectionState when asked GET_CERTIFICATE (missing SPDM_GET_DIGESTS_RECEIVE_FLAG and SPDM_GET_CAPABILITIES_RECEIVE_FLAG)
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNEXPECTED_REQUEST
**/
void TestSpdmResponderCertificateCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ResponseState = SpdmResponseStateNormal;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest1Size, &mSpdmGetCertificateRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  free(Data);
}

/**
  Test 7: request Length at the boundary of maximum integer values, while keeping offset 0
  Expected Behavior: generate correctly formed Certficate messages, including its PortionLength and RemainderLength fields
**/
void TestSpdmResponderCertificateCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  // Testing Lengths at the boundary of maximum integer values
  UINT16               TestLenghts[] = {0, MAX_INT8, (UINT16)(MAX_INT8+1), MAX_UINT8, MAX_INT16, (UINT16)(MAX_INT16+1), MAX_UINT16, (UINT16)(-1)};
  UINT16               ExpectedChunkSize;

  // Setting up the SpdmContext and loading a sample certificate chain
  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  // This tests considers only offset = 0, other tests vary offset value
  mSpdmGetCertificateRequest3.Offset = 0;

  for(int i=0; i<sizeof(TestLenghts)/sizeof(TestLenghts[0]); i++) {
    TEST_DEBUG_PRINT("i:%d TestLenghts[i]:%u\n",i, TestLenghts[i]);
    mSpdmGetCertificateRequest3.Length = TestLenghts[i];
    // Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN (implementation specific?)
    ExpectedChunkSize = MIN(mSpdmGetCertificateRequest3.Length, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);

    // reseting an internal buffer to avoid overflow and prevent tests to succeed
    ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
    ResponseSize = sizeof(Response);
    Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest3Size, &mSpdmGetCertificateRequest3, &ResponseSize, Response);
    assert_int_equal (Status, RETURN_SUCCESS);
    assert_int_equal (ResponseSize, sizeof(SPDM_CERTIFICATE_RESPONSE) + ExpectedChunkSize);
    SpdmResponse = (VOID *)Response;
    assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CERTIFICATE);
    assert_int_equal (SpdmResponse->Header.Param1, 0);
    assert_int_equal (SpdmResponse->PortionLength, ExpectedChunkSize);
    assert_int_equal (SpdmResponse->RemainderLength, DataSize - ExpectedChunkSize);
  }
  free(Data);
}

/**
  Test 8: request Offset at the boundary of maximum integer values, while keeping Length 0
  Expected Behavior: generate correctly formed Certficate messages, including its PortionLength and RemainderLength fields
**/
void TestSpdmResponderCertificateCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  SPDM_ERROR_RESPONSE  *SpdmResponseError;
  VOID                 *Data;
  UINTN                DataSize;

  // Testing Offsets at the boundary of maximum integer values and at the boundary of certificate length (first three positions)
  UINT16               TestOffsets[] = {(UINT16)(-1), 0, +1, 0, MAX_INT8, (UINT16)(MAX_INT8+1), MAX_UINT8, MAX_INT16, (UINT16)(MAX_INT16+1), MAX_UINT16, (UINT16)(-1)};

  // Setting up the SpdmContext and loading a sample certificate chain
  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  // This tests considers only length = 0, other tests vary length value
  mSpdmGetCertificateRequest3.Length = 0;
  // Setting up offset values at the boundary of certificate length
  TestOffsets[0] = (UINT16)(TestOffsets[0] + DataSize);
  TestOffsets[1] = (UINT16)(TestOffsets[1] + DataSize);
  TestOffsets[2] = (UINT16)(TestOffsets[2] + DataSize);

  for(int i=0; i<sizeof(TestOffsets)/sizeof(TestOffsets[0]); i++) {
    TEST_DEBUG_PRINT("i:%d TestOffsets[i]:%u\n",i, TestOffsets[i]);
    mSpdmGetCertificateRequest3.Offset = TestOffsets[i];

    // reseting an internal buffer to avoid overflow and prevent tests to succeed
    ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
    ResponseSize = sizeof(Response);
    Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest3Size, &mSpdmGetCertificateRequest3, &ResponseSize, Response);
    assert_int_equal (Status, RETURN_SUCCESS);

    if(mSpdmGetCertificateRequest3.Offset >= DataSize) {
      // A too long of an offset should return an error
      SpdmResponseError = (VOID *)Response;
      assert_int_equal (SpdmResponseError->Header.RequestResponseCode, SPDM_ERROR);
      assert_int_equal (SpdmResponseError->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    } else {
      // Otherwise it should work properly, considering Length = 0
      assert_int_equal (ResponseSize, sizeof(SPDM_CERTIFICATE_RESPONSE));
      SpdmResponse = (VOID *)Response;
      assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CERTIFICATE);
      assert_int_equal (SpdmResponse->Header.Param1, 0);
      assert_int_equal (SpdmResponse->PortionLength, 0);
      assert_int_equal (SpdmResponse->RemainderLength, (UINT16)(DataSize - mSpdmGetCertificateRequest3.Offset));
    }
  }
  free(Data);
}

/**
  Test 9: request Offset and Length at the boundary of maximum integer values
  Expected Behavior: generate correctly formed Certficate messages, including its PortionLength and RemainderLength fields
**/
void TestSpdmResponderCertificateCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  SPDM_ERROR_RESPONSE  *SpdmResponseError;
  VOID                 *Data;
  UINTN                DataSize;

  // Testing Offsets and Length combinations
  // Check at the boundary of maximum integer values and at the boundary of certificate length
  UINT16               TestSizes[] =   {(UINT16)(-1), 0, +1, // reserved for sizes around the certificate chain size
                                        (UINT16)(-1), 0, +1,
                                        (UINT16)(MAX_INT8-1), MAX_INT8, (UINT16)(MAX_INT8+1),
                                        (UINT16)(MAX_UINT8-1), MAX_UINT8,
                                        (UINT16)(MAX_INT16-1), MAX_INT16, (UINT16)(MAX_INT16+1),
                                        (UINT16)(MAX_UINT16-1), MAX_UINT16
                                       };
  UINT16               ExpectedChunkSize;
  UINT16               ExpectedRemainder;

  // Setting up the SpdmContext and loading a sample certificate chain
  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  // Setting up offset values at the boundary of certificate length
  TestSizes[0] += (UINT16)(TestSizes[0] + DataSize);
  TestSizes[1] += (UINT16)(TestSizes[1] + DataSize);
  TestSizes[2] += (UINT16)(TestSizes[2] + DataSize);

  for(int i=0; i<sizeof(TestSizes)/sizeof(TestSizes[0]); i++) {
    TEST_DEBUG_PRINT("i:%d TestSizes[i]=Length:%u\n",i, TestSizes[i]);
    mSpdmGetCertificateRequest3.Length = TestSizes[i];
    for(int j=0; j<sizeof(TestSizes)/sizeof(TestSizes[0]); j++) {
      TEST_DEBUG_PRINT("\tj:%d TestSizes[j]=Offset:%u\n",j, TestSizes[j]);
      mSpdmGetCertificateRequest3.Offset = TestSizes[j];

      // reseting an internal buffer to avoid overflow and prevent tests to succeed
      ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
      ResponseSize = sizeof(Response);
      Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest3Size, &mSpdmGetCertificateRequest3, &ResponseSize, Response);
      assert_int_equal (Status, RETURN_SUCCESS);

      if(mSpdmGetCertificateRequest3.Offset >= DataSize) {
        // A too long of an offset should return an error
        SpdmResponseError = (VOID *)Response;
        assert_int_equal (SpdmResponseError->Header.RequestResponseCode, SPDM_ERROR);
        assert_int_equal (SpdmResponseError->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
      } else {
        // Otherwise it should work properly

        // Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN and by the remaining length
        ExpectedChunkSize = (UINT16)(MIN(mSpdmGetCertificateRequest3.Length, DataSize - mSpdmGetCertificateRequest3.Offset));
        ExpectedChunkSize = MIN(ExpectedChunkSize, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
        // Expected certificate length left
        ExpectedRemainder = (UINT16)(DataSize - mSpdmGetCertificateRequest3.Offset - ExpectedChunkSize);

        assert_int_equal (ResponseSize, sizeof(SPDM_CERTIFICATE_RESPONSE) + ExpectedChunkSize);
        SpdmResponse = (VOID *)Response;
        assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CERTIFICATE);
        assert_int_equal (SpdmResponse->Header.Param1, 0);
        assert_int_equal (SpdmResponse->PortionLength, ExpectedChunkSize);
        assert_int_equal (SpdmResponse->RemainderLength, ExpectedRemainder);
      }
    }
  }
  free(Data);
}

/**
  Test 10: request MAX_SPDM_CERT_CHAIN_BLOCK_LEN bytes of long certificate chains, with the largest valid Offset
  Expected Behavior: generate correctly formed Certficate messages, including its PortionLength and RemainderLength fields
**/
void TestSpdmResponderCertificateCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  SPDM_ERROR_RESPONSE  *SpdmResponseError;
  VOID                 *Data;
  UINTN                DataSize;

  UINT16               TestCases[] =   {TEST_CERT_MAXINT16, TEST_CERT_MAXUINT16};

  UINTN                ExpectedChunkSize;
  UINTN                ExpectedRemainder;

  // Setting up the SpdmContext and loading a sample certificate chain
  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

  mSpdmGetCertificateRequest3.Length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

  for(int i=0; i<sizeof(TestCases)/sizeof(TestCases[0]); i++) {
    ReadResponderPublicCertificateChainBySize (mUseHashAlgo, mUseAsymAlgo, TestCases[i], &Data, &DataSize, NULL, NULL);

    SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
    SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    SpdmContext->LocalContext.SlotCount = 1;

    mSpdmGetCertificateRequest3.Offset = (UINT16)(MIN(DataSize - 1, MAX_UINT16));
    TEST_DEBUG_PRINT("DataSize: %u\n",DataSize);
    TEST_DEBUG_PRINT("mSpdmGetCertificateRequest3.Offset: %u\n",mSpdmGetCertificateRequest3.Offset);
    TEST_DEBUG_PRINT("mSpdmGetCertificateRequest3.Length: %u\n",mSpdmGetCertificateRequest3.Length);
    TEST_DEBUG_PRINT("Offset + Length: %u\n",mSpdmGetCertificateRequest3.Offset + mSpdmGetCertificateRequest3.Length);

    // reseting an internal buffer to avoid overflow and prevent tests to succeed
    ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
    ResponseSize = sizeof(Response);
    Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest3Size, &mSpdmGetCertificateRequest3, &ResponseSize, Response);
    assert_int_equal (Status, RETURN_SUCCESS);

    // Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN and by the remaining length
    ExpectedChunkSize = (UINT16)(MIN(mSpdmGetCertificateRequest3.Length, DataSize - mSpdmGetCertificateRequest3.Offset));
    ExpectedChunkSize = MIN(ExpectedChunkSize, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
    // Expected certificate length left
    ExpectedRemainder = (UINT16)(DataSize - mSpdmGetCertificateRequest3.Offset - ExpectedChunkSize);

    TEST_DEBUG_PRINT("ExpectedChunkSize %u\n",ExpectedChunkSize);
    TEST_DEBUG_PRINT("ExpectedRemainder %u\n",ExpectedRemainder);

    if (ExpectedRemainder > MAX_UINT16 || ExpectedChunkSize > MAX_UINT16) {
      SpdmResponseError = (VOID *)Response;
      assert_int_equal (SpdmResponseError->Header.RequestResponseCode, SPDM_ERROR);
      assert_int_equal (SpdmResponseError->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    } else {
      assert_int_equal (ResponseSize, sizeof(SPDM_CERTIFICATE_RESPONSE) + ExpectedChunkSize);
      SpdmResponse = (VOID *)Response;
      assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CERTIFICATE);
      assert_int_equal (SpdmResponse->Header.Param1, 0);
      assert_int_equal (SpdmResponse->PortionLength, ExpectedChunkSize);
      assert_int_equal (SpdmResponse->RemainderLength, ExpectedRemainder);
    }

    TEST_DEBUG_PRINT("\n");

    free(Data);
  }
}

/**
  Test 11: request MAX_SPDM_CERT_CHAIN_BLOCK_LEN bytes of a short certificate chain (fits in 1 message)
  Expected Behavior: generate correctly formed Certficate messages, including its PortionLength and RemainderLength fields
**/
void TestSpdmResponderCertificateCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  SPDM_ERROR_RESPONSE  *SpdmResponseError;
  VOID                 *Data;
  UINTN                DataSize;

  UINT16               TestCases[] =   {TEST_CERT_SMALL};

  UINTN                ExpectedChunkSize;
  UINTN                ExpectedRemainder;

  // Setting up the SpdmContext and loading a sample certificate chain
  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xB;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;

  mSpdmGetCertificateRequest3.Length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  mSpdmGetCertificateRequest3.Offset = 0;

  for(int i=0; i<sizeof(TestCases)/sizeof(TestCases[0]); i++) {
    ReadResponderPublicCertificateChainBySize (mUseHashAlgo, mUseAsymAlgo, TestCases[i], &Data, &DataSize, NULL, NULL);
    SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
    SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
    SpdmContext->LocalContext.SlotCount = 1;

    TEST_DEBUG_PRINT("DataSize: %u\n",DataSize);
    TEST_DEBUG_PRINT("mSpdmGetCertificateRequest3.Offset: %u\n",mSpdmGetCertificateRequest3.Offset);
    TEST_DEBUG_PRINT("mSpdmGetCertificateRequest3.Length: %u\n",mSpdmGetCertificateRequest3.Length);
    TEST_DEBUG_PRINT("Offset + Length: %u\n",mSpdmGetCertificateRequest3.Offset + mSpdmGetCertificateRequest3.Length);

    // reseting an internal buffer to avoid overflow and prevent tests to succeed
    ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
    ResponseSize = sizeof(Response);
    Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest3Size, &mSpdmGetCertificateRequest3, &ResponseSize, Response);
    assert_int_equal (Status, RETURN_SUCCESS);

    // Expected received length is limited by MAX_SPDM_CERT_CHAIN_BLOCK_LEN and by the remaining length
    ExpectedChunkSize = MIN(mSpdmGetCertificateRequest3.Length, DataSize - mSpdmGetCertificateRequest3.Offset);
    ExpectedChunkSize = MIN(ExpectedChunkSize, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
    // Expected certificate length left
    ExpectedRemainder = DataSize - mSpdmGetCertificateRequest3.Offset - ExpectedChunkSize;

    TEST_DEBUG_PRINT("ExpectedChunkSize %u\n",ExpectedChunkSize);
    TEST_DEBUG_PRINT("ExpectedRemainder %u\n",ExpectedRemainder);

    if (ExpectedRemainder > MAX_UINT16 || ExpectedChunkSize > MAX_UINT16) {
      SpdmResponseError = (VOID *)Response;
      assert_int_equal (SpdmResponseError->Header.RequestResponseCode, SPDM_ERROR);
      assert_int_equal (SpdmResponseError->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    } else {
      assert_int_equal (ResponseSize, sizeof(SPDM_CERTIFICATE_RESPONSE) + ExpectedChunkSize);
      SpdmResponse = (VOID *)Response;
      assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CERTIFICATE);
      assert_int_equal (SpdmResponse->Header.Param1, 0);
      assert_int_equal (SpdmResponse->PortionLength, ExpectedChunkSize);
      assert_int_equal (SpdmResponse->RemainderLength, ExpectedRemainder);
    }

    TEST_DEBUG_PRINT("\n");

    free(Data);
  }
}

/**
  Test 12: Request a whole certificate chain byte by byte
  Expected Behavior: generate correctly formed Certficate messages, including its PortionLength and RemainderLength fields
**/
void TestSpdmResponderCertificateCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  UINTN                Count;
  UINT16               ExpectedChunkSize;

  // Setting up the SpdmContext and loading a sample certificate chain
  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xC;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  // This tests considers only Length = 1
  mSpdmGetCertificateRequest3.Length = 1;
  ExpectedChunkSize = 1;

  Count = (DataSize + mSpdmGetCertificateRequest3.Length - 1) / mSpdmGetCertificateRequest3.Length;

  // reseting an internal buffer to avoid overflow and prevent tests to succeed
  ResetManagedBuffer (&SpdmContext->Transcript.MessageB);

  SpdmResponse = NULL;
  for(UINTN offset=0; offset<DataSize; offset++) {
    TEST_DEBUG_PRINT("offset:%u \n", offset);
    mSpdmGetCertificateRequest3.Offset = (UINT16)offset;

    ResponseSize = sizeof(Response);
    Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest3Size, &mSpdmGetCertificateRequest3, &ResponseSize, Response);
    assert_int_equal (Status, RETURN_SUCCESS);
    SpdmResponse = (VOID *)Response;
    // It may fail because the spdm does not support too many messages.
    // assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CERTIFICATE);
    if (SpdmResponse->Header.RequestResponseCode == SPDM_CERTIFICATE) {
      assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CERTIFICATE);
      assert_int_equal (ResponseSize, sizeof(SPDM_CERTIFICATE_RESPONSE) + ExpectedChunkSize);
      assert_int_equal (SpdmResponse->Header.Param1, 0);
      assert_int_equal (SpdmResponse->PortionLength, ExpectedChunkSize);
      assert_int_equal (SpdmResponse->RemainderLength, DataSize - offset - ExpectedChunkSize);
      assert_int_equal ( ((UINT8*) Data)[offset], (Response + sizeof(SPDM_CERTIFICATE_RESPONSE))[0]);
    } else {
      assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
      break;
    }
  }
  if (SpdmResponse != NULL) {
    if (SpdmResponse->Header.RequestResponseCode == SPDM_CERTIFICATE) {
      assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
    }
  }
  free(Data);
}


SPDM_TEST_CONTEXT       mSpdmResponderCertificateTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderCertificateTestMain(void) {
  const struct CMUnitTest SpdmResponderCertificateTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderCertificateCase1),
    // Bad Request Size
    cmocka_unit_test(TestSpdmResponderCertificateCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderCertificateCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderCertificateCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderCertificateCase5),
    // ConnectionState Check
    cmocka_unit_test(TestSpdmResponderCertificateCase6),
    // Tests varying length
    cmocka_unit_test(TestSpdmResponderCertificateCase7),
    // Tests varying offset
    cmocka_unit_test(TestSpdmResponderCertificateCase8),
    // Tests varying length and offset
    cmocka_unit_test(TestSpdmResponderCertificateCase9),
    // Tests large certificate chains
    cmocka_unit_test(TestSpdmResponderCertificateCase10),
    // Certificate fits in one single message
    cmocka_unit_test(TestSpdmResponderCertificateCase11),
    // Requests byte by byte
    cmocka_unit_test(TestSpdmResponderCertificateCase12),

  };

  SetupSpdmTestContext (&mSpdmResponderCertificateTestContext);

  return cmocka_run_group_tests(SpdmResponderCertificateTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
