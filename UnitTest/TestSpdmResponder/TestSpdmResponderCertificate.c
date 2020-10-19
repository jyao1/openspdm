/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize;
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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCertificate (SpdmContext, mSpdmGetCertificateRequest1Size, &mSpdmGetCertificateRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
  free(Data);
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize;
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
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
  assert_int_equal (ErrorData->RequestCode, SPDM_GET_CERTIFICATE);
  free(Data);
}

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
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.CertificateChain[0] = Data;
  SpdmContext->LocalContext.CertificateChainSize[0] = DataSize;
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
    // SpdmCmdReceiveState Check
    cmocka_unit_test(TestSpdmResponderCertificateCase6),
  };

  SetupSpdmTestContext (&mSpdmResponderCertificateTestContext);

  return cmocka_run_group_tests(SpdmResponderCertificateTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
