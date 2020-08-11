/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

#pragma pack(1)
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                Reserved;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];
} MY_SPDM_VERSION_RESPONSE;
#pragma pack()

SPDM_TEST_CONTEXT       mSpdmTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
  {
    NULL, // SpdmClientSendRequest,
    NULL, // SpdmClientReceiveResponse,
    NULL, // SpdmClientSecureSendRequest,
    NULL, // SpdmClientSecureReceiveResponse,
    SpdmIoSecureMessagingTypeDmtfMtcp,
    sizeof(UINT32)
  },
};

SPDM_GET_VERSION_REQUEST    mSpdmRequest1 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_VERSION,
  },
};
UINTN mSpdmRequest1Size = sizeof(mSpdmRequest1);

SPDM_GET_VERSION_REQUEST    mSpdmRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_VERSION,
  },
};
UINTN mSpdmRequest2Size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

void TestSpdmResponderVersionCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_VERSION_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseVersion (SpdmContext, mSpdmRequest1Size, &mSpdmRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(MY_SPDM_VERSION_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_VERSION);
}

void TestSpdmResponderVersionCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_VERSION_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseVersion (SpdmContext, mSpdmRequest2Size, &mSpdmRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

int main(void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(TestSpdmResponderVersionCase1),
    cmocka_unit_test(TestSpdmResponderVersionCase2),
  };

  return cmocka_run_group_tests(tests, TestSpdmRequesterGroupSetup, TestSpdmRequesterGroupTeardown);
}
