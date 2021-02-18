/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

#define DEFAULT_SPDM_VERSION_ENTRY_COUNT 2

#pragma pack(1)
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                Reserved;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];
} MY_SPDM_VERSION_RESPONSE;
#pragma pack()

SPDM_GET_VERSION_REQUEST    mSpdmGetVersionRequest1 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_VERSION,
  },
};
UINTN mSpdmGetVersionRequest1Size = sizeof(mSpdmGetVersionRequest1);

SPDM_GET_VERSION_REQUEST    mSpdmGetVersionRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_VERSION,
  },
};
UINTN mSpdmGetVersionRequest2Size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

SPDM_GET_VERSION_REQUEST    mSpdmGetVersionRequest3 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_VERSION,
  },
};
UINTN mSpdmGetVersionRequest3Size = sizeof(mSpdmGetVersionRequest3);

SPDM_GET_VERSION_REQUEST    mSpdmGetVersionRequest4 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_VERSION,
  },
};
UINTN mSpdmGetVersionRequest4Size = sizeof(mSpdmGetVersionRequest4);

/**
  Test 1: receiving a correct GET_VERSION from the requester.
  Expected behavior: the responder accepts the request and produces a valid VERSION
  response message.
**/
void TestSpdmResponderVersionCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_VERSION_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseVersion (SpdmContext, mSpdmGetVersionRequest1Size, &mSpdmGetVersionRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_VERSION_RESPONSE) + DEFAULT_SPDM_VERSION_ENTRY_COUNT * sizeof(SPDM_VERSION_NUMBER));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_VERSION);
}

/**
  Test 2: receiving a GET_VERSION message larger than specified (more parameters than the
  header), results in a correct VERSION message.
  Expected behavior: the responder refuses the GET_VERSION message and produces an
  ERROR message indicating the InvalidRequest.
**/
void TestSpdmResponderVersionCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_VERSION_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseVersion (SpdmContext, mSpdmGetVersionRequest2Size, &mSpdmGetVersionRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

/**
  Test 3: receiving a correct GET_VERSION from the requester, but the responder is in
  a Busy state.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the Buse state.
**/
void TestSpdmResponderVersionCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_VERSION_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseVersion (SpdmContext, mSpdmGetVersionRequest1Size, &mSpdmGetVersionRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
}

/**
  Test 4: receiving a correct GET_VERSION from the requester, but the responder requires
  resynchronization with the requester.
  Expected behavior: the requester resets the communication upon receiving the GET_VERSION
  message, fulfilling the resynchronization. A valid VERSION message is produced.
**/
void TestSpdmResponderVersionCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_VERSION_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseVersion (SpdmContext, mSpdmGetVersionRequest1Size, &mSpdmGetVersionRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_VERSION_RESPONSE) + DEFAULT_SPDM_VERSION_ENTRY_COUNT * sizeof(SPDM_VERSION_NUMBER));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_VERSION);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
}

/**
  Test 5: receiving a correct GET_VERSION from the requester, but the responder could not
  produce the response in time.
  TODO: As from version 1.0.0, a GET_VERSION message should not receive an ERROR message
  indicating the ResponseNotReady. No timing parameters have been agreed yet.
**/
void TestSpdmResponderVersionCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_VERSION_RESPONSE *SpdmResponse;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseVersion (SpdmContext, mSpdmGetVersionRequest1Size, &mSpdmGetVersionRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(&SpdmResponse->Reserved);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_GET_VERSION);
}

/**
  Test 6: receiving a GET_VERSION message in SPDM version 1.1 (in the header), but correct
  1.0-version format.
  Expected behavior: the responder refuses the GET_VERSION message and produces an
  ERROR message indicating the InvalidRequest.
**/
void TestSpdmResponderVersionCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_VERSION_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseVersion (SpdmContext, mSpdmGetVersionRequest3Size, &mSpdmGetVersionRequest3, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

/**
  Test 7: receiving a SPDM message with a VERSION 0x04 RequestResponseCode instead
  of a GET_VERSION 0x84 one.
  Expected behavior: the responder refuses the VERSION message and produces an
  ERROR message indicating the InvalidRequest.
**/
void TestSpdmResponderVersionCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_VERSION_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseVersion (SpdmContext, mSpdmGetVersionRequest3Size, &mSpdmGetVersionRequest3, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

SPDM_TEST_CONTEXT       mSpdmResponderVersionTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderVersionTestMain(void) {
  const struct CMUnitTest SpdmResponderVersionTests[] = {
    cmocka_unit_test(TestSpdmResponderVersionCase1),
    // Invalid request
    cmocka_unit_test(TestSpdmResponderVersionCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderVersionCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderVersionCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderVersionCase5),
    // Invalid request
    cmocka_unit_test(TestSpdmResponderVersionCase6),
  };

  SetupSpdmTestContext (&mSpdmResponderVersionTestContext);

  return cmocka_run_group_tests(SpdmResponderVersionTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
