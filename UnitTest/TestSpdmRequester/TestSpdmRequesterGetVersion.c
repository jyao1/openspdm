/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

#pragma pack(1)
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                Reserved;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];
} MY_SPDM_VERSION_RESPONSE;
#pragma pack()

RETURN_STATUS
EFIAPI
SpdmRequesterGetVersionTestSendMessage (
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
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmRequesterGetVersionTestReceiveMessage (
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
    MY_SPDM_VERSION_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_VERSION;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.VersionNumberEntryCount = 2;
    SpdmResponse.VersionNumberEntry[0].MajorVersion = 1;
    SpdmResponse.VersionNumberEntry[0].MinorVersion = 0;
    SpdmResponse.VersionNumberEntry[1].MajorVersion = 1;
    SpdmResponse.VersionNumberEntry[1].MinorVersion = 1;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_VERSION_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_VERSION;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.VersionNumberEntryCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x4:
  {
    SPDM_ERROR_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
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

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
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

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
      SpdmResponse.Header.Param2 = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    } else if (SubIndex1 == 1) {
      MY_SPDM_VERSION_RESPONSE    SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_VERSION;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.VersionNumberEntryCount = 2;
      SpdmResponse.VersionNumberEntry[0].MajorVersion = 1;
      SpdmResponse.VersionNumberEntry[0].MinorVersion = 0;
      SpdmResponse.VersionNumberEntry[1].MajorVersion = 1;
      SpdmResponse.VersionNumberEntry[1].MinorVersion = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
    SubIndex1 ++;
  }
    return RETURN_SUCCESS;

  case 0x7:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
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

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.ExtendErrorData.RDTExponent = 1;
    SpdmResponse.ExtendErrorData.RDTM = 1;
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_GET_VERSION;
    SpdmResponse.ExtendErrorData.Token = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x9:
  {
    STATIC UINTN SubIndex2 = 0;
    if (SubIndex2 == 0) {
      SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.ExtendErrorData.RDTExponent = 1;
      SpdmResponse.ExtendErrorData.RDTM = 1;
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_GET_VERSION;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    } else if (SubIndex2 == 1) {
      MY_SPDM_VERSION_RESPONSE    SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_VERSION;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.VersionNumberEntryCount = 2;
      SpdmResponse.VersionNumberEntry[0].MajorVersion = 1;
      SpdmResponse.VersionNumberEntry[0].MinorVersion = 0;
      SpdmResponse.VersionNumberEntry[1].MajorVersion = 1;
      SpdmResponse.VersionNumberEntry[1].MinorVersion = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
    SubIndex2 ++;
  }
    return RETURN_SUCCESS;

  case 0xA:
  {
    MY_SPDM_VERSION_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_VERSION;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.VersionNumberEntryCount = 2;
    SpdmResponse.VersionNumberEntry[0].MajorVersion = 1;
    SpdmResponse.VersionNumberEntry[0].MinorVersion = 0;
    SpdmResponse.VersionNumberEntry[1].MajorVersion = 1;
    SpdmResponse.VersionNumberEntry[1].MinorVersion = 1;
    SpdmResponse.VersionNumberEntry[2].MajorVersion = 1;
    SpdmResponse.VersionNumberEntry[2].MinorVersion = 2;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xB:
  {
    MY_SPDM_VERSION_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_VERSION;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.VersionNumberEntryCount = 2;
    SpdmResponse.VersionNumberEntry[0].MajorVersion = 10;
    SpdmResponse.VersionNumberEntry[0].MinorVersion = 0;
    SpdmResponse.VersionNumberEntry[1].MajorVersion = 10;
    SpdmResponse.VersionNumberEntry[1].MinorVersion = 1;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xC:
  {
    MY_SPDM_VERSION_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_VERSION;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.VersionNumberEntryCount = 2;
    SpdmResponse.VersionNumberEntry[0].MajorVersion = 1;
    SpdmResponse.VersionNumberEntry[0].MinorVersion = 0;
    SpdmResponse.VersionNumberEntry[1].MajorVersion = 1;
    SpdmResponse.VersionNumberEntry[1].MinorVersion = 1;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xD:
  {
    MY_SPDM_VERSION_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_GET_VERSION;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.VersionNumberEntryCount = 2;
    SpdmResponse.VersionNumberEntry[0].MajorVersion = 1;
    SpdmResponse.VersionNumberEntry[0].MinorVersion = 0;
    SpdmResponse.VersionNumberEntry[1].MajorVersion = 1;
    SpdmResponse.VersionNumberEntry[1].MinorVersion = 1;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

/**
  Test 1: when no VERSION message is received, and the client returns a device error.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterGetVersionCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

/**
  Test 2: receiving a correct VERSION message with available version 1.0 and 1.1.
  Expected behavior: client returns a Status of RETURN_SUCCESS.
**/
void TestSpdmRequesterGetVersionCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
}

/**
  Test 3: receiving a correct VERSION message header, but with 0 versions available.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterGetVersionCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

/**
  Test 4: receiving an InvalidRequest ERROR message from the responder.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterGetVersionCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

/**
  Test 5: receiving an Busy ERROR message correct VERSION message from the responder.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterGetVersionCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
}

/**
  Test 6: on the first try, receiving a Busy ERROR message, and on retry, receiving
  a correct VERSION message with available version 1.0 and 1.1.
  Expected behavior: client returns a Status of RETURN_SUCCESS.
**/
void TestSpdmRequesterGetVersionCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
}

/**
  Test 7: receiving a RequestResynch ERROR message from the responder.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR, and the
  internal state should be reset.
  Note: As from 1.1.c, this is an unexpected behavior, as the responder should not
  respond a GET_VERSION message with a RequestResynch. It should expect a GET_VERSION.
**/
void TestSpdmRequesterGetVersionCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->ConnectionInfo.ConnectionState, SpdmConnectionStateNotStarted);
}

/**
  Test 8: receiving a ResponseNotReady ERROR message from the responder.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
  Note: As from 1.0.0, this is an unexpected behavior, as the responder should not
  respond a GET_VERSION message with a ResponseNotReady.
**/
void TestSpdmRequesterGetVersionCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

/**
  Test 9: on the first try, receiving a ResponseNotReady ERROR message, and on retry,
  receiving a correct VERSION message with available version 1.0 and 1.1.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
  Note: The responder should not
  respond a GET_VERSION message with a ResponseNotReady.
**/
void TestSpdmRequesterGetVersionCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

/**
  Test 10: receiving a VERSION message with a larger list of available versions than indicated.
  The presence of only two versions are indicated, but the VERSION message presents a list
  with 3 versions: 1.0, 1.1 and 1.2.
  Expected behavior: client returns a Status of RETURN_SUCCESS, but truncate the message
  to consider only the two first versions, as indicated in the message.
**/
void TestSpdmRequesterGetVersionCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->ConnectionInfo.Version.SpdmVersionCount, 2);
}

/**
  Test 11: receiving a correct VERSION message with available version 10.0 and 10.1, but
  the requester do not have compatible versions with the responder.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterGetVersionCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xB;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

/**
  Test 12: receiving a VERSION message in SPDM version 1.1 (in the header), but correct
  1.0-version format, with available version 1.0 and 1.1.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterGetVersionCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xC;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

/**
  Test 13: receiving a VERSION message with wrong SPDM RequestResponseCode (in this
  case, GET_VERSION 0x84 instead of VERSION 0x04). The remaining data is a correct
  VERSION message, with available version 1.0 and 1.1.
  Expected behavior: client returns a Status of RETURN_DEVICE_ERROR.
**/
void TestSpdmRequesterGetVersionCase13(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xD;

  Status = SpdmGetVersion (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

SPDM_TEST_CONTEXT       mSpdmRequesterGetVersionTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterGetVersionTestSendMessage,
  SpdmRequesterGetVersionTestReceiveMessage,
};

int SpdmRequesterGetVersionTestMain(void) {
  const struct CMUnitTest SpdmRequesterGetVersionTests[] = {
      cmocka_unit_test(TestSpdmRequesterGetVersionCase1),
      cmocka_unit_test(TestSpdmRequesterGetVersionCase2),
      cmocka_unit_test(TestSpdmRequesterGetVersionCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterGetVersionCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterGetVersionCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetVersionCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterGetVersionCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterGetVersionCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetVersionCase9),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterGetVersionCase10),
      // Successful response + device error
      cmocka_unit_test(TestSpdmRequesterGetVersionCase11),
      cmocka_unit_test(TestSpdmRequesterGetVersionCase12),
      cmocka_unit_test(TestSpdmRequesterGetVersionCase13),
  };

  SetupSpdmTestContext (&mSpdmRequesterGetVersionTestContext);

  return cmocka_run_group_tests(SpdmRequesterGetVersionTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
