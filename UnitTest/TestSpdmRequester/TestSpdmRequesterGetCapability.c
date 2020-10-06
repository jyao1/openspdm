/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

#define  DEFAULT_CAPABILITY_FLAG   (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP)

RETURN_STATUS
EFIAPI
SpdmRequesterGetCapabilityTestSendMessage (
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
SpdmRequesterGetCapabilityTestReceiveMessage (
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
    SPDM_CAPABILITIES_RESPONSE    *SpdmResponse;

    *ResponseSize = 1 + sizeof(SPDM_CAPABILITIES_RESPONSE);
    *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
    SpdmResponse = (VOID *)((UINT8 *)Response + 1);

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_CAPABILITIES;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->CTExponent = 0;
    SpdmResponse->Flags = DEFAULT_CAPABILITY_FLAG;
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_CAPABILITIES_RESPONSE    *SpdmResponse;

    *ResponseSize = 1 + sizeof(SPDM_CAPABILITIES_RESPONSE);
    *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
    SpdmResponse = (VOID *)((UINT8 *)Response + 1);

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_CAPABILITIES;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->CTExponent = 0;
    SpdmResponse->Flags = DEFAULT_CAPABILITY_FLAG;
  }
    return RETURN_SUCCESS;

  case 0x4:
  {
    SPDM_ERROR_RESPONSE    *SpdmResponse;

    *ResponseSize = 1 + sizeof(SPDM_ERROR_RESPONSE);
    *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
    SpdmResponse = (VOID *)((UINT8 *)Response + 1);

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse->Header.Param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    SpdmResponse->Header.Param2 = 0;
  }
    return RETURN_SUCCESS;

  case 0x5:
  {
    SPDM_ERROR_RESPONSE	 *SpdmResponse;

    *ResponseSize = 1 + sizeof(SPDM_ERROR_RESPONSE);
    *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
    SpdmResponse = (VOID *)((UINT8 *)Response + 1);

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

      *ResponseSize = 1 + sizeof(SPDM_ERROR_RESPONSE);
      *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
      SpdmResponse = (VOID *)((UINT8 *)Response + 1);

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse->Header.Param1 = SPDM_ERROR_CODE_BUSY;
      SpdmResponse->Header.Param2 = 0;
    } else if (SubIndex1 == 1) {
      SPDM_CAPABILITIES_RESPONSE    *SpdmResponse;

      *ResponseSize = 1 + sizeof(SPDM_CAPABILITIES_RESPONSE);
      *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
      SpdmResponse = (VOID *)((UINT8 *)Response + 1);

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->CTExponent = 0;
      SpdmResponse->Flags = DEFAULT_CAPABILITY_FLAG;
    }
    SubIndex1 ++;
  }
    return RETURN_SUCCESS;

  case 0x7:
  {
    SPDM_ERROR_RESPONSE  *SpdmResponse;

    *ResponseSize = 1 + sizeof(SPDM_ERROR_RESPONSE);
    *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
    SpdmResponse = (VOID *)((UINT8 *)Response + 1);

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

    *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
    SpdmResponse = (VOID *)((UINT8 *)Response + 1);
    ExtendErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(SpdmResponse + 1);
    *ResponseSize = 1 + sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY);

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse->Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    SpdmResponse->Header.Param2 = 0;
    ExtendErrorData->RDTExponent = 1;
    ExtendErrorData->RDTM = 1;
    ExtendErrorData->RequestCode = SPDM_GET_CAPABILITIES;
    ExtendErrorData->Token = 0;
  }
    return RETURN_SUCCESS;

  case 0x9:
  {
    STATIC UINTN SubIndex2 = 0;
    if (SubIndex2 == 0) {
      SPDM_ERROR_RESPONSE	 *SpdmResponse;
      SPDM_ERROR_DATA_RESPONSE_NOT_READY   *ExtendErrorData;

      *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
      SpdmResponse = (VOID *)((UINT8 *)Response + 1);
      ExtendErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(SpdmResponse + 1);
      *ResponseSize = 1 + sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY);

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse->Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
      SpdmResponse->Header.Param2 = 0;
      ExtendErrorData->RDTExponent = 1;
      ExtendErrorData->RDTM = 1;
      ExtendErrorData->RequestCode = SPDM_GET_CAPABILITIES;
      ExtendErrorData->Token = 1;
    } else if (SubIndex2 == 1) {
      SPDM_CAPABILITIES_RESPONSE    *SpdmResponse;

      *ResponseSize = 1 + sizeof(SPDM_CAPABILITIES_RESPONSE);
      *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
      SpdmResponse = (VOID *)((UINT8 *)Response + 1);

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->CTExponent = 0;
      SpdmResponse->Flags = DEFAULT_CAPABILITY_FLAG;
    }
    SubIndex2 ++;
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

void TestSpdmRequesterGetCapabilityCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                RequesterCTExponent;
  UINT32               RequesterFlags;
  UINT8                ResponderCTExponent;
  UINT32               ResponderFlags;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  RequesterCTExponent = 0;
  RequesterFlags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext, RequesterCTExponent, RequesterFlags, &ResponderCTExponent, &ResponderFlags);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                RequesterCTExponent;
  UINT32               RequesterFlags;
  UINT8                ResponderCTExponent;
  UINT32               ResponderFlags;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  RequesterCTExponent = 0;
  RequesterFlags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext, RequesterCTExponent, RequesterFlags, &ResponderCTExponent, &ResponderFlags);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponderCTExponent, 0);
  assert_int_equal (ResponderFlags, DEFAULT_CAPABILITY_FLAG);
}

void TestSpdmRequesterGetCapabilityCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                RequesterCTExponent;
  UINT32               RequesterFlags;
  UINT8                ResponderCTExponent;
  UINT32               ResponderFlags;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->SpdmCmdReceiveState = 0;

  RequesterCTExponent = 0;
  RequesterFlags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext, RequesterCTExponent, RequesterFlags, &ResponderCTExponent, &ResponderFlags);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                RequesterCTExponent;
  UINT32               RequesterFlags;
  UINT8                ResponderCTExponent;
  UINT32               ResponderFlags;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  RequesterCTExponent = 0;
  RequesterFlags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext, RequesterCTExponent, RequesterFlags, &ResponderCTExponent, &ResponderFlags);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                RequesterCTExponent;
  UINT32               RequesterFlags;
  UINT8                ResponderCTExponent;
  UINT32               ResponderFlags;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  RequesterCTExponent = 0;
  RequesterFlags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext, RequesterCTExponent, RequesterFlags, &ResponderCTExponent, &ResponderFlags);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
}

void TestSpdmRequesterGetCapabilityCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                RequesterCTExponent;
  UINT32               RequesterFlags;
  UINT8                ResponderCTExponent;
  UINT32               ResponderFlags;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  RequesterCTExponent = 0;
  RequesterFlags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext, RequesterCTExponent, RequesterFlags, &ResponderCTExponent, &ResponderFlags);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponderCTExponent, 0);
  assert_int_equal (ResponderFlags, DEFAULT_CAPABILITY_FLAG);
}

void TestSpdmRequesterGetCapabilityCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                RequesterCTExponent;
  UINT32               RequesterFlags;
  UINT8                ResponderCTExponent;
  UINT32               ResponderFlags;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  RequesterCTExponent = 0;
  RequesterFlags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext, RequesterCTExponent, RequesterFlags, &ResponderCTExponent, &ResponderFlags);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->SpdmCmdReceiveState, 0);
}

void TestSpdmRequesterGetCapabilityCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                RequesterCTExponent;
  UINT32               RequesterFlags;
  UINT8                ResponderCTExponent;
  UINT32               ResponderFlags;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  RequesterCTExponent = 0;
  RequesterFlags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext, RequesterCTExponent, RequesterFlags, &ResponderCTExponent, &ResponderFlags);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                RequesterCTExponent;
  UINT32               RequesterFlags;
  UINT8                ResponderCTExponent;
  UINT32               ResponderFlags;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  RequesterCTExponent = 0;
  RequesterFlags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext, RequesterCTExponent, RequesterFlags, &ResponderCTExponent, &ResponderFlags);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponderCTExponent, 0);
  assert_int_equal (ResponderFlags, DEFAULT_CAPABILITY_FLAG);
}

SPDM_TEST_CONTEXT       mSpdmRequesterGetCapabilityTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterGetCapabilityTestSendMessage,
  SpdmRequesterGetCapabilityTestReceiveMessage,
};

int SpdmRequesterGetCapabilityTestMain(void) {
  const struct CMUnitTest SpdmRequesterGetCapabilityTests[] = {
      // SendRequest failed
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase1),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase2),
      // SpdmCmdReceiveState check failed
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase9),
  };
  
  SetupSpdmTestContext (&mSpdmRequesterGetCapabilityTestContext);

  return cmocka_run_group_tests(SpdmRequesterGetCapabilityTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
