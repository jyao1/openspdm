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
SpdmRequesterGetVersionTestReceiveMessage (
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
    MY_SPDM_VERSION_RESPONSE    *SpdmResponse;
        
    *ResponseSize = 1+ sizeof(MY_SPDM_VERSION_RESPONSE);
    *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
    SpdmResponse = (VOID *)((UINT8 *)Response + 1);

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_VERSION;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->VersionNumberEntryCount = 2;
    SpdmResponse->VersionNumberEntry[0].MajorVersion = 1;
    SpdmResponse->VersionNumberEntry[0].MinorVersion = 0;
    SpdmResponse->VersionNumberEntry[1].MajorVersion = 1;
    SpdmResponse->VersionNumberEntry[1].MinorVersion = 1;
  }    
    return RETURN_SUCCESS;
    
  case 0x3:
  {
    SPDM_VERSION_RESPONSE    *SpdmResponse;
        
    *ResponseSize = 1 + sizeof(SPDM_VERSION_RESPONSE);
    *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
    SpdmResponse = (VOID *)((UINT8 *)Response + 1);

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_VERSION;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->VersionNumberEntryCount = 0;
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
      MY_SPDM_VERSION_RESPONSE    *SpdmResponse;

      *ResponseSize = 1 + sizeof(MY_SPDM_VERSION_RESPONSE);
      *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
      SpdmResponse = (VOID *)((UINT8 *)Response + 1);

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_VERSION;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->VersionNumberEntryCount = 2;
      SpdmResponse->VersionNumberEntry[0].MajorVersion = 1;
      SpdmResponse->VersionNumberEntry[0].MinorVersion = 0;
      SpdmResponse->VersionNumberEntry[1].MajorVersion = 1;
      SpdmResponse->VersionNumberEntry[1].MinorVersion = 1;
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
    ExtendErrorData->RequestCode = SPDM_GET_VERSION;
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
      ExtendErrorData->RequestCode = SPDM_GET_VERSION;
      ExtendErrorData->Token = 1;
    } else if (SubIndex2 == 1) {
      MY_SPDM_VERSION_RESPONSE    *SpdmResponse;

      *ResponseSize = 1 + sizeof(MY_SPDM_VERSION_RESPONSE);
      *(UINT8 *)Response = TEST_MESSAGE_TYPE_SPDM;
      SpdmResponse = (VOID *)((UINT8 *)Response + 1);

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_VERSION;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->VersionNumberEntryCount = 2;
      SpdmResponse->VersionNumberEntry[0].MajorVersion = 1;
      SpdmResponse->VersionNumberEntry[0].MinorVersion = 0;
      SpdmResponse->VersionNumberEntry[1].MajorVersion = 1;
      SpdmResponse->VersionNumberEntry[1].MinorVersion = 1;
    }
    SubIndex2 ++;
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

void TestSpdmRequesterGetVersionCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  Status = SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetVersionCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  Status = SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
  assert_int_equal (Status, RETURN_SUCCESS);
}

void TestSpdmRequesterGetVersionCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  Status = SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetVersionCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  Status = SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetVersionCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  Status = SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
}

void TestSpdmRequesterGetVersionCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  Status = SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
  assert_int_equal (Status, RETURN_SUCCESS);
}

void TestSpdmRequesterGetVersionCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  Status = SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->SpdmCmdReceiveState, 0);
}

void TestSpdmRequesterGetVersionCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  Status = SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetVersionCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;

  VersionNumberEntryCount = MAX_SPDM_VERSION_COUNT;
  ZeroMem (VersionNumberEntry, sizeof(VersionNumberEntry));
  Status = SpdmGetVersion (SpdmContext, &VersionNumberEntryCount, VersionNumberEntry);
  assert_int_equal (Status, RETURN_SUCCESS);
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
  };
  
  SetupSpdmTestContext (&mSpdmRequesterGetVersionTestContext);

  return cmocka_run_group_tests(SpdmRequesterGetVersionTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
