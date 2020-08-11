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
SpdmClientSendRequest (
  IN     SPDM_IO_PROTOCOL        *This,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = SPDM_TEST_CONTEXT_FROM_SPDM_PROTOCOL(This);
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;
  case 0x2:
    return RETURN_SUCCESS;
  case 0x3:
    return RETURN_SUCCESS;
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmClientReceiveResponse (
  IN     SPDM_IO_PROTOCOL        *This,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = SPDM_TEST_CONTEXT_FROM_SPDM_PROTOCOL(This);
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;

  case 0x2:
  {
    MY_SPDM_VERSION_RESPONSE    *SpdmResponse;
        
    *ResponseSize = sizeof(MY_SPDM_VERSION_RESPONSE);
    *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
    SpdmResponse = Response;

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
        
    *ResponseSize = sizeof(SPDM_VERSION_RESPONSE);
    *ResponseSize = ALIGN_VALUE (*ResponseSize, SpdmTestContext->SpdmContext.Alignment);
    SpdmResponse = Response;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_VERSION;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->VersionNumberEntryCount = 0;
  }
    return RETURN_SUCCESS;
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmClientSecureSendRequest (
  IN     SPDM_IO_PROTOCOL                       *This,
  IN     UINT32                                 SessionId,
  IN     UINTN                                  RequestSize,
  IN     VOID                                   *Request,
  IN     UINT64                                 Timeout
  )
{
  return RETURN_UNSUPPORTED;
}

RETURN_STATUS
EFIAPI
SpdmClientSecureReceiveResponse (
  IN     SPDM_IO_PROTOCOL                       *This,
  IN     UINT32                                 SessionId,
  IN OUT UINTN                                  *ResponseSize,
  IN OUT VOID                                   *Response,
  IN     UINT64                                 Timeout
  )
{
  return RETURN_UNSUPPORTED;
}

SPDM_TEST_CONTEXT       mSpdmTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  {
    SpdmClientSendRequest,
    SpdmClientReceiveResponse,
    SpdmClientSecureSendRequest,
    SpdmClientSecureReceiveResponse,
    SpdmIoSecureMessagingTypeDmtfMtcp,
    sizeof(UINT32)
  },
};

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

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(TestSpdmRequesterGetVersionCase1),
      cmocka_unit_test(TestSpdmRequesterGetVersionCase2),
      cmocka_unit_test(TestSpdmRequesterGetVersionCase3),
  };

  return cmocka_run_group_tests(tests, TestSpdmRequesterGroupSetup, TestSpdmRequesterGroupTeardown);
}
