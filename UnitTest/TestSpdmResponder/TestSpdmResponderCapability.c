/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest1 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_CAPABILITIES,
  },
};
// Version 1.0 message consists of only header (size 0x04).
// However, SPDM_GET_CAPABILITIES_REQUEST has a size of 0x0c.
// Therefore, sending a v1.0 request with this structure results in a wrong size request.
// Size information was corrected to reflect the actual size of a get_capabilities 1.0 message.
UINTN mSpdmGetCapabilityRequest1Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_CAPABILITIES,
  },
};
UINTN mSpdmGetCapabilityRequest2Size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest3 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
  0x12345678//Flags
};
UINTN mSpdmGetCapabilityRequest3Size = sizeof(mSpdmGetCapabilityRequest3);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest4 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest4Size = sizeof(mSpdmGetCapabilityRequest4);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest5 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (0x01 |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest5Size = sizeof(mSpdmGetCapabilityRequest5);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest6 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest6Size = sizeof(mSpdmGetCapabilityRequest6);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest7 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest7Size = sizeof(mSpdmGetCapabilityRequest7);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest8 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (0x100000 |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest8Size = sizeof(mSpdmGetCapabilityRequest8);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest9 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest9Size = sizeof(mSpdmGetCapabilityRequest9);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest10 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  //
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest10Size = sizeof(mSpdmGetCapabilityRequest10);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest11 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  //
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest11Size = sizeof(mSpdmGetCapabilityRequest11);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest12 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  //
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP
  //
 )
};
UINTN mSpdmGetCapabilityRequest12Size = sizeof(mSpdmGetCapabilityRequest12);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest13 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  //
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP
  //
 )
};
UINTN mSpdmGetCapabilityRequest13Size = sizeof(mSpdmGetCapabilityRequest13);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest14 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest14Size = sizeof(mSpdmGetCapabilityRequest14);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest15 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP
 )
};
UINTN mSpdmGetCapabilityRequest15Size = sizeof(mSpdmGetCapabilityRequest15);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest16 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest16Size = sizeof(mSpdmGetCapabilityRequest16);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest17 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  //
  //
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP
 )
};
UINTN mSpdmGetCapabilityRequest17Size = sizeof(mSpdmGetCapabilityRequest17);

SPDM_GET_CAPABILITIES_REQUEST    mSpdmGetCapabilityRequest18 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CAPABILITIES,
  },//Header
  0x00,//Reserved
  0x01,//CTExponent
  0x0000,//Reserved, 2 bytes
 (// //Flags
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
  SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP
 )
};
UINTN mSpdmGetCapabilityRequest18Size = sizeof(mSpdmGetCapabilityRequest18);



void TestSpdmResponderCapabilityCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest1Size, &mSpdmGetCapabilityRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CAPABILITIES_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest1.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CAPABILITIES);
}

void TestSpdmResponderCapabilityCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest2Size, &mSpdmGetCapabilityRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest2.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest1Size, &mSpdmGetCapabilityRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest1.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
}

void TestSpdmResponderCapabilityCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest1Size, &mSpdmGetCapabilityRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest1.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
}

// According to spec, a responder shall not answer a get_capabilties with a ResponseNotReady
void TestSpdmResponderCapabilityCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest1Size, &mSpdmGetCapabilityRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest1.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(&SpdmResponse->Reserved);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_GET_CAPABILITIES);
}

void TestSpdmResponderCapabilityCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ResponseState = SpdmResponseStateNormal;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest1Size, &mSpdmGetCapabilityRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest1.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}
//New from here
void TestSpdmResponderCapabilityCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ResponseState = SpdmResponseStateNormal;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest3Size, &mSpdmGetCapabilityRequest3, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest3.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest4Size, &mSpdmGetCapabilityRequest4, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CAPABILITIES_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest4.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CAPABILITIES);
}

void TestSpdmResponderCapabilityCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest5Size, &mSpdmGetCapabilityRequest5, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CAPABILITIES_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest4.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CAPABILITIES);
}

void TestSpdmResponderCapabilityCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xa;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest6Size, &mSpdmGetCapabilityRequest6, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest6.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xb;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest7Size, &mSpdmGetCapabilityRequest7, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest7.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xc;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest8Size, &mSpdmGetCapabilityRequest8, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CAPABILITIES_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest4.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CAPABILITIES);
}

void TestSpdmResponderCapabilityCase13(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xd;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest9Size, &mSpdmGetCapabilityRequest9, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest9.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase14(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xe;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest10Size, &mSpdmGetCapabilityRequest10, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest10.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase15(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xf;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest11Size, &mSpdmGetCapabilityRequest11, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest11.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase16(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x10;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest12Size, &mSpdmGetCapabilityRequest12, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest12.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase17(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x11;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest13Size, &mSpdmGetCapabilityRequest13, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest13.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase18(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x12;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest14Size, &mSpdmGetCapabilityRequest14, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest14.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase19(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x13;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest15Size, &mSpdmGetCapabilityRequest15, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest15.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase20(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x14;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest16Size, &mSpdmGetCapabilityRequest16, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest16.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase21(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x15;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest17Size, &mSpdmGetCapabilityRequest17, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest17.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

void TestSpdmResponderCapabilityCase22(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CAPABILITIES_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x16;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseCapability (SpdmContext, mSpdmGetCapabilityRequest18Size, &mSpdmGetCapabilityRequest18, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CAPABILITIES_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (mSpdmGetCapabilityRequest18.Header.SPDMVersion, SpdmResponse->Header.SPDMVersion);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CAPABILITIES);
}

SPDM_TEST_CONTEXT       mSpdmResponderCapabilityTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderCapabilityTestMain(void) {
  const struct CMUnitTest SpdmResponderCapabilityTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderCapabilityCase1),
    // Bad Request Size
    cmocka_unit_test(TestSpdmResponderCapabilityCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderCapabilityCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderCapabilityCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderCapabilityCase5),
    // ConnectionState Check
    cmocka_unit_test(TestSpdmResponderCapabilityCase6),
    // Invalid requester capabilities flag (random flag)
    cmocka_unit_test(TestSpdmResponderCapabilityCase7),
    // V1.1 Success case, all possible flags set
    cmocka_unit_test(TestSpdmResponderCapabilityCase8),
    // Requester capabilities flag bit 0 is set. Reserved value should ne ignored
    cmocka_unit_test(TestSpdmResponderCapabilityCase9),
    // MEAS_CAP is set (MEAS_CAP shall be cleared)
    cmocka_unit_test(TestSpdmResponderCapabilityCase10),
    // MEAS_FRESH_CAP is set (MEAS_FRESH_CAP shall be cleared)
    cmocka_unit_test(TestSpdmResponderCapabilityCase11),
    // Requester capabilities flag byte 2 bit 1 is set. Reserved value should ne ignored
    cmocka_unit_test(TestSpdmResponderCapabilityCase12),
    // PUB_KEY_ID_CAP and CERT_CAP set (Flags are mutually exclusive)
    cmocka_unit_test(TestSpdmResponderCapabilityCase13),
    // ENCRYPT_CAP set and KEY_EX_CAP and PSK_CAP cleared (ENCRYPT_CAP demands KEY_EX_CAP or PSK_CAP to be set)
    cmocka_unit_test(TestSpdmResponderCapabilityCase14),
    // MAC_CAP set and KEY_EX_CAP and PSK_CAP cleared (MAC_CAP demands KEY_EX_CAP or PSK_CAP to be set)
    cmocka_unit_test(TestSpdmResponderCapabilityCase15),
    // KEY_EX_CAP set and ENCRYPT_CAP and MAC_CAP cleared (KEY_EX_CAP demands ENCRYPT_CAP or MAC_CAP to be set)
    cmocka_unit_test(TestSpdmResponderCapabilityCase16),
    // PSK_CAP set and ENCRYPT_CAP and MAC_CAP cleared (PSK_CAP demands ENCRYPT_CAP or MAC_CAP to be set)
    cmocka_unit_test(TestSpdmResponderCapabilityCase17),
    // ENCAP_CAP cleared and MUT_AUTH set (MUT_AUTH demands ENCAP_CAP to be set)
    cmocka_unit_test(TestSpdmResponderCapabilityCase18),
    // CERT_CAP set and PUB_KEY_ID_CAP set (PUB_KEY_ID_CAP demands CERT_CAP to be cleared)
    cmocka_unit_test(TestSpdmResponderCapabilityCase19),
    // KEY_EX_CAP cleared and HANDSHAKE_IN_THE_CLEAR_CAP set (HANDSHAKE_IN_THE_CLEAR_CAP demands KEY_EX_CAP to be set)
    cmocka_unit_test(TestSpdmResponderCapabilityCase20),
    // ENCRYPT_CAP and MAC_CAP cleared and HANDSHAKE_IN_THE_CLEAR_CAP set (HANDSHAKE_IN_THE_CLEAR_CAP shall be cleared if ENCRYPT_CAP and MAC_CAP are cleared)
    cmocka_unit_test(TestSpdmResponderCapabilityCase21),
    // CERT_CAP cleared and PUB_KEY_ID_CAP set (PUB_KEY_ID_CAP demands CERT_CAP to be cleared)
    cmocka_unit_test(TestSpdmResponderCapabilityCase22),
  };

  SetupSpdmTestContext (&mSpdmResponderCapabilityTestContext);

  return cmocka_run_group_tests(SpdmResponderCapabilityTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
