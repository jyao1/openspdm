/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

#define  DEFAULT_CAPABILITY_FLAG   (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP)
#define  DEFAULT_CAPABILITY_FLAG_VERSION_11   (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)
#define  DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)

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
  case 0xa:
    return RETURN_SUCCESS;
  case 0xb:
    return RETURN_SUCCESS;
  case 0xc:
    return RETURN_SUCCESS;
  case 0xd:
    return RETURN_SUCCESS;
  case 0xe:
    return RETURN_SUCCESS;
  case 0xf:
    return RETURN_SUCCESS;
  case 0x10:
    return RETURN_SUCCESS;
  case 0x11:
    return RETURN_SUCCESS;
  case 0x12:
    return RETURN_SUCCESS;
  case 0x13:
    return RETURN_SUCCESS;
  case 0x14:
    return RETURN_SUCCESS;
  case 0x15:
    return RETURN_SUCCESS;
  case 0x16:
    return RETURN_SUCCESS;
  case 0x17:
    return RETURN_SUCCESS;
  case 0x18:
    return RETURN_SUCCESS;
  case 0x19:
    return RETURN_SUCCESS;
  case 0x1a:
    return RETURN_SUCCESS;
  case 0x1b:
    return RETURN_SUCCESS;
  case 0x1c:
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
    SPDM_CAPABILITIES_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.CTExponent = 0;
    SpdmResponse.Flags = DEFAULT_CAPABILITY_FLAG;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_CAPABILITIES_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.CTExponent = 0;
    SpdmResponse.Flags = DEFAULT_CAPABILITY_FLAG;

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
      SPDM_CAPABILITIES_RESPONSE    SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_FLAG;

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
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_GET_CAPABILITIES;
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
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_GET_CAPABILITIES;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    } else if (SubIndex2 == 1) {
      SPDM_CAPABILITIES_RESPONSE    SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_FLAG;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
    SubIndex2 ++;
  }
    return RETURN_SUCCESS;

  case 0xa:
  {
    SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.CTExponent = 0;
    SpdmResponse.Flags = (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
                          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
                          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
                          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xb:
  {
    SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.CTExponent = 0;
    SpdmResponse.Flags = !(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
                          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
                          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
                          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xc:
  {
    SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.CTExponent = 0;
    SpdmResponse.Flags = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xd:
  {
    SPDM_CAPABILITIES_RESPONSE SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SPDM_MESSAGE_HEADER), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xe:
  {
    SPDM_CAPABILITIES_RESPONSE SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.CTExponent = 0;
    SpdmResponse.Flags = DEFAULT_CAPABILITY_FLAG;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse)+sizeof(UINT8), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_DEVICE_ERROR;

    case 0xf:
    {
      SPDM_CAPABILITIES_RESPONSE SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_FLAG;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse)-sizeof(UINT8), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_DEVICE_ERROR;

    case 0x10:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x11:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x12:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x13:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;
      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));
      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x14:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x15:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x16:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP));

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x17:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP));

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x18:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP));

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x19:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP));

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x1a:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

    case 0x1b:
    {
      SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
      SpdmResponse.Header.RequestResponseCode = SPDM_GET_CAPABILITIES;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.CTExponent = 0;
      SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
      return RETURN_SUCCESS;

      case 0x1c:
      {
        SPDM_CAPABILITIES_RESPONSE  SpdmResponse;

        ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
        SpdmResponse.Header.SPDMVersion = 0xFF;
        SpdmResponse.Header.RequestResponseCode = SPDM_CAPABILITIES;
        SpdmResponse.Header.Param1 = 0;
        SpdmResponse.Header.Param2 = 0;
        SpdmResponse.CTExponent = 0;
        SpdmResponse.Flags = DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11;

        SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
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

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_FLAG);
}

void TestSpdmRequesterGetCapabilityCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_UNSUPPORTED);
}

void TestSpdmRequesterGetCapabilityCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
}

void TestSpdmRequesterGetCapabilityCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_FLAG);
}

void TestSpdmRequesterGetCapabilityCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->ConnectionInfo.ConnectionState, SpdmConnectionStateNotStarted);
}

void TestSpdmRequesterGetCapabilityCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
//  assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
//  assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_FLAG);
}

void TestSpdmRequesterGetCapabilityCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xa;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, (SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
                                     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                                     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
                                     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
                                     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP));
}

void TestSpdmRequesterGetCapabilityCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xb;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, !(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP |
                                     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
                                     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
                                     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
                                     SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP));
}

void TestSpdmRequesterGetCapabilityCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xc;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP);
}

void TestSpdmRequesterGetCapabilityCase13(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xd;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase14(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xe;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase15(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xf;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase16(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x10;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11);
}

void TestSpdmRequesterGetCapabilityCase17(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x11;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void TestSpdmRequesterGetCapabilityCase18(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x12;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void TestSpdmRequesterGetCapabilityCase19(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x13;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void TestSpdmRequesterGetCapabilityCase20(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x14;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void TestSpdmRequesterGetCapabilityCase21(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x15;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void TestSpdmRequesterGetCapabilityCase22(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x16;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)));
}

void TestSpdmRequesterGetCapabilityCase23(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x17;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP)));
}

void TestSpdmRequesterGetCapabilityCase24(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x18;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)));
}

void TestSpdmRequesterGetCapabilityCase25(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x19;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 & (0xFFFFFFFF^(SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)));
}

void TestSpdmRequesterGetCapabilityCase26(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1a;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.CTExponent, 0);
  //assert_int_equal (SpdmContext->ConnectionInfo.Capability.Flags, DEFAULT_CAPABILITY_RESPONSE_FLAG_VERSION_11 | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP);
}

void TestSpdmRequesterGetCapabilityCase27(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1b;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterGetCapabilityCase28(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1c;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  ResetManagedBuffer(&SpdmContext->Transcript.MessageA);

  SpdmContext->LocalContext.Capability.CTExponent = 0;
  SpdmContext->LocalContext.Capability.Flags = DEFAULT_CAPABILITY_FLAG_VERSION_11;
  Status = SpdmGetCapabilities (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
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
      // ConnectionState check failed
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
      // CORRECTION for both case 8 and 9: A RESPONSE_NOT_READY is an invalid response for GET_CAPABILITIES
      // File SpdmRequesterLibHandleErrorResponse.c was corrected to reflect the documentation and now returns a RETURN_DEVICE_ERROR.
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase9),
      // All flags set in response
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase10),
      // All flags cleared in response
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase11),
      // MEAS_FRESH_CAP set, others cleared in response. This behaviour is undefined in the protocol
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase12),
      // Receives just header
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase13),
      // Receives a message 1 byte bigger than the capabilites response message
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase14),
      // Receives a message 1 byte smaller than the capabilites response message
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase15),
      // From this point forward, tests are performed with version 1.1
      // Requester sends all flags set and receives successful response with all flags set
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase16),
      // Requester sends all flags set and receives successful response with flags encrypt_cap and mac_cap set, and key_ex_cap and psk_cap cleared
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase17),
      // Requester sends all flags set and receives successful response with flags encrypt_cap set and mac_cap cleared, and key_ex_cap and psk_cap cleared
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase18),
      // Requester sends all flags set and receives successful response with flags encrypt_cap cleared and mac_cap set, and key_ex_cap and psk_cap cleared
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase19),
      // Requester sends all flags set and receives successful response with flags encrypt_cap cleared and mac_cap cleared, and key_ex_cap and psk_cap set
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase20),
      // Requester sends all flags set and receives successful response with flags encrypt_cap and mac_cap cleared, and key_ex_cap set and psk_cap cleared
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase21),
      // Requester sends all flags set and receives successful response with flags encrypt_cap and mac_cap cleared, and key_ex_cap cleared and psk_cap set
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase22),
      // Requester sends all flags set and receives successful response with flags mut_auth_cap set, and encap_cap cleared
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase23),
      // Requester sends all flags set and receives successful response with flags handshake_in_the_clear_cap set, and key_ex_cap cleared
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase24),
      // Requester sends all flags set and receives successful response with flags handshake_in_the_clear_cap set, and encrypt_cap and mac_cap cleared
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase25),
      // Requester sends all flags set and receives successful response with flags pub_key_id_cap set, and cert_cap set
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase26),
      // Requester sends all flags set and receives response with get_capabilities request code (wrong response code)
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase27),
      // Requester sends all flags set and receives response with 0xFF as version code (wrong version code)
      cmocka_unit_test(TestSpdmRequesterGetCapabilityCase28),
  };

  SetupSpdmTestContext (&mSpdmRequesterGetCapabilityTestContext);

  return cmocka_run_group_tests(SpdmRequesterGetCapabilityTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
