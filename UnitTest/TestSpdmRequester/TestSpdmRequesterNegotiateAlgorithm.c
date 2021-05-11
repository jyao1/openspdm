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
  UINT16               Length;
  UINT8                MeasurementSpecificationSel;
  UINT8                Reserved;
  UINT32               MeasurementHashAlgo;
  UINT32               BaseAsymSel;
  UINT32               BaseHashSel;
  UINT8                Reserved2[12];
  UINT8                ExtAsymSelCount;
  UINT8                ExtHashSelCount;
  UINT16               Reserved3;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  StructTable[4];
} SPDM_ALGORITHMS_RESPONSE_SPDM11;
#pragma pack()

RETURN_STATUS
EFIAPI
SpdmRequesterNegotiateAlgorithmTestSendMessage (
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
  case 0xD:
    return RETURN_SUCCESS;
  case 0xE:
    return RETURN_SUCCESS;
  case 0xF:
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
  case 0x1A:
    return RETURN_SUCCESS;
  case 0x1B:
    return RETURN_SUCCESS;
  case 0x1C:
    return RETURN_SUCCESS;
  case 0x1D:
    return RETURN_SUCCESS;
  case 0x1E:
    return RETURN_SUCCESS;
  case 0x1F:
    return RETURN_SUCCESS;
  case 0x20:
    return RETURN_SUCCESS;
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmRequesterNegotiateAlgorithmTestReceiveMessage (
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
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

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
      SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
      SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
      SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
      SpdmResponse.BaseAsymSel = mUseAsymAlgo;
      SpdmResponse.BaseHashSel = mUseHashAlgo;
      SpdmResponse.ExtAsymSelCount = 0;
      SpdmResponse.ExtHashSelCount = 0;

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
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_NEGOTIATE_ALGORITHMS;
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
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_NEGOTIATE_ALGORITHMS;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    } else if (SubIndex2 == 1) {
      SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

      ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
      SpdmResponse.Header.Param1 = 0;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
      SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
      SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
      SpdmResponse.BaseAsymSel = mUseAsymAlgo;
      SpdmResponse.BaseHashSel = mUseHashAlgo;
      SpdmResponse.ExtAsymSelCount = 0;
      SpdmResponse.ExtHashSelCount = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    }
    SubIndex2 ++;
  }
    return RETURN_SUCCESS;

  case 0xA:
  {
    SPDM_ALGORITHMS_RESPONSE  SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = 0;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xB:
  {
    SPDM_ALGORITHMS_RESPONSE  SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = 0;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xC:
  {
    SPDM_ALGORITHMS_RESPONSE  SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = 0;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xD:
  {
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SPDM_MESSAGE_HEADER), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xE:
  {
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;


    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SPDM_ALGORITHMS_RESPONSE)/2, &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xF:
  {
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 2;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x10:
  {
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 2;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  // case 0x11:
  // {
  //   SPDM_ALGORITHMS_RESPONSE    SpdmResponse;
  //
  //   ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  //   SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  //   SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
  //   SpdmResponse.Header.Param1 = 0;
  //   SpdmResponse.Header.Param2 = 0;
  //   SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
  //   SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
  //   SpdmResponse.MeasurementHashAlgo = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512;
  //   SpdmResponse.BaseAsymSel = mUseAsymAlgo;
  //   SpdmResponse.BaseHashSel = mUseHashAlgo;
  //   SpdmResponse.ExtAsymSelCount = 0;
  //   SpdmResponse.ExtHashSelCount = 0;
  //
  //   SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  // }
  //   return RETURN_SUCCESS;

  case 0x11:
  {
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x12:
  {
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x13:
  {
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo|SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x14:
  {
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo|SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x15:
  {
    SPDM_ALGORITHMS_RESPONSE    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 0;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo|SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x16:
  {
    SPDM_ALGORITHMS_RESPONSE_SPDM11    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 4;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;
    SpdmResponse.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    SpdmResponse.StructTable[0].AlgCount = 0x20;
    SpdmResponse.StructTable[0].AlgSupported = mUseDheAlgo;
    SpdmResponse.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    SpdmResponse.StructTable[1].AlgCount = 0x20;
    SpdmResponse.StructTable[1].AlgSupported = mUseAeadAlgo;
    SpdmResponse.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    SpdmResponse.StructTable[2].AlgCount = 0x20;
    SpdmResponse.StructTable[2].AlgSupported = mUseReqAsymAlgo;
    SpdmResponse.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    SpdmResponse.StructTable[3].AlgCount = 0x20;
    SpdmResponse.StructTable[3].AlgSupported = mUseKeyScheduleAlgo;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x17:
  {
    SPDM_ALGORITHMS_RESPONSE_SPDM11    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 4;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;
    SpdmResponse.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    SpdmResponse.StructTable[0].AlgCount = 0x20;
    SpdmResponse.StructTable[0].AlgSupported = mUseDheAlgo;
    SpdmResponse.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    SpdmResponse.StructTable[1].AlgCount = 0x20;
    SpdmResponse.StructTable[1].AlgSupported = mUseAeadAlgo;
    SpdmResponse.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    SpdmResponse.StructTable[2].AlgCount = 0x20;
    SpdmResponse.StructTable[2].AlgSupported = mUseReqAsymAlgo;
    SpdmResponse.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    SpdmResponse.StructTable[3].AlgCount = 0x20;
    SpdmResponse.StructTable[3].AlgSupported = mUseKeyScheduleAlgo;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x18:
  {
    SPDM_ALGORITHMS_RESPONSE_SPDM11    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 4;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;
    SpdmResponse.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    SpdmResponse.StructTable[0].AlgCount = 0x20;
    SpdmResponse.StructTable[0].AlgSupported = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
    SpdmResponse.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    SpdmResponse.StructTable[1].AlgCount = 0x20;
    SpdmResponse.StructTable[1].AlgSupported = mUseAeadAlgo;
    SpdmResponse.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    SpdmResponse.StructTable[2].AlgCount = 0x20;
    SpdmResponse.StructTable[2].AlgSupported = mUseReqAsymAlgo;
    SpdmResponse.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    SpdmResponse.StructTable[3].AlgCount = 0x20;
    SpdmResponse.StructTable[3].AlgSupported = mUseKeyScheduleAlgo;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x19:
  {
    SPDM_ALGORITHMS_RESPONSE_SPDM11    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 4;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;
    SpdmResponse.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    SpdmResponse.StructTable[0].AlgCount = 0x20;
    SpdmResponse.StructTable[0].AlgSupported = mUseDheAlgo;
    SpdmResponse.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    SpdmResponse.StructTable[1].AlgCount = 0x20;
    SpdmResponse.StructTable[1].AlgSupported = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
    SpdmResponse.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    SpdmResponse.StructTable[2].AlgCount = 0x20;
    SpdmResponse.StructTable[2].AlgSupported = mUseReqAsymAlgo;
    SpdmResponse.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    SpdmResponse.StructTable[3].AlgCount = 0x20;
    SpdmResponse.StructTable[3].AlgSupported = mUseKeyScheduleAlgo;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1A:
  {
    SPDM_ALGORITHMS_RESPONSE_SPDM11    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 4;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;
    SpdmResponse.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    SpdmResponse.StructTable[0].AlgCount = 0x20;
    SpdmResponse.StructTable[0].AlgSupported = mUseDheAlgo;
    SpdmResponse.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    SpdmResponse.StructTable[1].AlgCount = 0x20;
    SpdmResponse.StructTable[1].AlgSupported = mUseAeadAlgo;
    SpdmResponse.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    SpdmResponse.StructTable[2].AlgCount = 0x20;
    SpdmResponse.StructTable[2].AlgSupported = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    SpdmResponse.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    SpdmResponse.StructTable[3].AlgCount = 0x20;
    SpdmResponse.StructTable[3].AlgSupported = mUseKeyScheduleAlgo;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1B:
  {
    SPDM_ALGORITHMS_RESPONSE_SPDM11    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 4;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;
    SpdmResponse.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    SpdmResponse.StructTable[0].AlgCount = 0x20;
    SpdmResponse.StructTable[0].AlgSupported = mUseDheAlgo;
    SpdmResponse.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    SpdmResponse.StructTable[1].AlgCount = 0x20;
    SpdmResponse.StructTable[1].AlgSupported = mUseAeadAlgo;
    SpdmResponse.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    SpdmResponse.StructTable[2].AlgCount = 0x20;
    SpdmResponse.StructTable[2].AlgSupported = mUseReqAsymAlgo;
    SpdmResponse.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    SpdmResponse.StructTable[3].AlgCount = 0x20;
    SpdmResponse.StructTable[3].AlgSupported = BIT5;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1C:
  {
    SPDM_ALGORITHMS_RESPONSE_SPDM11    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 4;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;
    SpdmResponse.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    SpdmResponse.StructTable[0].AlgCount = 0x20;
    SpdmResponse.StructTable[0].AlgSupported = mUseDheAlgo | SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1;
    SpdmResponse.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    SpdmResponse.StructTable[1].AlgCount = 0x20;
    SpdmResponse.StructTable[1].AlgSupported = mUseAeadAlgo;
    SpdmResponse.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    SpdmResponse.StructTable[2].AlgCount = 0x20;
    SpdmResponse.StructTable[2].AlgSupported = mUseReqAsymAlgo;
    SpdmResponse.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    SpdmResponse.StructTable[3].AlgCount = 0x20;
    SpdmResponse.StructTable[3].AlgSupported = mUseKeyScheduleAlgo;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1D:
  {
    SPDM_ALGORITHMS_RESPONSE_SPDM11    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 4;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;
    SpdmResponse.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    SpdmResponse.StructTable[0].AlgCount = 0x20;
    SpdmResponse.StructTable[0].AlgSupported = mUseDheAlgo;
    SpdmResponse.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    SpdmResponse.StructTable[1].AlgCount = 0x20;
    SpdmResponse.StructTable[1].AlgSupported = mUseAeadAlgo | SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
    SpdmResponse.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    SpdmResponse.StructTable[2].AlgCount = 0x20;
    SpdmResponse.StructTable[2].AlgSupported = mUseReqAsymAlgo;
    SpdmResponse.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    SpdmResponse.StructTable[3].AlgCount = 0x20;
    SpdmResponse.StructTable[3].AlgSupported = mUseKeyScheduleAlgo;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1E:
  {
    SPDM_ALGORITHMS_RESPONSE_SPDM11    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 4;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;
    SpdmResponse.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    SpdmResponse.StructTable[0].AlgCount = 0x20;
    SpdmResponse.StructTable[0].AlgSupported = mUseDheAlgo;
    SpdmResponse.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    SpdmResponse.StructTable[1].AlgCount = 0x20;
    SpdmResponse.StructTable[1].AlgSupported = mUseAeadAlgo;
    SpdmResponse.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    SpdmResponse.StructTable[2].AlgCount = 0x20;
    SpdmResponse.StructTable[2].AlgSupported = mUseReqAsymAlgo | SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521;
    SpdmResponse.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    SpdmResponse.StructTable[3].AlgCount = 0x20;
    SpdmResponse.StructTable[3].AlgSupported = mUseKeyScheduleAlgo;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1F:
  {
    SPDM_ALGORITHMS_RESPONSE_SPDM11    SpdmResponse;

    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse.Header.RequestResponseCode = SPDM_ALGORITHMS;
    SpdmResponse.Header.Param1 = 4;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.Length = sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11);
    SpdmResponse.MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    SpdmResponse.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse.BaseAsymSel = mUseAsymAlgo;
    SpdmResponse.BaseHashSel = mUseHashAlgo;
    SpdmResponse.ExtAsymSelCount = 0;
    SpdmResponse.ExtHashSelCount = 0;
    SpdmResponse.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
    SpdmResponse.StructTable[0].AlgCount = 0x20;
    SpdmResponse.StructTable[0].AlgSupported = mUseDheAlgo;
    SpdmResponse.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
    SpdmResponse.StructTable[1].AlgCount = 0x20;
    SpdmResponse.StructTable[1].AlgSupported = mUseAeadAlgo;
    SpdmResponse.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
    SpdmResponse.StructTable[2].AlgCount = 0x20;
    SpdmResponse.StructTable[2].AlgSupported = mUseReqAsymAlgo;
    SpdmResponse.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
    SpdmResponse.StructTable[3].AlgCount = 0x20;
    SpdmResponse.StructTable[3].AlgSupported = mUseKeyScheduleAlgo | BIT5;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

void TestSpdmRequesterNegotiateAlgorithmCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageA.BufferSize, 0);
}

void TestSpdmRequesterNegotiateAlgorithmCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageA.BufferSize, sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) + sizeof(SPDM_ALGORITHMS_RESPONSE));
}

void TestSpdmRequesterNegotiateAlgorithmCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_UNSUPPORTED);
  assert_int_equal (SpdmContext->Transcript.MessageA.BufferSize, 0);
}

void TestSpdmRequesterNegotiateAlgorithmCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageA.BufferSize, 0);
}

void TestSpdmRequesterNegotiateAlgorithmCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  assert_int_equal (SpdmContext->Transcript.MessageA.BufferSize, 0);
}

void TestSpdmRequesterNegotiateAlgorithmCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageA.BufferSize, sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) + sizeof(SPDM_ALGORITHMS_RESPONSE));
}

void TestSpdmRequesterNegotiateAlgorithmCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->ConnectionInfo.ConnectionState, SpdmConnectionStateNotStarted);
  assert_int_equal (SpdmContext->Transcript.MessageA.BufferSize, 0);
}

void TestSpdmRequesterNegotiateAlgorithmCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterNegotiateAlgorithmCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
//  assert_int_equal (SpdmContext->Transcript.MessageA.BufferSize, sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) + sizeof(SPDM_ALGORITHMS_RESPONSE));
}

void TestSpdmRequesterNegotiateAlgorithmCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo, 0);
}

void TestSpdmRequesterNegotiateAlgorithmCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xB;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo, 0);
}

void TestSpdmRequesterNegotiateAlgorithmCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xC;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = 0;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, 0);
}

void TestSpdmRequesterNegotiateAlgorithmCase13(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xD;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterNegotiateAlgorithmCase14(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xE;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterNegotiateAlgorithmCase15(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xF;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterNegotiateAlgorithmCase16(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x10;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

// void TestSpdmRequesterNegotiateAlgorithmCase17(void **state) {
//   RETURN_STATUS        Status;
//   SPDM_TEST_CONTEXT    *SpdmTestContext;
//   SPDM_DEVICE_CONTEXT  *SpdmContext;
//
//   SpdmTestContext = *state;
//   SpdmContext = SpdmTestContext->SpdmContext;
//   SpdmTestContext->CaseId = 0x11;
//   SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
//   SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
//   SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
//   SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
//   SpdmContext->Transcript.MessageA.BufferSize = 0;
//
//   Status = SpdmNegotiateAlgorithms (SpdmContext);
//   assert_int_equal (Status, RETURN_DEVICE_ERROR);
// }

void TestSpdmRequesterNegotiateAlgorithmCase17(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x11;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterNegotiateAlgorithmCase18(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x12;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterNegotiateAlgorithmCase19(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x13;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmRequesterNegotiateAlgorithmCase20(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x14;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmRequesterNegotiateAlgorithmCase21(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x15;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmRequesterNegotiateAlgorithmCase22(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x16;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
}

void TestSpdmRequesterNegotiateAlgorithmCase23(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x17;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageA.BufferSize, sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) + 4*sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) + sizeof(SPDM_ALGORITHMS_RESPONSE_SPDM11));
}

void TestSpdmRequesterNegotiateAlgorithmCase24(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x18;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmRequesterNegotiateAlgorithmCase25(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x19;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmRequesterNegotiateAlgorithmCase26(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1A;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmRequesterNegotiateAlgorithmCase27(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1B;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmRequesterNegotiateAlgorithmCase28(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1C;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmRequesterNegotiateAlgorithmCase29(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1D;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmRequesterNegotiateAlgorithmCase30(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1E;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}

void TestSpdmRequesterNegotiateAlgorithmCase31(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1F;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;
  SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->LocalContext.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->Transcript.MessageA.BufferSize = 0;
  SpdmContext->LocalContext.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->LocalContext.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = mUseReqAsymAlgo;
  SpdmContext->LocalContext.Algorithm.KeySchedule = mUseKeyScheduleAlgo;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;

  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;

  Status = SpdmNegotiateAlgorithms (SpdmContext);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
}


SPDM_TEST_CONTEXT       mSpdmRequesterNegotiateAlgorithmTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterNegotiateAlgorithmTestSendMessage,
  SpdmRequesterNegotiateAlgorithmTestReceiveMessage,
};

int SpdmRequesterNegotiateAlgorithmTestMain(void) {
  const struct CMUnitTest SpdmRequesterNegotiateAlgorithmTests[] = {
      // SendRequest failed
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase1),
      // Successful response
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase2),
      // ConnectionState check failed
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase9),
      // When SpdmResponse.MeasurementHashAlgo is 0
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase10),
      // When SpdmResponse.BaseAsymSel is 0
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase11),
      // When SpdmResponse.BaseHashSel is 0
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase12),
      // When SpdmResponse has a size of header and SPDM_ALGORITHMS code
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase13),
      // When SpdmResponse has a size greater than header and smaller than algorithm and SPDM_ALGORITHMS code
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase14),
      // When SpdmResponse has ExtAsymSelCount > 1
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase15),
      // When SpdmResponse has ExtAsymHashCount > 1
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase16),
      // // When SpdmResponse returns an unlisted MeasurementHashAlgo
      // cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase17),
      // When SpdmResponse returns an unlisted BaseAsymSel
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase17),
      // When SpdmResponse returns an unlisted BaseHashSel
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase18),
      // When SpdmResponse returns multiple MeasurementHashAlgo
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase19),
      // When SpdmResponse returns multiple BaseAsymSel
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase20),
      // When SpdmResponse returns multiple BaseHashSel
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase21),
      // Request and Response mismatch version
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase22),
      // Successful V1.1 response
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase23),
      // When SpdmResponse returns an unlisted DheAlgo
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase24),
      // When SpdmResponse returns an unlisted AEADAlgo
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase25),
      // When SpdmResponse returns an unlisted ReqAsymAlgo
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase26),
      // When SpdmResponse returns an unlisted KeySchedule
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase27),
      // When SpdmResponse returns multiple DheAlgo
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase28),
      // When SpdmResponse returns multiple AEADAlgo
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase29),
      // When SpdmResponse returns multiple ReqAsymAlgo
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase30),
      // When SpdmResponse returns multiple KeySchedule
      cmocka_unit_test(TestSpdmRequesterNegotiateAlgorithmCase31),
  };

  SetupSpdmTestContext (&mSpdmRequesterNegotiateAlgorithmTestContext);

  return cmocka_run_group_tests(SpdmRequesterNegotiateAlgorithmTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
