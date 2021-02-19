/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

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
  };
  
  SetupSpdmTestContext (&mSpdmRequesterNegotiateAlgorithmTestContext);

  return cmocka_run_group_tests(SpdmRequesterNegotiateAlgorithmTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
