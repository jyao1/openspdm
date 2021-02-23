/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest1 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_MEASUREMENTS,
    0,
    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS
  },
};
UINTN mSpdmGetMeasurementRequest1Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_MEASUREMENTS,
    0,
    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS
  },
};
UINTN mSpdmGetMeasurementRequest2Size = MAX_SPDM_MESSAGE_BUFFER_SIZE;

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest3 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_MEASUREMENTS,
    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
    1
  },
};
UINTN mSpdmGetMeasurementRequest3Size = sizeof(mSpdmGetMeasurementRequest3) - sizeof(UINT8);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest4 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_MEASUREMENTS,
    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
    1
  },
};
UINTN mSpdmGetMeasurementRequest4Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest5 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_MEASUREMENTS,
    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS
  },
};
UINTN mSpdmGetMeasurementRequest5Size = sizeof(mSpdmGetMeasurementRequest5) - sizeof(UINT8);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest6 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_MEASUREMENTS,
    0,
    1
  },
};
UINTN mSpdmGetMeasurementRequest6Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest7 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_MEASUREMENTS,
    0,
    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS
  },
};
UINTN mSpdmGetMeasurementRequest7Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest8 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_MEASUREMENTS,
    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS
  },
};
UINTN mSpdmGetMeasurementRequest8Size = sizeof(mSpdmGetMeasurementRequest8) - sizeof(UINT8);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest9 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_MEASUREMENTS,
    0,
    1
  },
};
UINTN mSpdmGetMeasurementRequest9Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest10 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_MEASUREMENTS,
    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
    1
  },
};
UINTN mSpdmGetMeasurementRequest10Size = sizeof(mSpdmGetMeasurementRequest10);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest11 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_MEASUREMENTS,
    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
    1
  },
  // Nonce
  // SlotId != 0
};
UINTN mSpdmGetMeasurementRequest11Size = sizeof(mSpdmGetMeasurementRequest11);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest12 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_MEASUREMENTS,
    SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
    1
  },
  // Nonce
  // SlotId >= MAX_SPDM_SLOT_COUNT
};
UINTN mSpdmGetMeasurementRequest12Size = sizeof(mSpdmGetMeasurementRequest12);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest13 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_MEASUREMENTS,
    0,
    0xFE
  },
};
UINTN mSpdmGetMeasurementRequest13Size = sizeof(SPDM_MESSAGE_HEADER);

/**
  Test 1: Successful response to get a number of measurements without signature
  Expected Behavior: get a RETURN_SUCCESS return code, correct Transcript.MessageM size, and correct response message size and fields
**/
void TestSpdmResponderMeasurementCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;  
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest1.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest1Size, &mSpdmGetMeasurementRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(UINT16));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);
  assert_int_equal (SpdmResponse->Header.Param1, MEASUREMENT_BLOCK_NUMBER);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, mSpdmGetMeasurementRequest1Size + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(UINT16));
}

/**
  Test 2: Error case, Bad Request Size (MAX_SPDM_MESSAGE_BUFFER_SIZE) to get measurement number without signature
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM size, and Error message as response
**/
void TestSpdmResponderMeasurementCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  
  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest2.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest2Size, &mSpdmGetMeasurementRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 3: Force ResponseState = SpdmResponseStateBusy when asked GET_MEASUREMENTS
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_BUSY
**/
void TestSpdmResponderMeasurementCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest1.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest1Size, &mSpdmGetMeasurementRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 4: Force ResponseState = SpdmResponseStateNeedResync when asked GET_MEASUREMENTS
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_REQUEST_RESYNCH
**/
void TestSpdmResponderMeasurementCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest1.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest1Size, &mSpdmGetMeasurementRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 5: Force ResponseState = SpdmResponseStateNotReady when asked GET_MEASUREMENTS
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_RESPONSE_NOT_READY
**/
void TestSpdmResponderMeasurementCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest1.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest1Size, &mSpdmGetMeasurementRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(&SpdmResponse->NumberOfBlocks);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_GET_MEASUREMENTS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 6: simulate wrong ConnectionState when asked GET_MEASUREMENTS
          (missing SPDM_GET_DIGESTS_RECEIVE_FLAG, SPDM_GET_CAPABILITIES_RECEIVE_FLAG and SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG)
  Expected Behavior: generate an ERROR_RESPONSE with code SPDM_ERROR_CODE_UNEXPECTED_REQUEST
**/
void TestSpdmResponderMeasurementCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ResponseState = SpdmResponseStateNormal;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest1.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest1Size, &mSpdmGetMeasurementRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 7: Successful response to get a number of measurements with signature
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM, and correct response message size and fields
**/
void TestSpdmResponderMeasurementCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  UINTN                MeasurmentSigSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;  
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest5.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest5Size, &mSpdmGetMeasurementRequest5, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + MeasurmentSigSize);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);  
  assert_int_equal (SpdmResponse->Header.Param1, MEASUREMENT_BLOCK_NUMBER);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 8: Successful response to get one measurement with signature
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM, and correct response message size and fields
**/
void TestSpdmResponderMeasurementCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  UINTN                MeasurmentSigSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;  
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest3.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest3Size, &mSpdmGetMeasurementRequest3, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 9: Error case, Bad Request Size (sizeof(SPDM_MESSAGE_HEADER)x) to get measurement number with signature
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM size, and Error message as response
**/
void TestSpdmResponderMeasurementCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;  
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest4.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest4Size, &mSpdmGetMeasurementRequest4, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 10: Successful response to get one measurement without signature
  Expected Behavior: get a RETURN_SUCCESS return code, correct Transcript.MessageM size, and correct response message size and fields
**/
void TestSpdmResponderMeasurementCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;  
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest6.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest6Size, &mSpdmGetMeasurementRequest6, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, mSpdmGetMeasurementRequest6Size + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16));
}

/**
  Test 11: Successful response to get all measurements with signature
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM, and correct response message size and fields
**/
void TestSpdmResponderMeasurementCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  UINTN                MeasurmentSigSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xB;  
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest8.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest8Size, &mSpdmGetMeasurementRequest8, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + (MEASUREMENT_BLOCK_NUMBER - 1) * (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)) + (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + MEASUREMENT_MANIFEST_SIZE) + MeasurmentSigSize);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);  
  assert_int_equal (SpdmResponse->NumberOfBlocks, MEASUREMENT_BLOCK_NUMBER);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 12: Successful response to get all measurements without signature
  Expected Behavior: get a RETURN_SUCCESS return code, correct Transcript.MessageM size, and correct response message size and fields
**/
void TestSpdmResponderMeasurementCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xC;  
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest7.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest7Size, &mSpdmGetMeasurementRequest7, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + (MEASUREMENT_BLOCK_NUMBER - 1) * (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)) + (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + MEASUREMENT_MANIFEST_SIZE) + sizeof(UINT16));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);
  assert_int_equal (SpdmResponse->NumberOfBlocks, MEASUREMENT_BLOCK_NUMBER);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, mSpdmGetMeasurementRequest7Size + sizeof(SPDM_MEASUREMENTS_RESPONSE) + (MEASUREMENT_BLOCK_NUMBER - 1) * (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)) + (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + MEASUREMENT_MANIFEST_SIZE) + sizeof(UINT16));
}

/**
  Test 13: Error case, even though signature was not required, there is nonce and/or slotID
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM size, and Error message as response
**/
void TestSpdmResponderMeasurementCase13(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  UINT16               TestMsgSizes[3];

  TestMsgSizes[0] = (UINT16)(mSpdmGetMeasurementRequest9Size + sizeof(mSpdmGetMeasurementRequest9.SlotIDParam) + sizeof(mSpdmGetMeasurementRequest9.Nonce));
  TestMsgSizes[1] = (UINT16)(mSpdmGetMeasurementRequest9Size + sizeof(mSpdmGetMeasurementRequest9.SlotIDParam));
  TestMsgSizes[2] = (UINT16)(mSpdmGetMeasurementRequest9Size + sizeof(mSpdmGetMeasurementRequest9.Nonce));

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xD;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest9.Nonce);
  for(int i=0; i<sizeof(TestMsgSizes)/sizeof(TestMsgSizes[0]); i++) {
    ResponseSize = sizeof(Response);
    Status = SpdmGetResponseMeasurement (SpdmContext, TestMsgSizes[i], &mSpdmGetMeasurementRequest9, &ResponseSize, Response);
    assert_int_equal (Status, RETURN_SUCCESS);
    assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
    SpdmResponse = (VOID *)Response;
    assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
    assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (SpdmResponse->Header.Param2, 0);
    assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  }
}

/**
  Test 14: Error case, signature was required, but there is no nonce and/or slotID
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM size, and Error message as response
**/
void TestSpdmResponderMeasurementCase14(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  UINT16               TestMsgSizes[3];
  
  TestMsgSizes[0] = (UINT16)(mSpdmGetMeasurementRequest10Size - sizeof(mSpdmGetMeasurementRequest10.SlotIDParam) - sizeof(mSpdmGetMeasurementRequest10.Nonce));
  TestMsgSizes[1] = (UINT16)(mSpdmGetMeasurementRequest10Size - sizeof(mSpdmGetMeasurementRequest10.SlotIDParam));
  TestMsgSizes[2] = (UINT16)(mSpdmGetMeasurementRequest10Size - sizeof(mSpdmGetMeasurementRequest10.Nonce));

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xE;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest10.Nonce);
  for(int i=0; i<sizeof(TestMsgSizes)/sizeof(TestMsgSizes[0]); i++) {
    ResponseSize = sizeof(Response);
    Status = SpdmGetResponseMeasurement (SpdmContext, TestMsgSizes[i], &mSpdmGetMeasurementRequest10, &ResponseSize, Response);
    assert_int_equal (Status, RETURN_SUCCESS);
    assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
    SpdmResponse = (VOID *)Response;
    assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
    assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
    assert_int_equal (SpdmResponse->Header.Param2, 0);
    assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  }
}

/**
  Test 15: Error case, MEAS_CAP = 01b, but signature was requested (request message includes nonce and slotID)
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM size, and Error message as response
**/
void TestSpdmResponderMeasurementCase15(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  // UINTN                MeasurmentSigSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xF;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  // MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest10.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest10Size, &mSpdmGetMeasurementRequest10, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 16: Error case, MEAS_CAP = 01b, but signature was requested (request message does not include nonce and slotID)
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM size, and Error message as response
**/
void TestSpdmResponderMeasurementCase16(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  // UINTN                MeasurmentSigSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x10;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  // MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);

  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest9Size, &mSpdmGetMeasurementRequest10, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 17: Error case, MEAS_CAP = 00
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM size, and Error message as response
**/
void TestSpdmResponderMeasurementCase17(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  // UINTN                MeasurmentSigSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x11;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;;
  // MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest9.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest9Size, &mSpdmGetMeasurementRequest9, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, mSpdmGetMeasurementRequest10.Header.RequestResponseCode);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 18: Successful response to get one measurement with signature, SlotId different from default
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM, and correct response message size and fields
**/
void TestSpdmResponderMeasurementCase18(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;
  UINTN                MeasurmentSigSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x12;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
  SpdmContext->LocalContext.SlotCount = MAX_SPDM_SLOT_COUNT;
  for (int i=1  ; i<SpdmContext->LocalContext.SlotCount; i++) {
    SpdmContext->LocalContext.LocalCertChainProvisionSize[i] = DataSize;
    SpdmContext->LocalContext.LocalCertChainProvision[i] = Data;
  }

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest11.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest11Size, &mSpdmGetMeasurementRequest11, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  assert_int_equal (mSpdmGetMeasurementRequest11.SlotIDParam, SpdmResponse->Header.Param2);

  SpdmContext->LocalContext.SlotCount = 1;
  free(Data);
}

/**
  Test 19: Error case, invalid SlotId parameter (SlotId >= MAX_SPDM_SLOT_COUNT)
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM size, and Error message as response
**/
void TestSpdmResponderMeasurementCase19(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  // UINTN                MeasurmentSigSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x13;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  // MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest12.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest12Size, &mSpdmGetMeasurementRequest12, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 19: Error case, invalid SlotId parameter (SlotCount < SlotId < MAX_SPDM_SLOT_COUNT)
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM size, and Error message as response
**/
void TestSpdmResponderMeasurementCase20(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  // UINTN                MeasurmentSigSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x14;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  // MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest11.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest11Size, &mSpdmGetMeasurementRequest11, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 21: Error case, request a measurement index larger than the total number of measurements
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM size, and Error message as response
**/
void TestSpdmResponderMeasurementCase21(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x15;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest13.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest13Size, &mSpdmGetMeasurementRequest13, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
}

/**
  Test 22: request a large number of measurements before requesting a singed response
  Expected Behavior: while Transcript.MessageM is not full, get a RETURN_SUCCESS return code, empty Transcript.MessageM, and correct response message size and fields
                      if Transcript.MessageM has no more room, an error response is expected
**/
void TestSpdmResponderMeasurementCase22(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  UINTN                NumberOfMessages;
  #define TOTAL_MESSAGES 100

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x16;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  for (NumberOfMessages = 1; NumberOfMessages <= TOTAL_MESSAGES; NumberOfMessages++) {
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest6.Nonce);
    ResponseSize = sizeof(Response);
    Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest6Size, &mSpdmGetMeasurementRequest6, &ResponseSize, Response);
    assert_int_equal (Status, RETURN_SUCCESS);
    SpdmResponse = (VOID *)Response;
    if (SpdmResponse->Header.RequestResponseCode == SPDM_MEASUREMENTS) {
      assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);
      assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16));
      assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, NumberOfMessages*(mSpdmGetMeasurementRequest6Size + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16)));
    } else {
      assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
      assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
      break;
    }
  }
}

SPDM_TEST_CONTEXT       mSpdmResponderMeasurementTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderMeasurementTestMain(void) {
  mSpdmGetMeasurementRequest11.SlotIDParam = MAX_SPDM_SLOT_COUNT-1;
  mSpdmGetMeasurementRequest12.SlotIDParam = MAX_SPDM_SLOT_COUNT+1;

  const struct CMUnitTest SpdmResponderMeasurementTests[] = {
    // Success Case to get measurement number without signature
    cmocka_unit_test(TestSpdmResponderMeasurementCase1),
    // Bad Request Size to get measurement number without signature
    cmocka_unit_test(TestSpdmResponderMeasurementCase2),
    // ResponseState: SpdmResponseStateBusy
    cmocka_unit_test(TestSpdmResponderMeasurementCase3),
    // ResponseState: SpdmResponseStateNeedResync
    cmocka_unit_test(TestSpdmResponderMeasurementCase4),
    // ResponseState: SpdmResponseStateNotReady
    cmocka_unit_test(TestSpdmResponderMeasurementCase5),
    // ConnectionState Check
    cmocka_unit_test(TestSpdmResponderMeasurementCase6),
    // Success Case to get measurement number with signature
    cmocka_unit_test(TestSpdmResponderMeasurementCase7),
    // Success Case to get one measurement with signature
    cmocka_unit_test(TestSpdmResponderMeasurementCase8),
    // Bad Request Size to get one measurement with signature
    cmocka_unit_test(TestSpdmResponderMeasurementCase9),
    // Success Case to get one measurement without signature
    cmocka_unit_test(TestSpdmResponderMeasurementCase10),
    // Success Case to get all measurements with signature
    cmocka_unit_test(TestSpdmResponderMeasurementCase11),
    // Success Case to get all measurements without signature
    cmocka_unit_test(TestSpdmResponderMeasurementCase12),
    // Error Case: no sig required, but there is nonce and/or slotID (special case of Test Case 2)
    cmocka_unit_test(TestSpdmResponderMeasurementCase13),
    // Error Case: sig required, but no nonce and/or SlotID
    cmocka_unit_test(TestSpdmResponderMeasurementCase14),
    // Error Case: sig required, but MEAS_CAP = 01b (including Nonce and SlotId on request)
    cmocka_unit_test(TestSpdmResponderMeasurementCase15),
    // Error Case: sig required, but MEAS_CAP = 01b (not including Nonce and SlotId on request)
    cmocka_unit_test(TestSpdmResponderMeasurementCase16),
    // Error Case: MEAS_CAP = 00b
    cmocka_unit_test(TestSpdmResponderMeasurementCase17),
    // Success Case: SlotId different from default
    cmocka_unit_test(TestSpdmResponderMeasurementCase18),
    // Bad SlotId parameter (>= MAX_SPDM_SLOT_COUNT)
    cmocka_unit_test(TestSpdmResponderMeasurementCase19),
    // Bad SlotId parameter (SlotCount < SlotId < MAX_SPDM_SLOT_COUNT)
    cmocka_unit_test(TestSpdmResponderMeasurementCase20),
    // Error Case: request a measurement out of bounds
    cmocka_unit_test(TestSpdmResponderMeasurementCase21),
    // Large number of requests before requiring a signature
    cmocka_unit_test(TestSpdmResponderMeasurementCase22),
  };

  SetupSpdmTestContext (&mSpdmResponderMeasurementTestContext);

  return cmocka_run_group_tests(SpdmResponderMeasurementTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
