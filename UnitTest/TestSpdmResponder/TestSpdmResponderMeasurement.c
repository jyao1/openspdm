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
    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS
  },
};
UINTN mSpdmGetMeasurementRequest1Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementRequest2 = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_GET_MEASUREMENTS,
    0,
    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS
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
    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS
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

void TestSpdmResponderMeasurementCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest1.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest1Size, &mSpdmGetMeasurementRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);  
  assert_int_equal (SpdmResponse->Header.Param1, MEASUREMENT_BLOCK_NUMBER);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, mSpdmGetMeasurementRequest1Size + sizeof(SPDM_MEASUREMENTS_RESPONSE));
  free(Data);
}

void TestSpdmResponderMeasurementCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);
  
  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest2.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest2Size, &mSpdmGetMeasurementRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmResponderMeasurementCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateBusy;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);

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
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmResponderMeasurementCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest1.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest1Size, &mSpdmGetMeasurementRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmResponderMeasurementCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);

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
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNormal);
  assert_int_equal (ErrorData->RequestCode, SPDM_GET_MEASUREMENTS);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmResponderMeasurementCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest1.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest1Size, &mSpdmGetMeasurementRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_UNEXPECTED_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmResponderMeasurementCase7(void **state) {
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
  SpdmTestContext->CaseId = 0x7;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);
  MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSize (SpdmContext);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest5.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest5Size, &mSpdmGetMeasurementRequest5, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + MeasurmentSigSize);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);  
  assert_int_equal (SpdmResponse->Header.Param1, MEASUREMENT_BLOCK_NUMBER);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmResponderMeasurementCase8(void **state) {
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
  SpdmTestContext->CaseId = 0x8;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);
  MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSize (SpdmContext);
  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest3.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest3Size, &mSpdmGetMeasurementRequest3, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (SpdmContext) + MeasurmentSigSize);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmResponderMeasurementCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest4.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest4Size, &mSpdmGetMeasurementRequest4, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmResponderMeasurementCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest6.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest6Size, &mSpdmGetMeasurementRequest6, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (SpdmContext));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);  
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, mSpdmGetMeasurementRequest6Size + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (SpdmContext));
  free(Data);
}

void TestSpdmResponderMeasurementCase11(void **state) {
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
  SpdmTestContext->CaseId = 0xB;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);
  MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSize (SpdmContext);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest8.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest8Size, &mSpdmGetMeasurementRequest8, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + (MEASUREMENT_BLOCK_NUMBER - 1) * (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize(SpdmContext)) + (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + MEASUREMENT_MANIFEST_SIZE) + MeasurmentSigSize);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);  
  assert_int_equal (SpdmResponse->NumberOfBlocks, MEASUREMENT_BLOCK_NUMBER);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmResponderMeasurementCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse;
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xC;  
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG; 
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG; 
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;
  SpdmContext->LocalContext.SpdmMeasurementCollectionFunc = SpdmMeasurementCollectionFunc;
  SpdmContext->LocalContext.SpdmRequesterDataSignFunc = SpdmRequesterDataSignFunc;
  SpdmContext->LocalContext.SpdmResponderDataSignFunc = SpdmResponderDataSignFunc;
  ReadResponderPrivateCertificate (&Data, &DataSize);

  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementRequest7.Nonce);
  Status = SpdmGetResponseMeasurement (SpdmContext, mSpdmGetMeasurementRequest7Size, &mSpdmGetMeasurementRequest7, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + (MEASUREMENT_BLOCK_NUMBER - 1) * (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize(SpdmContext)) + (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + MEASUREMENT_MANIFEST_SIZE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);  
  assert_int_equal (SpdmResponse->NumberOfBlocks, MEASUREMENT_BLOCK_NUMBER);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, mSpdmGetMeasurementRequest7Size + sizeof(SPDM_MEASUREMENTS_RESPONSE) + (MEASUREMENT_BLOCK_NUMBER - 1) * (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize(SpdmContext)) + (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + MEASUREMENT_MANIFEST_SIZE));
  free(Data);
}

SPDM_TEST_CONTEXT       mSpdmResponderMeasurementTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderMeasurementTestMain(void) {
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
    // SpdmCmdReceiveState Check
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
  };

  SetupSpdmTestContext (&mSpdmResponderMeasurementTestContext);

  return cmocka_run_group_tests(SpdmResponderMeasurementTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
