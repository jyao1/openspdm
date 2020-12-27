/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

STATIC UINTN                  LocalBufferSize;
STATIC UINT8                  LocalBuffer[MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE];

RETURN_STATUS
EFIAPI
SpdmRequesterGetMeasurementTestSendMessage (
  IN     VOID                    *SpdmContext,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;
  UINT8                   *Ptr;

  SpdmTestContext = GetSpdmTestContext ();
  Ptr = (UINT8 *)Request;
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;
  case 0x2:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x3:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x4:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x5:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x6:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x7:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x8:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0x9:
  {
    STATIC UINTN SubIndex = 0;
    if (SubIndex == 0) {
      LocalBufferSize = 0;
      CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
      LocalBufferSize += (RequestSize - 1);
      SubIndex ++;
    }
  }
    return RETURN_SUCCESS;
  case 0xA:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  case 0xB:
    LocalBufferSize = 0;
    CopyMem (LocalBuffer, &Ptr[1], RequestSize - 1);
    LocalBufferSize += (RequestSize - 1);
    return RETURN_SUCCESS;
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmRequesterGetMeasurementTestReceiveMessage (
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
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINTN                         MeasurmentSigSize;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    *(UINT32 *)SpdmResponse->MeasurementRecordLength = (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    Ptr = (VOID *)((UINT8 *)SpdmResponse + TempBufSize - MeasurmentSigSize);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n", GetSpdmHashSize (mUseHashAlgo)));
    InternalDumpHex (HashData, GetSpdmHashSize (mUseHashAlgo));
    SigSize = GetSpdmAsymSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, HashData, GetSpdmHashSize (mUseHashAlgo), Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINTN                         MeasurmentSigSize;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    *(UINT32 *)SpdmResponse->MeasurementRecordLength = (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    Ptr = (VOID *)((UINT8 *)SpdmResponse + TempBufSize - MeasurmentSigSize);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n", GetSpdmHashSize (mUseHashAlgo)));
    InternalDumpHex (HashData, GetSpdmHashSize (mUseHashAlgo));
    SigSize = GetSpdmAsymSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, HashData, GetSpdmHashSize (mUseHashAlgo), Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x4:
  {
    SPDM_ERROR_RESPONSE    SpdmResponse;

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

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
      SpdmResponse.Header.Param2 = 0;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex1 ++;
    } else if (SubIndex1 == 1) {
      SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
      UINT8                         *Ptr;
      UINT8                         HashData[MAX_HASH_SIZE];
      UINTN                         SigSize;
      UINTN                         MeasurmentSigSize;
      SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;  

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
      MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSize (mUseAsymAlgo);
      TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->NumberOfBlocks = 1;
      *(UINT32 *)SpdmResponse->MeasurementRecordLength = (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
      MeasurmentBlock = (VOID *)(SpdmResponse + 1);
      SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
      Ptr = (VOID *)((UINT8 *)SpdmResponse + TempBufSize - MeasurmentSigSize);
      SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
      Ptr += SPDM_NONCE_SIZE;
      *(UINT16 *)Ptr = 0;
      Ptr += sizeof(UINT16);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
      InternalDumpHex (LocalBuffer, LocalBufferSize);
      SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
      DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n", GetSpdmHashSize (mUseHashAlgo)));
      InternalDumpHex (HashData, GetSpdmHashSize (mUseHashAlgo));
      SigSize = GetSpdmAsymSize (mUseAsymAlgo);
      SpdmResponderDataSignFunc (mUseAsymAlgo, HashData, GetSpdmHashSize (mUseHashAlgo), Ptr, &SigSize);
      Ptr += SigSize;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
  }
    return RETURN_SUCCESS;

  case 0x7:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

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

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.ExtendErrorData.RDTExponent = 1;
    SpdmResponse.ExtendErrorData.RDTM = 1;
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_GET_MEASUREMENTS;
    SpdmResponse.ExtendErrorData.Token = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x9:
  {
    STATIC UINTN SubIndex2 = 0;
    if (SubIndex2 == 0) {
      SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.ExtendErrorData.RDTExponent = 1;
      SpdmResponse.ExtendErrorData.RDTM = 1;
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_GET_MEASUREMENTS;
      SpdmResponse.ExtendErrorData.Token = 1;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
      SubIndex2 ++;
    } else if (SubIndex2 == 1) {
      SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
      UINT8                         *Ptr;
      UINT8                         HashData[MAX_HASH_SIZE];
      UINTN                         SigSize;
      UINTN                         MeasurmentSigSize;
      SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;

      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
      ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
      MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSize (mUseAsymAlgo);
      TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->NumberOfBlocks = 1;
      *(UINT32 *)SpdmResponse->MeasurementRecordLength = (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
      MeasurmentBlock = (VOID *)(SpdmResponse + 1);
      SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
      Ptr = (VOID *)((UINT8 *)SpdmResponse + TempBufSize - MeasurmentSigSize);
      SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
      Ptr += SPDM_NONCE_SIZE;
      *(UINT16 *)Ptr = 0;
      Ptr += sizeof(UINT16);
      CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
      LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
      DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
      InternalDumpHex (LocalBuffer, LocalBufferSize);
      SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
      DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n", GetSpdmHashSize (mUseHashAlgo)));
      InternalDumpHex (HashData, GetSpdmHashSize (mUseHashAlgo));
      SigSize = GetSpdmAsymSize (mUseAsymAlgo);
      SpdmResponderDataSignFunc (mUseAsymAlgo, HashData, GetSpdmHashSize (mUseHashAlgo), Ptr, &SigSize);
      Ptr += SigSize;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
    }
  }
    return RETURN_SUCCESS;

  case 0xA:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;    
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE);
    SpdmResponse = (VOID *)TempBuf;
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 4;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 0;
    *(UINT32 *)SpdmResponse->MeasurementRecordLength = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xB:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    *(UINT32 *)SpdmResponse->MeasurementRecordLength = (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

void TestSpdmRequesterGetMeasurementCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlock;
  UINT32               MeasurementRecordLength;
  UINT8                MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];  
  UINT8                RequestAttribute; 
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;  
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetMeasurementCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlock;
  UINT32               MeasurementRecordLength;
  UINT8                MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];  
  UINT8                RequestAttribute;  
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetMeasurementCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlock;
  UINT32               MeasurementRecordLength;
  UINT8                MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];  
  UINT8                RequestAttribute;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->SpdmCmdReceiveState = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetMeasurementCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlock;
  UINT32               MeasurementRecordLength;
  UINT8                MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];  
  UINT8                RequestAttribute;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetMeasurementCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlock;
  UINT32               MeasurementRecordLength;
  UINT8                MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];  
  UINT8                RequestAttribute;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);  
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetMeasurementCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlock;
  UINT32               MeasurementRecordLength;
  UINT8                MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];  
  UINT8                RequestAttribute;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetMeasurementCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlock;
  UINT32               MeasurementRecordLength;
  UINT8                MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];  
  UINT8                RequestAttribute;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->SpdmCmdReceiveState, 0);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetMeasurementCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlock;
  UINT32               MeasurementRecordLength;
  UINT8                MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];  
  UINT8                RequestAttribute;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterGetMeasurementCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlock;
  UINT32               MeasurementRecordLength;
  UINT8                MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];  
  UINT8                RequestAttribute;
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetMeasurementCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlocks;
  UINT8                RequestAttribute;  
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  Status = SpdmGetMeasurement (
             SpdmContext, RequestAttribute,
             SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS,
             0, &NumberOfBlocks, NULL, NULL);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (NumberOfBlocks, 4);
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE));
  free(Data);
}

void TestSpdmRequesterGetMeasurementCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINT8                NumberOfBlock;
  UINT32               MeasurementRecordLength;
  UINT8                MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];  
  UINT8                RequestAttribute; 
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xB;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.L1L2.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);  
  assert_int_equal (SpdmContext->Transcript.L1L2.BufferSize, sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
  free(Data);
}

SPDM_TEST_CONTEXT       mSpdmRequesterGetMeasurementTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterGetMeasurementTestSendMessage,
  SpdmRequesterGetMeasurementTestReceiveMessage,
};

int SpdmRequesterGetMeasurementTestMain(void) {
  const struct CMUnitTest SpdmRequesterGetMeasurementTests[] = {
      // SendRequest failed
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase1),
      // Successful response to get measurement with signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase2),
      // SpdmCmdReceiveState check failed
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase9),
      // Successful response to get total measurement number
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase10),
      // Successful response to get one measurement without signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase11),
  };
  
  SetupSpdmTestContext (&mSpdmRequesterGetMeasurementTestContext);

  return cmocka_run_group_tests(SpdmRequesterGetMeasurementTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
