/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

#define              alternativeDefaultSlotID 2
#define              largeMeasurementSize     ((1<<24) - 1)

STATIC UINTN                  LocalBufferSize;
STATIC UINT8                  LocalBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

UINTN
SpdmTestGetMeasurementRequestSize (
  IN VOID    *SpdmContext,
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_GET_MEASUREMENTS_REQUEST   *SpdmRequest;
  UINTN                           MessageSize;

  SpdmRequest = Buffer;
  MessageSize = sizeof(SPDM_MESSAGE_HEADER);
  if (BufferSize < MessageSize) {
    return BufferSize;
  }

  if (SpdmRequest->Header.RequestResponseCode != SPDM_GET_MEASUREMENTS) {
    return BufferSize;
  }

  if (SpdmRequest->Header.Param1 == SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
    if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
      if (BufferSize < sizeof(SPDM_GET_MEASUREMENTS_REQUEST)) {
        return BufferSize;
      }
      MessageSize = sizeof(SPDM_GET_MEASUREMENTS_REQUEST);
    } else {
      if (BufferSize < sizeof(SPDM_GET_MEASUREMENTS_REQUEST) - sizeof(SpdmRequest->SlotIDParam)) {
        return BufferSize;
      }
      MessageSize = sizeof(SPDM_GET_MEASUREMENTS_REQUEST) - sizeof(SpdmRequest->SlotIDParam);
    }
  } else {
    // already checked before if BufferSize < sizeof(SPDM_MESSAGE_HEADER)
    MessageSize = sizeof(SPDM_MESSAGE_HEADER);
  }

  // Good message, return actual size
  return MessageSize;
}

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
  UINTN                   HeaderSize;
  UINTN                   MessageSize;

  SpdmTestContext = GetSpdmTestContext ();
  HeaderSize = sizeof(TEST_MESSAGE_HEADER);
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;
  case 0x2:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x3:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x4:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x5:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x6:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x7:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x8:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x9:
  {
    STATIC UINTN SubIndex = 0;
    if (SubIndex == 0) {
      LocalBufferSize = 0;
      MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
      CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
      LocalBufferSize += MessageSize;
      SubIndex ++;
    }
  }
    return RETURN_SUCCESS;
  case 0xA:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0xB:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0xC:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0xD:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0xE:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0xF:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x10:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x11:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x12:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x13:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x14:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x15:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x16:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x17:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x18:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x19:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x1A:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x1B:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x1C:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x1D:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x1E:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x1F:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
    return RETURN_SUCCESS;
  case 0x20:
    LocalBufferSize = 0;
    MessageSize = SpdmTestGetMeasurementRequestSize (SpdmContext, (UINT8 *)Request + HeaderSize, RequestSize - HeaderSize);
    CopyMem (LocalBuffer, (UINT8 *)Request + HeaderSize, MessageSize);
    LocalBufferSize += MessageSize;
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
  RETURN_STATUS           Status;

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
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
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
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
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
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
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
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
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
      MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
      TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->NumberOfBlocks = 1;
      SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
      MeasurmentBlock = (VOID *)(SpdmResponse + 1);
      SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
      MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
      MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
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
      InternalDumpHex (LocalBuffer, LocalBufferSize);
      SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
      SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
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
      MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
      TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->NumberOfBlocks = 1;
      SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
      MeasurmentBlock = (VOID *)(SpdmResponse + 1);
      SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
      MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
      MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
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
      InternalDumpHex (LocalBuffer, LocalBufferSize);
      SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
      SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
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

    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(UINT16);
    SpdmResponse = (VOID *)TempBuf;
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 4;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 0;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, 0);
    *(UINT16 *)((UINT8 *)SpdmResponse + sizeof(SPDM_MEASUREMENTS_RESPONSE)) = 0;

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
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    *(UINT16 *)((UINT8 *)SpdmResponse + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)) = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xC:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    UINTN                         SigSize;
    UINTN                         MeasurmentSigSize;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;

    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    Ptr = (VOID *)((UINT8 *)SpdmResponse + TempBufSize - MeasurmentSigSize);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SetMem(Ptr, SigSize, 0);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xD:
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
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
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
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmGetRandomNumber (SigSize, Ptr);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xE:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    UINTN                         MeasurmentSigSize;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    Ptr = (VOID *)((UINT8 *)SpdmResponse + TempBufSize - MeasurmentSigSize);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    *(UINT16 *)Ptr = 0;
    Ptr += sizeof(UINT16);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0xF:
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
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS + 1;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
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
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x10:
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
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = alternativeDefaultSlotID;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
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
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x11:
  {
    STATIC UINTN SubIndex0x11 = 0;

    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE);

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 1;
    SpdmResponse->Header.Param2 = 0;
    if (SubIndex0x11 == 0) {
      TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo);
      SpdmResponse->NumberOfBlocks = 1;
      SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
      MeasurmentBlock = (VOID *)(SpdmResponse + 1);
      SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
      MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
      MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    } else if (SubIndex0x11 == 1) {
      TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE);
      SpdmResponse->NumberOfBlocks = 1;
      SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, 0);
    } else if (SubIndex0x11 == 2) {
      TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo);
      SpdmResponse->NumberOfBlocks = 0;
      SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
      MeasurmentBlock = (VOID *)(SpdmResponse + 1);
      SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
      MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
      MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    }
    SubIndex0x11++;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x12:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         *TempBuf;
    UINTN                         TempBufSize;
    UINTN                         count;

    TempBuf = (UINT8*) malloc(sizeof(SPDM_MEASUREMENTS_RESPONSE) + largeMeasurementSize);

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = MAX_UINT8;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(largeMeasurementSize));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, largeMeasurementSize, 1);
    for (count = 0; count < SpdmResponse->NumberOfBlocks; count++) {
      MeasurmentBlock->MeasurementBlockCommonHeader.Index = (UINT8)(count + 1);
      MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
      MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = MAX_UINT16;
      TempBufSize += (UINTN)(sizeof(SPDM_MEASUREMENT_BLOCK_COMMON_HEADER) + MAX_UINT16);
    }
    Status = SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);

    free(TempBuf);
  }
    return Status;

  case 0x13:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.Index = 1;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = BIT0 | BIT1;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x14:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.Index = 1;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = BIT2 | BIT1;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x15:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.Index = 1;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = (UINT8)(mUseMeasurementSpec<<1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x16:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16);;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    *(UINT16 *)((UINT8 *)SpdmResponse + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)) = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x17:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16) + MAX_SPDM_OPAQUE_DATA_SIZE;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    // adding extra fields: OpaqueLength, OpaqueData
    Ptr = (VOID *)((UINT8 *)SpdmResponse + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    // SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    // Ptr += SPDM_NONCE_SIZE;
    *(UINT16 *)Ptr = MAX_SPDM_OPAQUE_DATA_SIZE; // OpaqueLength
    Ptr += sizeof(UINT16);
    SetMem (Ptr, MAX_SPDM_OPAQUE_DATA_SIZE, 255);
    Ptr += MAX_SPDM_OPAQUE_DATA_SIZE;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x18:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16) + (MAX_SPDM_OPAQUE_DATA_SIZE+1);
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    // adding extra fields: OpaqueLength, OpaqueData
    Ptr = (VOID *)((UINT8 *)SpdmResponse + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    // SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    // Ptr += SPDM_NONCE_SIZE;
    *(UINT16 *)Ptr = (MAX_SPDM_OPAQUE_DATA_SIZE+1); // OpaqueLength
    Ptr += sizeof(UINT16);
    SetMem (Ptr, (MAX_SPDM_OPAQUE_DATA_SIZE+1), 255);
    Ptr += (MAX_SPDM_OPAQUE_DATA_SIZE+1);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x19:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINTN                         MeasurmentSigSize;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    UINT16                        OpaqueSizeTest = MAX_SPDM_OPAQUE_DATA_SIZE;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + OpaqueSizeTest + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    Ptr = (VOID *)((UINT8 *)SpdmResponse + TempBufSize - MeasurmentSigSize);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;

    *(UINT16 *)Ptr = OpaqueSizeTest; // OpaqueLength
    Ptr += sizeof(UINT16);
    SetMem (Ptr, OpaqueSizeTest, 255);
    Ptr += OpaqueSizeTest;

    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n", GetSpdmHashSize (mUseHashAlgo)));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1A:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINTN                         MeasurmentSigSize;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    UINTN                         MissingBytes;
    UINT16                        OpaqueSizeTest = MAX_SPDM_OPAQUE_DATA_SIZE;

    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    MissingBytes = SigSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + (OpaqueSizeTest - MissingBytes) + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    Ptr = (VOID *)((UINT8 *)SpdmResponse + TempBufSize - MeasurmentSigSize);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;

    *(UINT16 *)Ptr = OpaqueSizeTest; // OpaqueLength
    Ptr += sizeof(UINT16);
    SetMem (Ptr, OpaqueSizeTest - MissingBytes, 255);
    Ptr += (OpaqueSizeTest - MissingBytes);

    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n", GetSpdmHashSize (mUseHashAlgo)));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1B:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINTN                         MeasurmentSigSize;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    UINTN                         MissingBytes;
    UINT16                        OpaqueSizeTest = MAX_SPDM_OPAQUE_DATA_SIZE;

    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);
    MissingBytes = SigSize + 1;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + (OpaqueSizeTest - MissingBytes) + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    Ptr = (VOID *)((UINT8 *)SpdmResponse + TempBufSize - MeasurmentSigSize);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;

    *(UINT16 *)Ptr = OpaqueSizeTest; // OpaqueLength
    Ptr += sizeof(UINT16);
    SetMem (Ptr, OpaqueSizeTest - MissingBytes, 255);
    Ptr += (OpaqueSizeTest - MissingBytes);

    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n", GetSpdmHashSize (mUseHashAlgo)));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1C:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    UINT8                         HashData[MAX_HASH_SIZE];
    UINTN                         SigSize;
    UINTN                         MeasurmentSigSize;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    UINT16                        OpaqueSizeTest = MAX_SPDM_OPAQUE_DATA_SIZE/2;
    UINT16                        OpaqueInformedSize = OpaqueSizeTest - 1;

    SigSize = GetSpdmAsymSignatureSize (mUseAsymAlgo);

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    MeasurmentSigSize = SPDM_NONCE_SIZE + sizeof(UINT16) + OpaqueSizeTest + GetSpdmAsymSignatureSize (mUseAsymAlgo);
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + MeasurmentSigSize;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    Ptr = (VOID *)((UINT8 *)SpdmResponse + TempBufSize - MeasurmentSigSize);
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;

    *(UINT16 *)Ptr = OpaqueInformedSize; // OpaqueLength
    Ptr += sizeof(UINT16);
    SetMem (Ptr, OpaqueSizeTest, 255);
    Ptr += (OpaqueSizeTest);

    CopyMem (&LocalBuffer[LocalBufferSize], SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
    LocalBufferSize += ((UINTN)Ptr - (UINTN)SpdmResponse);
    DEBUG((DEBUG_INFO, "LocalBufferSize (0x%x):\n", LocalBufferSize));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmHashAll (mUseHashAlgo, LocalBuffer, LocalBufferSize, HashData);
    DEBUG((DEBUG_INFO, "HashDataSize (0x%x):\n", GetSpdmHashSize (mUseHashAlgo)));
    InternalDumpHex (LocalBuffer, LocalBufferSize);
    SpdmResponderDataSignFunc (mUseAsymAlgo, mUseHashAlgo, LocalBuffer, LocalBufferSize, Ptr, &SigSize);
    Ptr += SigSize;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1D:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    UINT16                        OpaqueSizeTest = MAX_SPDM_OPAQUE_DATA_SIZE/2;
    UINT16                        OpaqueInformedSize = OpaqueSizeTest - 1;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16) + OpaqueSizeTest;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    // adding extra fields: OpaqueLength, OpaqueData
    Ptr = (VOID *)((UINT8 *)SpdmResponse + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    // SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    // Ptr += SPDM_NONCE_SIZE;
    *(UINT16 *)Ptr = OpaqueInformedSize; // OpaqueLength
    Ptr += sizeof(UINT16);
    SetMem (Ptr, OpaqueSizeTest, 255);
    Ptr += OpaqueSizeTest;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1E:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    UINT16                        OpaqueSizeTest = MAX_UINT16;
    UINT16                        OpaqueInformedSize = MAX_SPDM_OPAQUE_DATA_SIZE/2;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16) + OpaqueSizeTest;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    // adding extra fields: NONCE, OpaqueLength, OpaqueData
    Ptr = (VOID *)((UINT8 *)SpdmResponse + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    // SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    // Ptr += SPDM_NONCE_SIZE;
    *(UINT16 *)Ptr = OpaqueInformedSize; // OpaqueLength
    Ptr += sizeof(UINT16);
    SetMem (Ptr, OpaqueSizeTest, 255);
    Ptr += OpaqueSizeTest;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x1F:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    UINT8                         *Ptr;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;
    UINT16                        OpaqueSizeTest = MAX_UINT16;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + SPDM_NONCE_SIZE + sizeof(UINT16) + OpaqueSizeTest;
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 1;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    // adding extra fields: NONCE, OpaqueLength, OpaqueData
    Ptr = (VOID *)((UINT8 *)SpdmResponse + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
    Ptr += SPDM_NONCE_SIZE;
    *(UINT16 *)Ptr = (OpaqueSizeTest); // OpaqueLength
    Ptr += sizeof(UINT16);
    SetMem (Ptr, (OpaqueSizeTest), 255);
    Ptr += (OpaqueSizeTest);

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x20:
  {
    SPDM_MEASUREMENTS_RESPONSE    *SpdmResponse;
    SPDM_MEASUREMENT_BLOCK_DMTF   *MeasurmentBlock;
    UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
    UINTN                         TempBufSize;

    ((SPDM_DEVICE_CONTEXT*)SpdmContext)->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
    TempBufSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + 2*(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    SpdmResponse = (VOID *)TempBuf;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 2;
    *(UINT32 *)SpdmResponse->MeasurementRecordLength = 2*((UINT32)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    SetMem (MeasurmentBlock, 2*(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)), 1);
    MeasurmentBlock->MeasurementBlockCommonHeader.Index = 1;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    MeasurmentBlock = (VOID *)(((UINT8*)MeasurmentBlock) + (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)));
    MeasurmentBlock->MeasurementBlockCommonHeader.Index = 2;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16) (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo));
    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

/**
  Test 1: message could not be sent
  Expected Behavior: get a RETURN_DEVICE_ERROR return code, with an empty Transcript.MessageM
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 2: Successful response to get a measurement with signature
  Expected Behavior: get a RETURN_SUCCESS return code, with an empty Transcript.MessageM
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 3: Error case, attempt to get measurements before GET_DIGESTS, GET_CAPABILITIES, and NEGOTIATE_ALGORITHMS
  Expected Behavior: get a RETURN_UNSUPPORTED return code, with an empty Transcript.MessageM
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_UNSUPPORTED);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 4: Error case, always get an error response with code SPDM_ERROR_CODE_INVALID_REQUEST
  Expected Behavior: get a RETURN_DEVICE_ERROR return code, with an empty Transcript.MessageM
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 5: Error case, always get an error response with code SPDM_ERROR_CODE_BUSY
  Expected Behavior: get a RETURN_DEVICE_ERROR return code, with an empty Transcript.MessageM
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 6: Successfully get one measurement block (signed), after getting SPDM_ERROR_CODE_BUSY on first attempt
  Expected Behavior: get a RETURN_SUCCESS return code, with an empty Transcript.MessageM
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 7: Error case, get an error response with code SPDM_ERROR_CODE_REQUEST_RESYNCH
  Expected Behavior: get a RETURN_DEVICE_ERROR return code, with an empty Transcript.MessageM
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->ConnectionInfo.ConnectionState, SpdmConnectionStateNotStarted);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 8: Error case, always get an error response with code SPDM_ERROR_CODE_RESPONSE_NOT_READY
  Expected Behavior: get a RETURN_DEVICE_ERROR return code, with an empty Transcript.MessageM
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

/**
  Test 9: Successfully get one measurement block (signed), after getting SPDM_ERROR_CODE_RESPONSE_NOT_READY on first attempt
  Expected Behavior: get a RETURN_SUCCESS return code, with an empty Transcript.MessageM
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 10: Successful response to get total number of measurements, without signature
  Expected Behavior: get a RETURN_SUCCESS return code, correct NumberOfBlocks, correct Transcript.MessageM.BufferSize
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  Status = SpdmGetMeasurement (
             SpdmContext, NULL, RequestAttribute,
             SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
             0, &NumberOfBlocks, NULL, NULL);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (NumberOfBlocks, 4);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(UINT16));
  free(Data);
}

/**
  Test 11: Successful response to get a measurement block, without signature
  Expected Behavior: get a RETURN_SUCCESS return code, correct Transcript.MessageM.BufferSize
**/
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
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16));
  free(Data);
}

/**
  Test 12: Error case, signature is invalid (all bytes are 0)
  Expected Behavior: get a RETURN_SECURITY_VIOLATION return code
**/
void TestSpdmRequesterGetMeasurementCase12(void **state) {
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
  SpdmTestContext->CaseId = 0xC;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 13: Error case, signature is invalid (random)
  Expected Behavior: get a RETURN_SECURITY_VIOLATION return code
**/
void TestSpdmRequesterGetMeasurementCase13(void **state) {
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
  SpdmTestContext->CaseId = 0xD;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 14: Error case, request a signed response, but response is malformed (signature absent)
  Expected Behavior: get a RETURN_DEVICE_ERROR return code
**/
void TestSpdmRequesterGetMeasurementCase14(void **state) {
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
  SpdmTestContext->CaseId = 0xE;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 15: Error case, response with wrong response code
  Expected Behavior: get a RETURN_DEVICE_ERROR return code
**/
void TestSpdmRequesterGetMeasurementCase15(void **state) {
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
  SpdmTestContext->CaseId = 0xF;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 16: SlotID verificaton, the response's SlotID should match the request
  Expected Behavior: get a RETURN_SUCCESS return code if the fields match, RETURN_DEVICE_ERROR otherwise. Either way, Transcript.MessageM should be empty
**/
void TestSpdmRequesterGetMeasurementCase16(void **state) {
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
  UINT8                SlotIDs[] = {0, 1, 2, 3, 0xF};

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x10;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  for(int i=0; i<sizeof(SlotIDs)/sizeof(SlotIDs[0]); i++) {
    MeasurementRecordLength = sizeof(MeasurementRecord);
    SpdmContext->Transcript.MessageM.BufferSize = 0;
    Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, SlotIDs[i], &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
    if (SlotIDs[i] == alternativeDefaultSlotID) {
      assert_int_equal (Status, RETURN_SUCCESS);
      assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
    } else if (SlotIDs[i] == 0xF) {
      assert_int_equal (Status, RETURN_INVALID_PARAMETER);
    } else {
      assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
      assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
    }
  }
  free(Data);
}

/**
  Test 17: Error case, response to get total number of measurements, but response NumberOfBlocks and/or MeasurementRecordLength are non 0
  Expected Behavior: get a RETURN_DEVICE_ERROR return code
**/
void TestSpdmRequesterGetMeasurementCase17(void **state) {
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
  SpdmTestContext->CaseId = 0x11;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  for (int i=0; i<3; i++) {
    // i=0 => both NumberOfBlocks and MeasurementRecordLength are non 0
    // i=1 => only NumberOfBlocks is non 0
    // i=2 => only is MeasurementRecordLength is non 0
    Status = SpdmGetMeasurement (
               SpdmContext, NULL, RequestAttribute,
               SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
               0, &NumberOfBlocks, NULL, NULL);
    assert_int_equal (Status, RETURN_DEVICE_ERROR);
    assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  }
  free(Data);
}

/**
  Test 18: Successful response to get a measurement block, without signature. Measurement block is the largest possible.
  Expected Behavior: get a RETURN_SUCCESS return code, correct Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase18(void **state) {
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
  SpdmTestContext->CaseId = 0x12;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE) + largeMeasurementSize);
  free(Data);
}

/**
  Test 19: Error case, MeasurementSpecification field in response has 2 bits set (bit 0 is one of them)
  Expected Behavior: get a RETURN_DEVICE_ERROR return code,
**/
void TestSpdmRequesterGetMeasurementCase19(void **state) {
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
  SpdmTestContext->CaseId = 0x13;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  // assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 20: Error case, MeasurementSpecification field in response has 2 bits set (bit 0 is not one of them)
  Expected Behavior: get a RETURN_DEVICE_ERROR return code,
**/
void TestSpdmRequesterGetMeasurementCase20(void **state) {
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
  SpdmTestContext->CaseId = 0x14;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  // assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 21: Error case, MeasurementSpecification field in response does not "match the selected measurement specification in the ALGORITHMS message"
  Expected Behavior: get a RETURN_DEVICE_ERROR return code,
**/
void TestSpdmRequesterGetMeasurementCase21(void **state) {
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
  SpdmTestContext->CaseId = 0x15;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  // assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 22: request a large number of unsigned measurements before requesting a signature
  Expected Behavior: RETURN_SUCCESS return code and correct Transcript.MessageM.BufferSize while Transcript.MessageM has room; RETURN_DEVICE_ERROR otherwise
**/
void TestSpdmRequesterGetMeasurementCase22(void **state) {
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
  UINTN                NumberOfMessages;
  #define TOTAL_MESSAGES 100

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x16;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  for (NumberOfMessages = 1; NumberOfMessages <= TOTAL_MESSAGES; NumberOfMessages++) {
    Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
    // It may fail due to Transcript.MessageM overflow
    if (Status == RETURN_SUCCESS) {
      assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, NumberOfMessages * (sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16)));
    } else {
      assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
      break;
    }
  }
  free(Data);
}

/**
  Test 23: Successful response to get a measurement block, without signature. Response contains opaque data
  Expected Behavior: get a RETURN_SUCCESS return code, correct Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase23(void **state) {
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
  SpdmTestContext->CaseId = 0x17;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16) + MAX_SPDM_OPAQUE_DATA_SIZE);
  free(Data);
}

/**
  Test 24: Error case, reponse contains opaque data larger than the maximum allowed
  Expected Behavior: get a RETURN_DEVICE_ERROR return code, correct Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase24(void **state) {
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
  SpdmTestContext->CaseId = 0x18;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_MESSAGE_HEADER));
  free(Data);
}

/**
  Test 25: Successful response to get a measurement block, with signature. Response contains opaque data
  Expected Behavior: get a RETURN_SUCCESS return code, empty Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase25(void **state) {
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
  SpdmTestContext->CaseId = 0x19;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, 0);
  free(Data);
}

/**
  Test 26: Error case, request with signature, but response opaque data is S bytes shorter than informed
  Expected Behavior: get a RETURN_DEVICE_ERROR return code, correct Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase26(void **state) {
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
  SpdmTestContext->CaseId = 0x1A;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_GET_MEASUREMENTS_REQUEST));
  free(Data);
}

/**
  Test 27: Error case, request with signature, but response opaque data is (S+1) bytes shorter than informed
  Expected Behavior: get a RETURN_DEVICE_ERROR return code, correct Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase27(void **state) {
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
  SpdmTestContext->CaseId = 0x1B;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_GET_MEASUREMENTS_REQUEST));
  free(Data);
}

/**
  Test 28: Error case, request with signature, but response opaque data is 1 byte longer than informed
  Expected Behavior: get a RETURN_DEVICE_ERROR return code, correct Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase28(void **state) {
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
  UINTN                ExpectedBufferSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1C;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
  ExpectedBufferSize = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, ExpectedBufferSize);
  free(Data);
}

/**
  Test 29: Request measurement without signature, but response opaque data is 1 byte longer than informed
  Expected Behavior: extra byte should just be ignored. Get a RETURN_SUCCESS return code, correct Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase29(void **state) {
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
  SpdmTestContext->CaseId = 0x1D;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE) +
                                                                  sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) +
                                                                  sizeof(UINT16) + MAX_SPDM_OPAQUE_DATA_SIZE/2 - 1);
  free(Data);
}

/**
  Test 30: Request measurement without signature, response opaque data contains MAXUINT16 bytes, but informed opaque data size is valid
  Expected Behavior: extra bytes should just be ignored. Get a RETURN_SUCCESS return code, correct Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase30(void **state) {
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
  SpdmTestContext->CaseId = 0x1E;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16) + MAX_SPDM_OPAQUE_DATA_SIZE/2);
  free(Data);
}

/**
  Test 31: Error case, reponse contains opaque data larger than the maximum allowed. MAXUINT16 is used
  Expected Behavior: get a RETURN_DEVICE_ERROR return code, correct Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase31(void **state) {
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
  SpdmTestContext->CaseId = 0x1F;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, 1, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo) + sizeof(UINT16) + MAX_UINT16);
  free(Data);
}

/**
  Test 32: Successful response to get all measurement blocks, without signature
  Expected Behavior: get a RETURN_SUCCESS return code, correct Transcript.MessageM.BufferSize
**/
void TestSpdmRequesterGetMeasurementCase32(void **state) {
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
  SpdmTestContext->CaseId = 0x20;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->Transcript.MessageM.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
  RequestAttribute = 0;

  MeasurementRecordLength = sizeof(MeasurementRecord);
  Status = SpdmGetMeasurement (SpdmContext, NULL, RequestAttribute, SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS, 0, &NumberOfBlock, &MeasurementRecordLength, MeasurementRecord);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageM.BufferSize, sizeof(SPDM_MESSAGE_HEADER) + sizeof(SPDM_MEASUREMENTS_RESPONSE) + 2*(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + GetSpdmMeasurementHashSize (mUseMeasurementHashAlgo)) + sizeof(UINT16));
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
      // ConnectionState check failed
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
      // Successful response to get total measurement number without signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase10),
      // Successful response to get one measurement without signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase11),
      // Error: request signature, but response contains null signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase12),
      // Error: request signature, but response contains wrong non-null signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase13),
      // Error: request signature, but response does not contain signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase14),
      // Error: wrong response code
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase15),
      // Error: SlotID mismatch
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase16),
      // Error: get total measurement number (no signature), but there is a measurement block
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase17),
      // Large measurement block
      // cmocka_unit_test(TestSpdmRequesterGetMeasurementCase18), // test triggers runtime assert because the transmitted packet is larger than the 4096-byte buffer
      // Error: MeasurementSpecification has 2 bits set (bit 0 is one of them)
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase19),
      // Error: MeasurementSpecification has 2 bits set (bit 0 is not one of them)
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase20),
      // Error: MeasurementSpecification does not "match the selected measurement specification in the ALGORITHMS message"
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase21),
      // Request a large number of measurement blocks before requesting a signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase22),
      // Successful response to get one measurement with opaque data without signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase23),
      // Error: get one measurement with opaque data larger than 1024, without signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase24),
      // Successful response to get one measurement with opaque data with signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase25),
      // Error: response to get one measurement with opaque data with signature, opaque data is S bytes shorter than announced
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase26),
      // Error: response to get one measurement with opaque data with signature, opaque data is S+1 bytes shorter than announced
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase27),
      // Error: response to get one measurement with opaque data with signature, opaque data is 1 byte longer than announced
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase28),
      // response to get one measurement with opaque data without signature, opaque data is 1 byte longer than announced
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase29),
      // response to get one measurement with opaque data without signature, opaque data has MAX_UINT16, but opaque data size is valid
      // cmocka_unit_test(TestSpdmRequesterGetMeasurementCase30), // test triggers runtime assert because the transmitted packet is larger than the 4096-byte buffer
      // Error: get one measurement with opaque data too large, without signature
      // cmocka_unit_test(TestSpdmRequesterGetMeasurementCase31), // test triggers runtime assert because the transmitted packet is larger than the 4096-byte buffer
      // Successful response to get all measurements without signature
      cmocka_unit_test(TestSpdmRequesterGetMeasurementCase32),
  };

  SetupSpdmTestContext (&mSpdmRequesterGetMeasurementTestContext);

  return cmocka_run_group_tests(SpdmRequesterGetMeasurementTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);

}

