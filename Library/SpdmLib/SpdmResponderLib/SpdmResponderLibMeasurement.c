/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

BOOLEAN
SpdmResponderGenerateSpdmMeasurementSignature (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN VOID                       *ResponseMessage,
  IN UINTN                      ResponseMessageSize,
  OUT UINT8                     *Signature
  )
{
  UINT8                         HashData[MAX_HASH_SIZE];
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT32                        HashSize;

  if (SpdmContext->LocalContext.SpdmDataSignFunc == NULL) {
    return FALSE;
  }

  SignatureSize = GetSpdmAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  AppendManagedBuffer (&SpdmContext->Transcript.L1L2, ResponseMessage, ResponseMessageSize);
  
  DEBUG((DEBUG_INFO, "Calc L1L2 Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.L1L2), GetManagedBufferSize(&SpdmContext->Transcript.L1L2));

  HashFunc (SpdmContext, GetManagedBuffer(&SpdmContext->Transcript.L1L2), GetManagedBufferSize(&SpdmContext->Transcript.L1L2), HashData);
  DEBUG((DEBUG_INFO, "Calc L1L2 Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  
  Result = SpdmContext->LocalContext.SpdmDataSignFunc (
             SpdmContext,
             TRUE,
             SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
             HashData,
             HashSize,
             Signature,
             &SignatureSize
             );

  return Result;
}

BOOLEAN
SpdmResponderCreateMeasurementSig (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN VOID                       *ResponseMessage,
  IN UINTN                      ResponseMessageSize
  )
{
  UINT8                         *Ptr;
  UINTN                         MeasurmentSigSize;
  UINTN                         SignatureSize;
  BOOLEAN                       Result;
  
  SignatureSize = GetSpdmAsymSize (SpdmContext);
  MeasurmentSigSize = SPDM_NONCE_SIZE +
                      sizeof(UINT16) +
                      SpdmContext->LocalContext.OpaqueMeasurementRspSize +
                      SignatureSize;
  ASSERT (ResponseMessageSize > MeasurmentSigSize);
  Ptr = (VOID *)((UINT8 *)ResponseMessage + ResponseMessageSize - MeasurmentSigSize);
  
  GetRandomNumber (SPDM_NONCE_SIZE, Ptr);
  Ptr += SPDM_NONCE_SIZE;

  *(UINT16 *)Ptr = (UINT16)SpdmContext->LocalContext.OpaqueMeasurementRspSize;
  Ptr += sizeof(UINT16);
  CopyMem (Ptr, SpdmContext->LocalContext.OpaqueMeasurementRsp, SpdmContext->LocalContext.OpaqueMeasurementRspSize);
  Ptr += SpdmContext->LocalContext.OpaqueMeasurementRspSize;
  
  Result = SpdmResponderGenerateSpdmMeasurementSignature (SpdmContext, ResponseMessage, ResponseMessageSize - SignatureSize, (VOID *)Ptr);
  return Result;
}

RETURN_STATUS
EFIAPI
SpdmGetResponseMeasurement (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  UINT8                          Index;
  SPDM_GET_MEASUREMENTS_REQUEST  *SpdmRequest;
  SPDM_MEASUREMENTS_RESPONSE     *SpdmResponse;
  UINTN                          SpdmResponseSize;
  RETURN_STATUS                  Status;
  UINT32                         HashSize;
  UINTN                          SignatureSize;
  UINTN                          MeasurmentSigSize;
  UINTN                          MeasurmentBlockSize;
  SPDM_MEASUREMENT_BLOCK_DMTF    *MeasurmentBlock;
  SPDM_MEASUREMENT_BLOCK_DMTF    *CachedMeasurmentBlock;
  SPDM_DEVICE_CONTEXT            *SpdmContext;
  UINT8                          SlotNum;

  SpdmContext = Context;
  SpdmRequest = Request;
  if (SpdmRequest->Header.Param1 == SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
    if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
      if (RequestSize < sizeof(SPDM_GET_MEASUREMENTS_REQUEST)) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
      RequestSize = sizeof(SPDM_GET_MEASUREMENTS_REQUEST);
    } else {
      if (RequestSize < sizeof(SPDM_GET_MEASUREMENTS_REQUEST) - sizeof(SpdmRequest->SlotIDParam)) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
      RequestSize = sizeof(SPDM_GET_MEASUREMENTS_REQUEST) - sizeof(SpdmRequest->SlotIDParam);
    }
  } else {
    if (RequestSize != sizeof(SPDM_MESSAGE_HEADER)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  }
  if (((SpdmContext->SpdmCmdReceiveState & SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CAPABILITIES_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CERTIFICATE_RECEIVE_FLAG) == 0)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  //
  // Cache
  //
  ResetManagedBuffer (&SpdmContext->Transcript.M1M2);
  AppendManagedBuffer (&SpdmContext->Transcript.L1L2, SpdmRequest, RequestSize);

  HashSize = GetSpdmMeasurementHashSize (SpdmContext);
  SignatureSize = GetSpdmAsymSize (SpdmContext);
  MeasurmentSigSize = SPDM_NONCE_SIZE +
                      sizeof(UINT16) +
                      SpdmContext->LocalContext.OpaqueMeasurementRspSize +
                      SignatureSize;
  MeasurmentBlockSize = sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + HashSize;

  ASSERT(SpdmContext->LocalContext.DeviceMeasurementCount <= MAX_SPDM_MEASUREMENT_BLOCK_COUNT);

  switch (SpdmRequest->Header.Param2) {
  case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS:
    SpdmResponseSize = sizeof(SPDM_MEASUREMENTS_RESPONSE);
    if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
      SpdmResponseSize += MeasurmentSigSize;
    }

    ASSERT (*ResponseSize >= SpdmResponseSize);
    *ResponseSize = SpdmResponseSize;
    ZeroMem (Response, *ResponseSize);
    SpdmResponse = Response;


    if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    } else {
      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    }
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = SpdmContext->LocalContext.DeviceMeasurementCount;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 0;
    *(UINT32 *)SpdmResponse->MeasurementRecordLength = 0;

    if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
      if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
        SlotNum = SpdmRequest->SlotIDParam;
        if (SlotNum > SpdmContext->LocalContext.SlotCount) {
          SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
          return RETURN_SUCCESS;
        }
      }
      Status = SpdmResponderCreateMeasurementSig (SpdmContext, SpdmResponse, SpdmResponseSize);
      if (RETURN_ERROR(Status)) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_MEASUREMENTS, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
    }
    break;

  case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
    SpdmResponseSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + MeasurmentBlockSize * SpdmContext->LocalContext.DeviceMeasurementCount;
    if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
      SpdmResponseSize += MeasurmentSigSize;
    }

    ASSERT (*ResponseSize >= SpdmResponseSize);
    *ResponseSize = SpdmResponseSize;
    ZeroMem (Response, *ResponseSize);
    SpdmResponse = Response;

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = SpdmContext->LocalContext.DeviceMeasurementCount;
    *(UINT32 *)SpdmResponse->MeasurementRecordLength = (UINT32)(MeasurmentBlockSize * SpdmContext->LocalContext.DeviceMeasurementCount);

    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    CachedMeasurmentBlock = SpdmContext->LocalContext.DeviceMeasurement;
    for (Index = 0; Index < SpdmContext->LocalContext.DeviceMeasurementCount; Index++) {
      CopyMem (MeasurmentBlock, CachedMeasurmentBlock, MeasurmentBlockSize);
      CachedMeasurmentBlock = (VOID *)((UINTN)CachedMeasurmentBlock + MeasurmentBlockSize);
      MeasurmentBlock = (VOID *)((UINTN)MeasurmentBlock + MeasurmentBlockSize);
    }

    if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
      if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
        SlotNum = SpdmRequest->SlotIDParam;
        if (SlotNum > SpdmContext->LocalContext.SlotCount) {
          SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
          return RETURN_SUCCESS;
        }
      }
      Status = SpdmResponderCreateMeasurementSig (SpdmContext, SpdmResponse, SpdmResponseSize);
      if (RETURN_ERROR(Status)) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_MEASUREMENTS, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
    }
    break;

  default:
    if (SpdmRequest->Header.Param2 <= SpdmContext->LocalContext.DeviceMeasurementCount) {

      SpdmResponseSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + MeasurmentBlockSize;
      if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        SpdmResponseSize += MeasurmentSigSize;
      }

      ASSERT (*ResponseSize >= SpdmResponseSize);
      *ResponseSize = SpdmResponseSize;
      ZeroMem (Response, *ResponseSize);
      SpdmResponse = Response;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->NumberOfBlocks = 1;
      *(UINT32 *)SpdmResponse->MeasurementRecordLength = (UINT32)MeasurmentBlockSize;

      MeasurmentBlock = (VOID *)(SpdmResponse + 1);
      CachedMeasurmentBlock = (VOID *)((UINTN)SpdmContext->LocalContext.DeviceMeasurement + MeasurmentBlockSize * (SpdmRequest->Header.Param2 - 1));
      CopyMem (MeasurmentBlock, CachedMeasurmentBlock, MeasurmentBlockSize);

      if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
          SlotNum = SpdmRequest->SlotIDParam;
          if (SlotNum > SpdmContext->LocalContext.SlotCount) {
            SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
            return RETURN_SUCCESS;
          }
        }
        Status = SpdmResponderCreateMeasurementSig (SpdmContext, SpdmResponse, SpdmResponseSize);
        if (RETURN_ERROR(Status)) {
          SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_MEASUREMENTS, ResponseSize, Response);
          return RETURN_SUCCESS;
        }
      }
    } else {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    break;
  }
  if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
    //
    // Reset
    //
    ResetManagedBuffer (&SpdmContext->Transcript.L1L2);
  } else {
    AppendManagedBuffer (&SpdmContext->Transcript.L1L2, SpdmResponse, *ResponseSize);
  }
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_MEASUREMENTS_RECEIVE_FLAG;
  return RETURN_SUCCESS;
}

