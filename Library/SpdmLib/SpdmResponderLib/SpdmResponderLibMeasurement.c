/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

#pragma pack(1)

typedef struct {
  UINT8                       Nonce[SPDM_NONCE_SIZE];
  UINT16                      OpaqueLength;
  UINT8                       OpaqueData[DEFAULT_OPAQUE_LENGTH];
//UINT8                       Signature[SignatureSize];
} SPDM_MEASUREMENT_SIG;

#pragma pack()

BOOLEAN
GenerateSpdmMeasurementSignature (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN VOID                       *ResponseMessage,
  IN UINTN                      ResponseMessageSize,
  OUT UINT8                     *Signature
  )
{
  VOID                          *RsaContext;
  UINT8                         HashData[MAX_HASH_SIZE];
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT32                        HashSize;
  HASH_ALL                      HashFunc;

  if (SpdmContext->LocalContext.PrivatePem == NULL) {
    return FALSE;
  }

  SignatureSize = GetSpdmAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);
  HashFunc = GetSpdmHashFunc (SpdmContext);

  Result = RsaGetPrivateKeyFromPem (SpdmContext->LocalContext.PrivatePem, SpdmContext->LocalContext.PrivatePemSize, NULL, &RsaContext);
  if (!Result) {
    return FALSE;
  }
  
  AppendManagedBuffer (&SpdmContext->Transcript.L1L2, ResponseMessage, ResponseMessageSize);
  
  DEBUG((DEBUG_INFO, "Calc L1L2 Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.L1L2), GetManagedBufferSize(&SpdmContext->Transcript.L1L2));

  HashFunc (GetManagedBuffer(&SpdmContext->Transcript.L1L2), GetManagedBufferSize(&SpdmContext->Transcript.L1L2), HashData);
  DEBUG((DEBUG_INFO, "Calc L1L2 Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  
  Result = RsaPkcs1Sign (
             RsaContext,
             HashData,
             HashSize,
             Signature,
             &SignatureSize
             );
  RsaFree (RsaContext);

  return Result;
}

RETURN_STATUS
CreateMeasurementSig (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN VOID                       *ResponseMessage,
  IN UINTN                      ResponseMessageSize
  )
{
  SPDM_MEASUREMENT_SIG          *SigStruct;
  UINTN                         MeasurmentSigSize;
  UINTN                         SignatureSize;
  BOOLEAN                       Result;
  
  SignatureSize = GetSpdmAsymSize (SpdmContext);
  MeasurmentSigSize = sizeof(SPDM_MEASUREMENT_SIG) + SignatureSize;
  ASSERT (ResponseMessageSize > MeasurmentSigSize);
  SigStruct = (VOID *)((UINT8 *)ResponseMessage + ResponseMessageSize - MeasurmentSigSize);
  
  GetRandomNumber (SPDM_NONCE_SIZE, SigStruct->Nonce);
  SigStruct->OpaqueLength = DEFAULT_OPAQUE_LENGTH;
  SetMem (SigStruct->OpaqueData, DEFAULT_OPAQUE_LENGTH, DEFAULT_OPAQUE_DATA);
  
  Result = GenerateSpdmMeasurementSignature (SpdmContext, ResponseMessage, ResponseMessageSize - SignatureSize, (VOID *)(SigStruct + 1));
  if (!Result) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
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
  UINTN                          SpdmRequestSize;
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

  SpdmContext = Context;
  SpdmRequest = Request;
  if (SpdmRequest->Header.Param1 == SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
    if (RequestSize != sizeof(SPDM_GET_MEASUREMENTS_REQUEST)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  } else {
    if (RequestSize != sizeof(SPDM_MESSAGE_HEADER)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  }
  SpdmRequestSize = RequestSize;
  //
  // Cache
  //
  ResetManagedBuffer (&SpdmContext->Transcript.M1M2);
  AppendManagedBuffer (&SpdmContext->Transcript.L1L2, SpdmRequest, RequestSize);

  HashSize = GetSpdmMeasurementHashSize (SpdmContext);
  SignatureSize = GetSpdmAsymSize (SpdmContext);
  MeasurmentSigSize = sizeof(SPDM_MEASUREMENT_SIG) + SignatureSize;
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

    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.RequestResponseCode = SPDM_MEASUREMENTS;
    SpdmResponse->Header.Param1 = SpdmContext->LocalContext.DeviceMeasurementCount;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 0;
    *(UINT32 *)SpdmResponse->MeasurementRecordLength = 0;

    if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
      Status = CreateMeasurementSig (SpdmContext, SpdmResponse, SpdmResponseSize);
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
      Status = CreateMeasurementSig (SpdmContext, SpdmResponse, SpdmResponseSize);
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
        Status = CreateMeasurementSig (SpdmContext, SpdmResponse, SpdmResponseSize);
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
  return RETURN_SUCCESS;
}

