/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  This function creates the measurement signature to response message based upon L1L2.
  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ResponseMessage              The measurement response message with empty signature to be filled.
  @param  ResponseMessageSize          Total size in bytes of the response message including signature.

  @retval TRUE  measurement signature is created.
  @retval FALSE measurement signature is not created.
**/
BOOLEAN
SpdmCreateMeasurementSignature (
  IN     SPDM_DEVICE_CONTEXT    *SpdmContext,
  IN OUT VOID                   *ResponseMessage,
  IN     UINTN                  ResponseMessageSize
  )
{
  UINT8                         *Ptr;
  UINTN                         MeasurmentSigSize;
  UINTN                         SignatureSize;
  BOOLEAN                       Result;
  RETURN_STATUS                 Status;

  SignatureSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
  MeasurmentSigSize = SPDM_NONCE_SIZE +
                      sizeof(UINT16) +
                      SpdmContext->LocalContext.OpaqueMeasurementRspSize +
                      SignatureSize;
  ASSERT (ResponseMessageSize > MeasurmentSigSize);
  Ptr = (VOID *)((UINT8 *)ResponseMessage + ResponseMessageSize - MeasurmentSigSize);
  
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
  Ptr += SPDM_NONCE_SIZE;

  *(UINT16 *)Ptr = (UINT16)SpdmContext->LocalContext.OpaqueMeasurementRspSize;
  Ptr += sizeof(UINT16);
  CopyMem (Ptr, SpdmContext->LocalContext.OpaqueMeasurementRsp, SpdmContext->LocalContext.OpaqueMeasurementRspSize);
  Ptr += SpdmContext->LocalContext.OpaqueMeasurementRspSize;

  Status = SpdmAppendMessageM (SpdmContext, ResponseMessage, ResponseMessageSize - SignatureSize);
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  Result = SpdmGenerateMeasurementSignature (SpdmContext, Ptr);

  return Result;
}

/**
  This function creates the opaque data to response message.
  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ResponseMessage              The measurement response message with empty signature to be filled.
  @param  ResponseMessageSize          Total size in bytes of the response message including signature.
**/
VOID
SpdmCreateMeasurementOpaque (
  IN     SPDM_DEVICE_CONTEXT    *SpdmContext,
  IN OUT VOID                   *ResponseMessage,
  IN     UINTN                  ResponseMessageSize
  )
{
  UINT8                         *Ptr;
  UINTN                         MeasurmentNoSigSize;

  MeasurmentNoSigSize = sizeof(UINT16) +
                        SpdmContext->LocalContext.OpaqueMeasurementRspSize;
  ASSERT (ResponseMessageSize > MeasurmentNoSigSize);
  Ptr = (VOID *)((UINT8 *)ResponseMessage + ResponseMessageSize - MeasurmentNoSigSize);

  *(UINT16 *)Ptr = (UINT16)SpdmContext->LocalContext.OpaqueMeasurementRspSize;
  Ptr += sizeof(UINT16);
  CopyMem (Ptr, SpdmContext->LocalContext.OpaqueMeasurementRsp, SpdmContext->LocalContext.OpaqueMeasurementRspSize);
  Ptr += SpdmContext->LocalContext.OpaqueMeasurementRspSize;

  return ;
}

/**
  Process the SPDM GET_MEASUREMENT request and return the response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestSize                  Size in bytes of the request data.
  @param  Request                      A pointer to the request data.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  Response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
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
  UINTN                          SignatureSize;
  UINTN                          MeasurmentSigSize;
  UINTN                          MeasurmentNoSigSize;
  UINTN                          MeasurmentRecordSize;
  UINTN                          MeasurmentBlockSize;
  SPDM_MEASUREMENT_BLOCK_DMTF    *MeasurmentBlock;
  SPDM_MEASUREMENT_BLOCK_DMTF    *CachedMeasurmentBlock;
  SPDM_DEVICE_CONTEXT            *SpdmContext;
  UINT8                          SlotIdParam;
  UINT8                          DeviceMeasurement[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
  UINT8                          DeviceMeasurementCount;
  UINTN                          DeviceMeasurementSize;
  BOOLEAN                        Ret;
  SPDM_SESSION_INFO              *SessionInfo;
  SPDM_SESSION_STATE             SessionState;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  // check local context here, because MEAS_CAP is reserved for requester.
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_MEASUREMENTS, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (!SpdmContext->LastSpdmRequestSessionIdValid) {
    if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateAuthenticated) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  } else {
    if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateNegotiated) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SpdmContext->LastSpdmRequestSessionId);
    if (SessionInfo == NULL) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    SessionState = SpdmSecuredMessageGetSessionState (SessionInfo->SecuredMessageContext);
    if (SessionState != SpdmSessionStateEstablished) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
      return RETURN_UNSUPPORTED;
    }
  }

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

  if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
    if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  }

  DeviceMeasurementSize = sizeof(DeviceMeasurement);
  Ret = SpdmMeasurementCollectionFunc (
          SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec,
          SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo,
          &DeviceMeasurementCount,
          DeviceMeasurement,
          &DeviceMeasurementSize
          );
  if (!Ret) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  ASSERT(DeviceMeasurementCount <= MAX_SPDM_MEASUREMENT_BLOCK_COUNT);

  //
  // Cache
  //
  Status = SpdmAppendMessageM (SpdmContext, SpdmRequest, RequestSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SignatureSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
  MeasurmentSigSize = SPDM_NONCE_SIZE +
                      sizeof(UINT16) +
                      SpdmContext->LocalContext.OpaqueMeasurementRspSize +
                      SignatureSize;
  MeasurmentNoSigSize = sizeof(UINT16) +
                        SpdmContext->LocalContext.OpaqueMeasurementRspSize;

  switch (SpdmRequest->Header.Param2) {
  case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS:
    SpdmResponseSize = sizeof(SPDM_MEASUREMENTS_RESPONSE);
    if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
      SpdmResponseSize += MeasurmentSigSize;
    } else {
      SpdmResponseSize += MeasurmentNoSigSize;
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
    SpdmResponse->Header.Param1 = DeviceMeasurementCount;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = 0;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, 0);

    if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
      if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
        SlotIdParam = SpdmRequest->SlotIDParam;
        if ((SlotIdParam != 0xF) && (SlotIdParam >= SpdmContext->LocalContext.SlotCount)) {
          SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
          ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
          return RETURN_SUCCESS;
        }
        SpdmResponse->Header.Param2 = SlotIdParam;
      }
      Status = SpdmCreateMeasurementSignature (SpdmContext, SpdmResponse, SpdmResponseSize);
      if (RETURN_ERROR(Status)) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_MEASUREMENTS, ResponseSize, Response);
        ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
        return RETURN_SUCCESS;
      }
    } else {
      SpdmCreateMeasurementOpaque (SpdmContext, SpdmResponse, SpdmResponseSize);
    }
    break;

  case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
    MeasurmentRecordSize = 0;
    CachedMeasurmentBlock = (VOID *)DeviceMeasurement;
    for (Index = 0; Index < DeviceMeasurementCount; Index++) {
      MeasurmentBlockSize = sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + CachedMeasurmentBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize;
      MeasurmentRecordSize += MeasurmentBlockSize;
      CachedMeasurmentBlock = (VOID *)((UINTN)CachedMeasurmentBlock + MeasurmentBlockSize);
    }

    SpdmResponseSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + MeasurmentRecordSize;
    if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
      SpdmResponseSize += MeasurmentSigSize;
    } else {
      SpdmResponseSize += MeasurmentNoSigSize;
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
    SpdmResponse->Header.Param1 = 0;
    SpdmResponse->Header.Param2 = 0;
    SpdmResponse->NumberOfBlocks = DeviceMeasurementCount;
    SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)MeasurmentRecordSize);

    MeasurmentBlock = (VOID *)(SpdmResponse + 1);
    CachedMeasurmentBlock = (VOID *)DeviceMeasurement;
    for (Index = 0; Index < DeviceMeasurementCount; Index++) {
      MeasurmentBlockSize = sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + CachedMeasurmentBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize;
      CopyMem (MeasurmentBlock, CachedMeasurmentBlock, MeasurmentBlockSize);
      CachedMeasurmentBlock = (VOID *)((UINTN)CachedMeasurmentBlock + MeasurmentBlockSize);
      MeasurmentBlock = (VOID *)((UINTN)MeasurmentBlock + MeasurmentBlockSize);
    }

    if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
      if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
        SlotIdParam = SpdmRequest->SlotIDParam;
        if ((SlotIdParam != 0xF) && (SlotIdParam >= SpdmContext->LocalContext.SlotCount)) {
          SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
          ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
          return RETURN_SUCCESS;
        }
        SpdmResponse->Header.Param2 = SlotIdParam;
      }
      Status = SpdmCreateMeasurementSignature (SpdmContext, SpdmResponse, SpdmResponseSize);
      if (RETURN_ERROR(Status)) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_MEASUREMENTS, ResponseSize, Response);
        ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
        return RETURN_SUCCESS;
      }
    } else {
      SpdmCreateMeasurementOpaque (SpdmContext, SpdmResponse, SpdmResponseSize);
    }
    break;

  default:
    if (SpdmRequest->Header.Param2 <= DeviceMeasurementCount) {
      MeasurmentRecordSize = 0;
      CachedMeasurmentBlock = (VOID *)DeviceMeasurement;
      for (Index = 0; Index < DeviceMeasurementCount; Index++) {
        MeasurmentBlockSize = sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + CachedMeasurmentBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize;
        if (Index + 1 == SpdmRequest->Header.Param2) {
          MeasurmentRecordSize = MeasurmentBlockSize;
          break;
        }
        CachedMeasurmentBlock = (VOID *)((UINTN)CachedMeasurmentBlock + MeasurmentBlockSize);
      }

      SpdmResponseSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + MeasurmentRecordSize;
      if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        SpdmResponseSize += MeasurmentSigSize;
      } else {
        SpdmResponseSize += MeasurmentNoSigSize;
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
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->NumberOfBlocks = 1;
      SpdmWriteUint24 (SpdmResponse->MeasurementRecordLength, (UINT32)MeasurmentRecordSize);

      MeasurmentBlock = (VOID *)(SpdmResponse + 1);
      CachedMeasurmentBlock = (VOID *)DeviceMeasurement;
      for (Index = 0; Index < DeviceMeasurementCount; Index++) {
        MeasurmentBlockSize = sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + CachedMeasurmentBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize;
        if (Index + 1 == SpdmRequest->Header.Param2) {
          CopyMem (MeasurmentBlock, CachedMeasurmentBlock, MeasurmentBlockSize);
          MeasurmentBlock->MeasurementBlockCommonHeader.Index = 1; // always set to 1, since we only have 1 block.
          break;
        }
        CachedMeasurmentBlock = (VOID *)((UINTN)CachedMeasurmentBlock + MeasurmentBlockSize);
      }

      if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
        if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
          SlotIdParam = SpdmRequest->SlotIDParam;
          if ((SlotIdParam != 0xF) && (SlotIdParam >= SpdmContext->LocalContext.SlotCount)) {
            SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
            ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
            return RETURN_SUCCESS;
          }
          SpdmResponse->Header.Param2 = SlotIdParam;
        }
        Status = SpdmCreateMeasurementSignature (SpdmContext, SpdmResponse, SpdmResponseSize);
        if (RETURN_ERROR(Status)) {
          SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_MEASUREMENTS, ResponseSize, Response);
          ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
          return RETURN_SUCCESS;
        }
      } else {
        SpdmCreateMeasurementOpaque (SpdmContext, SpdmResponse, SpdmResponseSize);
      }
    } else {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
      return RETURN_SUCCESS;
    }
    break;
  }
  if ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0) {
    //
    // Reset
    //
    ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
  } else {
    Status = SpdmAppendMessageM (SpdmContext, SpdmResponse, *ResponseSize);
    if (RETURN_ERROR(Status)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
      return RETURN_SUCCESS;
    }
  }

  return RETURN_SUCCESS;
}

