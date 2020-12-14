/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  This function calculate the measurement summary hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MeasurementSummaryHashType   The type of the measurement summary hash.
  @param  MeasurementSummaryHash       The buffer to store the measurement summary hash.

  @retval TRUE  measurement summary hash is generated.
  @retval FALSE measurement summary hash is not generated.
**/
BOOLEAN
SpdmResponderCalculateMeasurementSummaryHash (
  IN  SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN  UINT8                MeasurementSummaryHashType,
  OUT UINT8                *MeasurementSummaryHash
  )
{
  UINT8                         MeasurementData[MAX_HASH_SIZE * MAX_SPDM_MEASUREMENT_BLOCK_COUNT];
  UINTN                         Index;
  UINTN                         LocalIndex;
  UINT32                        HashSize;
  UINTN                         MeasurmentBlockSize;
  SPDM_MEASUREMENT_BLOCK_DMTF   *CachedMeasurmentBlock;
  
  HashSize = GetSpdmMeasurementHashSize (SpdmContext);
  
  MeasurmentBlockSize = sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + HashSize;

  ASSERT(SpdmContext->LocalContext.DeviceMeasurementCount <= MAX_SPDM_MEASUREMENT_BLOCK_COUNT);

  switch (MeasurementSummaryHashType) {
  case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
    ZeroMem (MeasurementSummaryHash, HashSize);
    break;
  case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
    CachedMeasurmentBlock = SpdmContext->LocalContext.DeviceMeasurement;
    LocalIndex = 0;
    for (Index = 0; Index < SpdmContext->LocalContext.DeviceMeasurementCount; Index++) {
      switch (CachedMeasurmentBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType) {
      case SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM:
        CopyMem (
          &MeasurementData[HashSize * LocalIndex],
          (CachedMeasurmentBlock + 1),
          HashSize
          );
        LocalIndex ++;
        break;
      default:
        break;
      }
      CachedMeasurmentBlock = (VOID *)((UINTN)CachedMeasurmentBlock + MeasurmentBlockSize);
    }
    SpdmHashAll (SpdmContext, MeasurementData, HashSize * LocalIndex, MeasurementSummaryHash);
    break;
  case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:
    CachedMeasurmentBlock = SpdmContext->LocalContext.DeviceMeasurement;
    for (Index = 0; Index < SpdmContext->LocalContext.DeviceMeasurementCount; Index++) {
      CopyMem (
        &MeasurementData[HashSize * Index],
        (CachedMeasurmentBlock + 1),
        HashSize
        );
      CachedMeasurmentBlock = (VOID *)((UINTN)CachedMeasurmentBlock + MeasurmentBlockSize);
    }
    SpdmHashAll (SpdmContext, MeasurementData, HashSize * SpdmContext->LocalContext.DeviceMeasurementCount, MeasurementSummaryHash);
    break;
  default:
    return FALSE;
    break;
  }
  return TRUE;
}

/**
  This function generates the challenge signature based upon M1M2 for mutual authentication.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ResponseMessage              The response message buffer.
  @param  ResponseMessageSize          Size in bytes of the response message buffer.
  @param  Signature                    The buffer to store the challenge signature.

  @retval TRUE  challenge signature is generated.
  @retval FALSE challenge signature is not generated.
**/
BOOLEAN
SpdmResponderGenerateChallengeSignature (
  IN  SPDM_DEVICE_CONTEXT        *SpdmContext,
  IN  VOID                       *ResponseMessage,
  IN  UINTN                      ResponseMessageSize,
  OUT UINT8                      *Signature
  )
{
  UINT8                         HashData[MAX_HASH_SIZE];
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT32                        HashSize;
  
  if (SpdmContext->LocalContext.SpdmResponderDataSignFunc == NULL) {
    return FALSE;
  }

  SignatureSize = GetSpdmAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  AppendManagedBuffer (&SpdmContext->Transcript.MessageC, ResponseMessage, ResponseMessageSize);
  AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageB), GetManagedBufferSize(&SpdmContext->Transcript.MessageB));
  AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageC), GetManagedBufferSize(&SpdmContext->Transcript.MessageC));

  DEBUG((DEBUG_INFO, "Calc MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "Calc MessageB Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageB), GetManagedBufferSize(&SpdmContext->Transcript.MessageB));

  DEBUG((DEBUG_INFO, "Calc MessageC Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageC), GetManagedBufferSize(&SpdmContext->Transcript.MessageC));

  SpdmHashAll (SpdmContext, GetManagedBuffer(&SpdmContext->Transcript.M1M2), GetManagedBufferSize(&SpdmContext->Transcript.M1M2), HashData);
  DEBUG((DEBUG_INFO, "Calc M1M2 Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  
  Result = SpdmContext->LocalContext.SpdmResponderDataSignFunc (
             SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
             HashData,
             HashSize,
             Signature,
             &SignatureSize
             );

  return Result;
}

/**
  Process the SPDM CHALLENGE request and return the response.

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
SpdmGetResponseChallengeAuth (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_CHALLENGE_REQUEST                    *SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_CHALLENGE_AUTH_RESPONSE              *SpdmResponse;
  BOOLEAN                                   Result;
  UINTN                                     SignatureSize;
  UINT8                                     SlotNum;
  UINT32                                    HashSize;
  UINT8                                     *Ptr;
  UINTN                                     TotalSize;
  SPDM_DEVICE_CONTEXT                       *SpdmContext;
  SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE    AuthAttribute;

  SpdmContext = Context;
  SpdmRequest = Request;
  if (RequestSize != sizeof(SPDM_CHALLENGE_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (((SpdmContext->SpdmCmdReceiveState & SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CAPABILITIES_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_DIGESTS_RECEIVE_FLAG) == 0)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  SpdmRequestSize = RequestSize;
  //
  // Cache
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageC, SpdmRequest, SpdmRequestSize);

  SlotNum = SpdmRequest->Header.Param1;

  if ((SlotNum != 0xFF) && (SlotNum >= SpdmContext->LocalContext.SlotCount)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SignatureSize = GetSpdmAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  TotalSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              HashSize +
              SPDM_NONCE_SIZE +
              HashSize +
              sizeof(UINT16) +
              SpdmContext->LocalContext.OpaqueChallengeAuthRspSize +
              SignatureSize;

  ASSERT (*ResponseSize >= TotalSize);
  *ResponseSize = TotalSize;
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmResponse->Header.RequestResponseCode = SPDM_CHALLENGE_AUTH;
  AuthAttribute.SlotNum = (UINT8)(SlotNum & 0xF);
  AuthAttribute.Reserved = 0;
  AuthAttribute.BasicMutAuthReq = 0;
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP) != 0) {
    AuthAttribute.BasicMutAuthReq = 1;
  }
  SpdmResponse->Header.Param1 = *(UINT8 *)&AuthAttribute;
  SpdmResponse->Header.Param2 = (1 << SlotNum);
  if (SlotNum == 0xFF) {
    SpdmResponse->Header.Param2 = 0;

    SlotNum = SpdmContext->LocalContext.ProvisionedSlotNum;
  }

  Ptr = (VOID *)(SpdmResponse + 1);
  SpdmHashAll (SpdmContext, SpdmContext->LocalContext.CertificateChain[SlotNum], SpdmContext->LocalContext.CertificateChainSize[SlotNum], Ptr);
  Ptr += HashSize;

  SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
  Ptr += SPDM_NONCE_SIZE;

  Result = SpdmResponderCalculateMeasurementSummaryHash (SpdmContext, SpdmRequest->Header.Param2, Ptr);
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += HashSize;

  *(UINT16 *)Ptr = (UINT16)SpdmContext->LocalContext.OpaqueChallengeAuthRspSize;
  Ptr += sizeof(UINT16);
  CopyMem (Ptr, SpdmContext->LocalContext.OpaqueChallengeAuthRsp, SpdmContext->LocalContext.OpaqueChallengeAuthRspSize);
  Ptr += SpdmContext->LocalContext.OpaqueChallengeAuthRspSize;

  //
  // Calc Sign
  //
  Result = SpdmResponderGenerateChallengeSignature (SpdmContext, SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse, Ptr);
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_CHALLENGE_AUTH, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += SignatureSize;

  //
  // Reset
  //
  ResetManagedBuffer (&SpdmContext->Transcript.M1M2);
  SpdmContext->SpdmCmdReceiveState |= SPDM_CHALLENGE_RECEIVE_FLAG;

  return RETURN_SUCCESS;
}

