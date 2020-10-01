/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

BOOLEAN
SpdmEncapResponderCalculateCertChainHash (
  IN  SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN  UINT8                SlotNum,
  OUT UINT8                *CertChainHash
  )
{
  SpdmHashAll (SpdmContext, SpdmContext->LocalContext.CertificateChain[SlotNum], SpdmContext->LocalContext.CertificateChainSize[SlotNum], CertChainHash);
  return TRUE;
}

BOOLEAN
SpdmEncapResponderCalculateMeasurementSummaryHash (
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

BOOLEAN
SpdmEncapResponderGenerateChallengeSignature (
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
  
  if (SpdmContext->LocalContext.SpdmDataSignFunc == NULL) {
    return FALSE;
  }

  SignatureSize = GetSpdmReqAsymSize (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  AppendManagedBuffer (&SpdmContext->Transcript.MessageMutC, ResponseMessage, ResponseMessageSize);
  AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageMutB), GetManagedBufferSize(&SpdmContext->Transcript.MessageMutB));
  AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageMutC), GetManagedBufferSize(&SpdmContext->Transcript.MessageMutC));

  DEBUG((DEBUG_INFO, "Encap Calc MessageMutB Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageMutB), GetManagedBufferSize(&SpdmContext->Transcript.MessageMutB));

  DEBUG((DEBUG_INFO, "Encap Calc MessageMutC Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageMutC), GetManagedBufferSize(&SpdmContext->Transcript.MessageMutC));

  SpdmHashAll (SpdmContext, GetManagedBuffer(&SpdmContext->Transcript.M1M2), GetManagedBufferSize(&SpdmContext->Transcript.M1M2), HashData);
  DEBUG((DEBUG_INFO, "Encap Calc M1M2 Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  
  Result = SpdmContext->LocalContext.SpdmDataSignFunc (
             SpdmContext,
             FALSE,
             SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg,
             HashData,
             HashSize,
             Signature,
             &SignatureSize
             );

  return Result;
}

RETURN_STATUS
EFIAPI
SpdmGetEncapResponseChallengeAuth (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_CHALLENGE_REQUEST                    *SpdmRequest;
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
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  //
  // Cache
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageMutC, SpdmRequest, RequestSize);

  SlotNum = SpdmRequest->Header.Param1;

  if ((SlotNum != 0xFF) && (SlotNum >= SpdmContext->LocalContext.SlotCount)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SignatureSize = GetSpdmReqAsymSize (SpdmContext);
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
  SpdmResponse->Header.Param1 = *(UINT8 *)&AuthAttribute;
  SpdmResponse->Header.Param2 = (1 << SlotNum);
  if (SlotNum == 0xFF) {
    SpdmResponse->Header.Param2 = 0;

    SlotNum = SpdmContext->LocalContext.ProvisionedSlotNum;
  }

  Ptr = (VOID *)(SpdmResponse + 1);
  SpdmEncapResponderCalculateCertChainHash (SpdmContext, SlotNum, Ptr);
  Ptr += HashSize;

  SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
  Ptr += SPDM_NONCE_SIZE;

  Result = SpdmEncapResponderCalculateMeasurementSummaryHash (SpdmContext, SpdmRequest->Header.Param2, Ptr);
  if (!Result) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
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
  Result = SpdmEncapResponderGenerateChallengeSignature (SpdmContext, SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse, Ptr);
  if (!Result) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_CHALLENGE_AUTH, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += SignatureSize;

  //
  // Reset
  //
  ResetManagedBuffer (&SpdmContext->Transcript.M1M2);

  return RETURN_SUCCESS;
}

