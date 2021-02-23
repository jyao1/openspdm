/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

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
  UINT32                                    MeasurementSummaryHashSize;
  UINT8                                     *Ptr;
  UINTN                                     TotalSize;
  SPDM_DEVICE_CONTEXT                       *SpdmContext;
  SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE    AuthAttribute;
  RETURN_STATUS                             Status;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_CHALLENGE, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateNegotiated) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (RequestSize != sizeof(SPDM_CHALLENGE_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SpdmRequestSize = RequestSize;
  //
  // Cache
  //
  Status = SpdmAppendMessageC (SpdmContext, SpdmRequest, SpdmRequestSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SlotNum = SpdmRequest->Header.Param1;

  if ((SlotNum != 0xFF) && (SlotNum >= SpdmContext->LocalContext.SlotCount)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SignatureSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  MeasurementSummaryHashSize = SpdmGetMeasurementSummaryHashSize (SpdmContext, FALSE, SpdmRequest->Header.Param2);

  TotalSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
              HashSize +
              SPDM_NONCE_SIZE +
              MeasurementSummaryHashSize +
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
  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) &&
      SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP, 0) &&
      (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0) ||
       SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0))) {
    AuthAttribute.BasicMutAuthReq = SpdmContext->LocalContext.BasicMutAuthRequested;
  }
  if (AuthAttribute.BasicMutAuthReq != 0) {
    SpdmInitBasicMutAuthEncapState (Context, AuthAttribute.BasicMutAuthReq);
  }

  SpdmResponse->Header.Param1 = *(UINT8 *)&AuthAttribute;
  SpdmResponse->Header.Param2 = (1 << SlotNum);
  if (SlotNum == 0xFF) {
    SpdmResponse->Header.Param2 = 0;

    SlotNum = SpdmContext->LocalContext.ProvisionedSlotNum;
  }

  Ptr = (VOID *)(SpdmResponse + 1);
  SpdmGenerateCertChainHash (SpdmContext, SlotNum, Ptr);
  Ptr += HashSize;

  SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
  Ptr += SPDM_NONCE_SIZE;

  Result = SpdmGenerateMeasurementSummaryHash (SpdmContext, FALSE, SpdmRequest->Header.Param2, Ptr);
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += MeasurementSummaryHashSize;

  *(UINT16 *)Ptr = (UINT16)SpdmContext->LocalContext.OpaqueChallengeAuthRspSize;
  Ptr += sizeof(UINT16);
  CopyMem (Ptr, SpdmContext->LocalContext.OpaqueChallengeAuthRsp, SpdmContext->LocalContext.OpaqueChallengeAuthRspSize);
  Ptr += SpdmContext->LocalContext.OpaqueChallengeAuthRspSize;

  //
  // Calc Sign
  //
  Status = SpdmAppendMessageC (SpdmContext, SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Result = SpdmGenerateChallengeAuthSignature (SpdmContext, FALSE, Ptr);
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_CHALLENGE_AUTH, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += SignatureSize;

  if (AuthAttribute.BasicMutAuthReq == 0) {
    SpdmSetConnectionState (SpdmContext, SpdmConnectionStateAuthenticated);
  }

  return RETURN_SUCCESS;
}
