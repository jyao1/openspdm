/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

/**
  Process the SPDM encapsulated GET_CERTIFICATE request and return the response.

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
SpdmGetEncapResponseCertificate (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_GET_CERTIFICATE_REQUEST  *SpdmRequest;
  SPDM_CERTIFICATE_RESPONSE     *SpdmResponse;
  UINT16                        Offset;
  UINT16                        Length;
  UINTN                         RemainderLength;
  UINT8                         SlotNum;
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  RETURN_STATUS                 Status;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_CERTIFICATE, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (RequestSize != sizeof(SPDM_GET_CERTIFICATE_REQUEST)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (SpdmContext->LocalContext.LocalCertChainProvision == NULL) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_CERTIFICATE, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SlotNum = SpdmRequest->Header.Param1;

  if (SlotNum >= SpdmContext->LocalContext.SlotCount) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Offset = SpdmRequest->Offset;
  Length = SpdmRequest->Length;
  if (Length > MAX_SPDM_CERT_CHAIN_BLOCK_LEN) {
    Length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  }
  
  if (Offset >= SpdmContext->LocalContext.LocalCertChainProvisionSize[SlotNum]) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if ((UINTN)(Offset + Length) > SpdmContext->LocalContext.LocalCertChainProvisionSize[SlotNum]) {
    Length = (UINT16)(SpdmContext->LocalContext.LocalCertChainProvisionSize[SlotNum] - Offset);
  }
  RemainderLength = SpdmContext->LocalContext.LocalCertChainProvisionSize[SlotNum] - (Length + Offset);

  //
  // Cache
  //
  Status = SpdmAppendMessageMutB (SpdmContext, SpdmRequest, RequestSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  ASSERT (*ResponseSize >= sizeof(SPDM_CERTIFICATE_RESPONSE) + Length);
  *ResponseSize = sizeof(SPDM_CERTIFICATE_RESPONSE) + Length;
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmResponse->Header.RequestResponseCode = SPDM_CERTIFICATE;
  SpdmResponse->Header.Param1 = SlotNum;
  SpdmResponse->Header.Param2 = 0;
  SpdmResponse->PortionLength = Length;
  SpdmResponse->RemainderLength = (UINT16)RemainderLength;
  CopyMem (SpdmResponse + 1, (UINT8 *)SpdmContext->LocalContext.LocalCertChainProvision[SlotNum] + Offset, Length);
  //
  // Cache
  //
  Status = SpdmAppendMessageMutB (SpdmContext, SpdmResponse, *ResponseSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  return RETURN_SUCCESS;
}

