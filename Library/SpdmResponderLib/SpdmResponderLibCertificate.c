/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Process the SPDM GET_CERTIFICATE request and return the response.

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
SpdmGetResponseCertificate (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_GET_CERTIFICATE_REQUEST  *SpdmRequest;
  UINTN                         SpdmRequestSize;
  SPDM_CERTIFICATE_RESPONSE     *SpdmResponse;
  UINT16                        Offset;
  UINT16                        Length;
  UINTN                         RemainderLength;
  UINT8                         SlotNum;
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  RETURN_STATUS                 Status;

  SpdmContext = Context;
  SpdmRequest = Request;
  if (RequestSize != sizeof(SPDM_GET_CERTIFICATE_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (((SpdmContext->SpdmCmdReceiveState & SPDM_GET_DIGESTS_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CAPABILITIES_RECEIVE_FLAG) == 0)) {
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
  Status = AppendManagedBuffer (&SpdmContext->Transcript.MessageB, SpdmRequest, SpdmRequestSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  if (SpdmContext->LocalContext.CertificateChain == NULL) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_CERTIFICATE, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SlotNum = SpdmRequest->Header.Param1;

  if (SlotNum >= SpdmContext->LocalContext.SlotCount) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Offset = SpdmRequest->Offset;
  Length = SpdmRequest->Length;
  if (Length > MAX_SPDM_CERT_CHAIN_BLOCK_LEN) {
    Length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  }
  
  if (Offset >= SpdmContext->LocalContext.CertificateChainSize[SlotNum]) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if ((UINTN)(Offset + Length) > SpdmContext->LocalContext.CertificateChainSize[SlotNum]) {
    Length = (UINT16)(SpdmContext->LocalContext.CertificateChainSize[SlotNum] - Offset);
  }
  RemainderLength = SpdmContext->LocalContext.CertificateChainSize[SlotNum] - (Length + Offset);

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
  CopyMem (SpdmResponse + 1, (UINT8 *)SpdmContext->LocalContext.CertificateChain[SlotNum] + Offset, Length);
  //
  // Cache
  //
  Status = AppendManagedBuffer (&SpdmContext->Transcript.MessageB, SpdmResponse, *ResponseSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CERTIFICATE_RECEIVE_FLAG;

  return RETURN_SUCCESS;
}

