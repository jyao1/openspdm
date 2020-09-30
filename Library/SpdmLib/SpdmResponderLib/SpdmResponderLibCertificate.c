/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

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
  AppendManagedBuffer (&SpdmContext->Transcript.MessageB, SpdmRequest, SpdmRequestSize);

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
  AppendManagedBuffer (&SpdmContext->Transcript.MessageB, SpdmResponse, *ResponseSize);
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CERTIFICATE_RECEIVE_FLAG;

  return RETURN_SUCCESS;
}

