/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmGetResponseDigest (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_GET_DIGESTS_REQUEST      *SpdmRequest;
  UINTN                         SpdmRequestSize;
  SPDM_DIGESTS_RESPONSE         *SpdmResponse;
  UINTN                         Index;
  UINT32                        HashSize;
  HASH_ALL                      HashFunc;
  UINT8                         *Digest;
  SPDM_DEVICE_CONTEXT           *SpdmContext;

  SpdmContext = Context;
  SpdmRequest = Request;
  if (RequestSize != sizeof(SPDM_GET_DIGESTS_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (((SpdmContext->SpdmCmdReceiveState & SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CAPABILITIES_RECEIVE_FLAG) == 0)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SpdmRequestSize = RequestSize;
  //
  // Cache
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageB, SpdmRequest, SpdmRequestSize);

  if (SpdmContext->LocalContext.CertificateChain == NULL) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_DIGESTS, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  HashSize = GetSpdmHashSize (SpdmContext);
  HashFunc = GetSpdmHashFunc (SpdmContext);

  ASSERT (*ResponseSize >= sizeof(SPDM_DIGESTS_RESPONSE) + HashSize * SpdmContext->LocalContext.SlotCount);
  *ResponseSize = sizeof(SPDM_DIGESTS_RESPONSE) + HashSize * SpdmContext->LocalContext.SlotCount;
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  Digest = (VOID *)(SpdmResponse + 1);
  for (Index = 0; Index < SpdmContext->LocalContext.SlotCount; Index++) {
    SpdmResponse->Header.Param2 |= (1 << Index);
    HashFunc (SpdmContext->LocalContext.CertificateChain[Index], SpdmContext->LocalContext.CertificateChainSize[Index], &Digest[HashSize * Index]);
  }
  //
  // Cache
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageB, SpdmResponse, *ResponseSize);
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;

  return RETURN_SUCCESS;
}

