/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

/**
  Process the SPDM encapsulated GET_DIGESTS request and return the response.

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
SpdmGetEncapResponseDigest (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_GET_DIGESTS_REQUEST      *SpdmRequest;
  SPDM_DIGESTS_RESPONSE         *SpdmResponse;
  UINTN                         Index;
  UINT32                        HashSize;
  UINT8                         *Digest;
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  RETURN_STATUS                 Status;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_DIGESTS, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (RequestSize != sizeof(SPDM_GET_DIGESTS_REQUEST)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (SpdmContext->LocalContext.LocalCertChainProvision == NULL) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_DIGESTS, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  //
  // Cache
  //
  Status = SpdmAppendMessageMutB (SpdmContext, SpdmRequest, RequestSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

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
    SpdmGenerateCertChainHash (SpdmContext, Index, &Digest[HashSize * Index]);
  }
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

