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
  SPDM_DIGESTS_RESPONSE         *SpdmResponse;
  UINTN                         Index;
  UINT32                        HashSize;
  HASH_ALL                      HashFunc;
  UINT8                         *Digest;
  SPDM_DEVICE_CONTEXT           *SpdmContext;

  SpdmContext = Context;

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

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  SpdmResponse->Header.RequestResponseCode = SPDM_DIGESTS;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  Digest = (VOID *)(SpdmResponse + 1);
  for (Index = 0; Index < SpdmContext->LocalContext.SlotCount; Index++) {
    SpdmResponse->Header.Param2 |= (1 << Index);
    HashFunc (SpdmContext->LocalContext.CertificateChain[Index], SpdmContext->LocalContext.CertificateChainSize[Index], &Digest[HashSize * Index]);
  }

  return RETURN_SUCCESS;
}

