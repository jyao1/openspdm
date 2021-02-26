/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Get the SPDM encapsulated GET_DIGESTS request.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  EncapRequestSize             Size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  EncapRequest                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmGetEncapReqestGetDigest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  )
{
  SPDM_GET_DIGESTS_REQUEST                  *SpdmRequest;
  RETURN_STATUS                             Status;

  SpdmContext->EncapContext.LastEncapRequestSize = 0;

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
    return RETURN_DEVICE_ERROR;
  }

  ASSERT (*EncapRequestSize >= sizeof(SPDM_GET_DIGESTS_REQUEST));
  *EncapRequestSize = sizeof(SPDM_GET_DIGESTS_REQUEST);

  SpdmRequest = EncapRequest;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmRequest->Header.RequestResponseCode = SPDM_GET_DIGESTS;
  SpdmRequest->Header.Param1 = 0;
  SpdmRequest->Header.Param2 = 0;

  //
  // Cache data
  //
  Status = SpdmAppendMessageMutB (SpdmContext, SpdmRequest, *EncapRequestSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  CopyMem (&SpdmContext->EncapContext.LastEncapRequestHeader, &SpdmRequest->Header, sizeof(SPDM_MESSAGE_HEADER));
  SpdmContext->EncapContext.LastEncapRequestSize = *EncapRequestSize;

  return RETURN_SUCCESS;
}

/**
  Process the SPDM encapsulated DIGESTS response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  EncapResponseSize            Size in bytes of the encapsulated response data.
  @param  EncapResponse                A pointer to the encapsulated response data.
  @param  Continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmProcessEncapResponseDigest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapResponseSize,
  IN     VOID                 *EncapResponse,
  OUT    BOOLEAN              *Continue
  )
{
  BOOLEAN                                   Result;
  SPDM_DIGESTS_RESPONSE                     *SpdmResponse;
  UINTN                                     SpdmResponseSize;
  UINT8                                     *Digest;
  UINTN                                     DigestSize;
  UINTN                                     DigestCount;
  UINTN                                     Index;
  RETURN_STATUS                             Status;

  SpdmResponse = EncapResponse;
  SpdmResponseSize = EncapResponseSize;

  if (SpdmResponseSize < sizeof(SPDM_MESSAGE_HEADER)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse->Header.RequestResponseCode == SPDM_ERROR) {
    Status = SpdmHandleEncapErrorResponseMain(SpdmContext, &SpdmContext->Transcript.MessageMutB, SpdmContext->EncapContext.LastEncapRequestSize, SpdmResponse->Header.Param1);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else if (SpdmResponse->Header.RequestResponseCode != SPDM_DIGESTS) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_DIGESTS_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }

  DigestSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  DigestCount = (SpdmResponseSize - sizeof(SPDM_DIGESTS_RESPONSE)) / DigestSize;
  if (DigestCount == 0) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_DIGESTS_RESPONSE) + DigestCount * DigestSize) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmResponseSize = sizeof(SPDM_DIGESTS_RESPONSE) + DigestCount * DigestSize;
  //
  // Cache data
  //
  Status = SpdmAppendMessageMutB (SpdmContext, SpdmResponse, SpdmResponseSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  Digest = (VOID *)(SpdmResponse + 1);
  for (Index = 0; Index < DigestCount; Index++) {
    DEBUG((DEBUG_INFO, "Digest (0x%x) - ", Index));
    InternalDumpData (&Digest[DigestSize * Index], DigestSize);
    DEBUG((DEBUG_INFO, "\n"));
  }

  Result = SpdmVerifyPeerDigests (SpdmContext, Digest, DigestCount * DigestSize);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }

  *Continue = FALSE;

  return RETURN_SUCCESS;
}
