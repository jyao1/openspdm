/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

BOOLEAN
SpdmEncapRequesterVerifyDigest (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *Digest,
  UINTN                           DigestSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     CertBufferHash[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  
  CertBuffer = SpdmContext->LocalContext.PeerCertChainVarBuffer;
  CertBufferSize = SpdmContext->LocalContext.PeerCertChainVarBufferSize;
  if ((CertBuffer != NULL) && (CertBufferSize != 0)) {
    HashSize = GetSpdmHashSize (SpdmContext);
    SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

    if (CompareMem (Digest, CertBufferHash, HashSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! EncapVerifyDigest - FAIL !!!\n"));
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "!!! EncapVerifyDigest - PASS !!!\n"));

  return TRUE;
}

/*
  Get all digest of the CertificateChains returned from device.

  TotalDigestSize = sizeof(Digest) * Count in SlotMask
*/
RETURN_STATUS
EFIAPI
SpdmGetEncapReqestGetDigest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  )
{
  SPDM_GET_DIGESTS_REQUEST                  *SpdmRequest;

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
  AppendManagedBuffer (&SpdmContext->Transcript.MessageMutB, SpdmRequest, *EncapRequestSize);

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmProcessEncapResponseDigest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapLastResponseSize,
  IN     VOID                 *EncapLastResponse,
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

  SpdmResponse = EncapLastResponse;
  SpdmResponseSize = EncapLastResponseSize;
  if (EncapLastResponseSize < sizeof(SPDM_DIGESTS_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }

  if (SpdmResponse->Header.RequestResponseCode != SPDM_DIGESTS) {
    return RETURN_DEVICE_ERROR;
  }

  DigestSize = GetSpdmHashSize (SpdmContext);
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
  AppendManagedBuffer (&SpdmContext->Transcript.MessageMutB, SpdmResponse, SpdmResponseSize);

  Digest = (VOID *)(SpdmResponse + 1);
  for (Index = 0; Index < DigestCount; Index++) {
    DEBUG((DEBUG_INFO, "Digest (0x%x) - ", Index));
    InternalDumpData (&Digest[DigestSize * Index], DigestSize);
    DEBUG((DEBUG_INFO, "\n"));
  }

  Result = SpdmEncapRequesterVerifyDigest (SpdmContext, Digest, DigestCount * DigestSize);
  if (!Result) {
    return RETURN_SECURITY_VIOLATION;
  }

  *Continue = FALSE;

  return RETURN_SUCCESS;
}
