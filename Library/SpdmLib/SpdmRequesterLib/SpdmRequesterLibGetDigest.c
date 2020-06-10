/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

#pragma pack(1)

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                Digest[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];
} SPDM_DIGESTS_RESPONSE_MAX;

#pragma pack()

RETURN_STATUS
VerifyDigest (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *Digest,
  UINTN                           DigestSize
  )
{
  HASH_ALL                                  HashAll;
  UINTN                                     HashSize;
  UINT8                                     HashData[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  
  CertBuffer = SpdmContext->LocalContext.SpdmCertChainVarBuffer;
  CertBufferSize = SpdmContext->LocalContext.SpdmCertChainVarBufferSize;
  if ((CertBuffer == NULL) || (CertBufferSize == 0)) {
    return RETURN_SECURITY_VIOLATION;
  }
  
  HashAll = GetSpdmHashFunc (SpdmContext);
  ASSERT(HashAll != NULL);
  HashSize = GetSpdmHashSize (SpdmContext);

  HashAll (CertBuffer, CertBufferSize, HashData);
  
  if (CompareMem (Digest, HashData, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyDigest - FAIL !!!\n"));
    return RETURN_SECURITY_VIOLATION;
  }
  
  DEBUG((DEBUG_INFO, "!!! VerifyDigest - PASS !!!\n"));

  return RETURN_SUCCESS;
}

/*
  Get all digest of the CertificateChains returned from device.

  TotalDigestSize = sizeof(Digest) * Count in SlotMask
*/
RETURN_STATUS
EFIAPI
SpdmGetDigest (
  IN     VOID                 *Context,
     OUT UINT8                *SlotMask,
     OUT VOID                 *TotalDigestBuffer
  )
{
  RETURN_STATUS                             Status;
  SPDM_GET_DIGESTS_REQUEST                  SpdmRequest;
  SPDM_DIGESTS_RESPONSE_MAX                 SpdmResponse;
  UINTN                                     SpdmResponseSize;
  UINTN                                     DigestSize;
  UINTN                                     DigestCount;
  UINTN                                     Index;
  SPDM_DEVICE_CONTEXT                       *SpdmContext;

  SpdmContext = Context;
  
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }
  
  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;
 
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  SpdmRequest.Header.RequestResponseCode = SPDM_GET_DIGESTS;
  SpdmRequest.Header.Param1 = 0;
  SpdmRequest.Header.Param2 = 0;

  Status = SpdmSendRequest (SpdmContext, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageB, &SpdmRequest, sizeof(SpdmRequest));

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveResponse (SpdmContext, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_DIGESTS_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_DIGESTS) {
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
  AppendManagedBuffer (&SpdmContext->Transcript.MessageB, &SpdmResponse, SpdmResponseSize);

  for (Index = 0; Index < DigestCount; Index++) {
    DEBUG((DEBUG_INFO, "Digest (0x%x) - ", Index));
    InternalDumpData (&SpdmResponse.Digest[DigestSize * Index], DigestSize);
    DEBUG((DEBUG_INFO, "\n"));
  }

  Status = VerifyDigest (SpdmContext, SpdmResponse.Digest, SpdmResponseSize - sizeof(SPDM_DIGESTS_RESPONSE));
  if (RETURN_ERROR(Status)) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_CERTIFIACTE_FAILURE;
    return Status;
  }

  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  
  if (SlotMask != NULL) {
    *SlotMask = SpdmResponse.Header.Param2;
  }
  if (TotalDigestBuffer != NULL) {
    CopyMem (TotalDigestBuffer, SpdmResponse.Digest, DigestSize * DigestCount);
  }

  return RETURN_SUCCESS;
}
