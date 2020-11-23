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

/**
  This function verifies the digest.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Digest                       The digest data buffer.
  @param  DigestSize                   Size in bytes of the digest data buffer.

  @retval TRUE  digest verification pass.
  @retval FALSE digest verification fail.
**/
BOOLEAN
SpdmRequesterVerifyDigest (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *Digest,
  UINTN                           DigestSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     CertBufferHash[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;

  CertBuffer = SpdmContext->LocalContext.PeerCertChainProvision;
  CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize;
  if ((CertBuffer != NULL) && (CertBufferSize != 0)) {
    HashSize = GetSpdmHashSize (SpdmContext);
    SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

    if (CompareMem (Digest, CertBufferHash, HashSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! VerifyDigest - FAIL !!!\n"));
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "!!! VerifyDigest - PASS !!!\n"));

  return TRUE;
}

/**
  This function sends GET_DIGEST
  to get all digest of the certificate chains from device.

  If the peer certificate chain is deployed,
  this function also verifies the digest with the certificate chain.

  TotalDigestSize = sizeof(Digest) * Count in SlotMask

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SlotMask                     The slots which deploy the CertificateChain.
  @param  TotalDigestBuffer            A pointer to a destination buffer to store the digest buffer.

  @retval RETURN_SUCCESS               The digests are got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
TrySpdmGetDigest (
  IN     VOID                 *Context,
     OUT UINT8                *SlotMask,
     OUT VOID                 *TotalDigestBuffer
  )
{
  BOOLEAN                                   Result;
  RETURN_STATUS                             Status;
  SPDM_GET_DIGESTS_REQUEST                  SpdmRequest;
  SPDM_DIGESTS_RESPONSE_MAX                 SpdmResponse;
  UINTN                                     SpdmResponseSize;
  UINTN                                     DigestSize;
  UINTN                                     DigestCount;
  UINTN                                     Index;
  SPDM_DEVICE_CONTEXT                       *SpdmContext;

  SpdmContext = Context;
  if (((SpdmContext->SpdmCmdReceiveState & SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CAPABILITIES_RECEIVE_FLAG) == 0)) {
    return RETURN_DEVICE_ERROR;
  }
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmRequest.Header.RequestResponseCode = SPDM_GET_DIGESTS;
  SpdmRequest.Header.Param1 = 0;
  SpdmRequest.Header.Param2 = 0;

  Status = SpdmSendSpdmRequest (SpdmContext, NULL, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageB, &SpdmRequest, sizeof(SpdmRequest));

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, NULL, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_MESSAGE_HEADER)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode == SPDM_ERROR) {
    Status = SpdmHandleErrorResponseMain(SpdmContext, NULL, &SpdmContext->Transcript.MessageB, sizeof(SpdmRequest), &SpdmResponseSize, &SpdmResponse, SPDM_GET_DIGESTS, SPDM_DIGESTS, sizeof(SPDM_DIGESTS_RESPONSE_MAX));
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else if (SpdmResponse.Header.RequestResponseCode != SPDM_DIGESTS) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_DIGESTS_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
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

  Result = SpdmRequesterVerifyDigest (SpdmContext, SpdmResponse.Digest, SpdmResponseSize - sizeof(SPDM_DIGESTS_RESPONSE));
  if (!Result) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;

  if (SlotMask != NULL) {
    *SlotMask = SpdmResponse.Header.Param2;
  }
  if (TotalDigestBuffer != NULL) {
    CopyMem (TotalDigestBuffer, SpdmResponse.Digest, DigestSize * DigestCount);
  }
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  return RETURN_SUCCESS;
}

/**
  This function sends GET_DIGEST
  to get all digest of the certificate chains from device.

  If the peer certificate chain is deployed,
  this function also verifies the digest with the certificate chain.

  TotalDigestSize = sizeof(Digest) * Count in SlotMask

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SlotMask                     The slots which deploy the CertificateChain.
  @param  TotalDigestBuffer            A pointer to a destination buffer to store the digest buffer.

  @retval RETURN_SUCCESS               The digests are got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetDigest (
  IN     VOID                 *Context,
     OUT UINT8                *SlotMask,
     OUT VOID                 *TotalDigestBuffer
  )
{
  SPDM_DEVICE_CONTEXT    *SpdmContext;
  UINTN                   Retry;
  RETURN_STATUS           Status;

  SpdmContext = Context;
  Retry = SpdmContext->RetryTimes;
  do {
    Status = TrySpdmGetDigest(SpdmContext, SlotMask, TotalDigestBuffer);
    if (RETURN_NO_RESPONSE != Status) {
      return Status;
    }
  } while (Retry-- != 0);

  return Status;
}
