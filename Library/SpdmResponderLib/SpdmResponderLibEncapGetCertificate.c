/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Get the SPDM encapsulated GET_CERTIFICATE request.

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
SpdmGetEncapReqestGetCertificate (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  )
{
  SPDM_GET_CERTIFICATE_REQUEST                  *SpdmRequest;
  RETURN_STATUS                                 Status;

  SpdmContext->EncapContext.LastEncapRequestSize = 0;

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0)) {
    return RETURN_DEVICE_ERROR;
  }

  ASSERT (*EncapRequestSize >= sizeof(SPDM_GET_CERTIFICATE_REQUEST));
  *EncapRequestSize = sizeof(SPDM_GET_CERTIFICATE_REQUEST);

  SpdmRequest = EncapRequest;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmRequest->Header.RequestResponseCode = SPDM_GET_CERTIFICATE;
  SpdmRequest->Header.Param1 = SpdmContext->EncapContext.ReqSlotNum;
  SpdmRequest->Header.Param2 = 0;
  SpdmRequest->Offset = (UINT16)GetManagedBufferSize (&SpdmContext->EncapContext.CertificateChainBuffer);
  SpdmRequest->Length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  DEBUG((DEBUG_INFO, "Request (Offset 0x%x, Size 0x%x):\n", SpdmRequest->Offset, SpdmRequest->Length));

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
  Process the SPDM encapsulated CERTIFICATE response.

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
SpdmProcessEncapResponseCertificate (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapResponseSize,
  IN     VOID                 *EncapResponse,
  OUT    BOOLEAN              *Continue
  )
{
  SPDM_CERTIFICATE_RESPONSE             *SpdmResponse;
  UINTN                                 SpdmResponseSize;
  BOOLEAN                               Result;
  RETURN_STATUS                         Status;

  SpdmContext->EncapContext.ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

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
  } else if (SpdmResponse->Header.RequestResponseCode != SPDM_CERTIFICATE) {
    return RETURN_DEVICE_ERROR;
  }
  if (EncapResponseSize < sizeof(SPDM_CERTIFICATE_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse->PortionLength > MAX_SPDM_CERT_CHAIN_BLOCK_LEN) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse->Header.Param1 != SpdmContext->EncapContext.ReqSlotNum) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_CERTIFICATE_RESPONSE) + SpdmResponse->PortionLength) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmResponseSize = sizeof(SPDM_CERTIFICATE_RESPONSE) + SpdmResponse->PortionLength;
  //
  // Cache data
  //
  Status = SpdmAppendMessageMutB (SpdmContext, SpdmResponse, SpdmResponseSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  DEBUG((DEBUG_INFO, "Certificate (Offset 0x%x, Size 0x%x):\n", GetManagedBufferSize (&SpdmContext->EncapContext.CertificateChainBuffer), SpdmResponse->PortionLength));
  InternalDumpHex ((VOID *)(SpdmResponse + 1), SpdmResponse->PortionLength);

  Status = AppendManagedBuffer (&SpdmContext->EncapContext.CertificateChainBuffer, (VOID *)(SpdmResponse + 1), SpdmResponse->PortionLength);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  if (SpdmResponse->RemainderLength != 0) {
    *Continue = TRUE;
    return RETURN_SUCCESS;
  }

  *Continue = FALSE;
  Result = SpdmVerifyPeerCertChainBuffer (SpdmContext, GetManagedBuffer(&SpdmContext->EncapContext.CertificateChainBuffer), GetManagedBufferSize(&SpdmContext->EncapContext.CertificateChainBuffer));
  if (!Result) {
    SpdmContext->EncapContext.ErrorState = SPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }
  SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = GetManagedBufferSize(&SpdmContext->EncapContext.CertificateChainBuffer);
  CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, GetManagedBuffer(&SpdmContext->EncapContext.CertificateChainBuffer), GetManagedBufferSize(&SpdmContext->EncapContext.CertificateChainBuffer));

  SpdmContext->EncapContext.ErrorState = SPDM_STATUS_SUCCESS;

  return RETURN_SUCCESS;
}
