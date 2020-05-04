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
  UINT16               PortionLength;
  UINT16               RemainderLength;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_BLOCK_LEN];
} SPDM_CERTIFICATE_RESPONSE_MAX;

#pragma pack()

RETURN_STATUS
VerifyCertificateChain (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *CertificateChain,
  UINTN                           CertificateChainSize
  )
{
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  
  CertBuffer = SpdmContext->LocalContext.SpdmCertChainVarBuffer;
  CertBufferSize = SpdmContext->LocalContext.SpdmCertChainVarBufferSize;
  if ((CertBuffer == NULL) || (CertBufferSize == 0)) {
    return RETURN_SECURITY_VIOLATION;
  }
  
  if (CertBufferSize != CertificateChainSize) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL !!!\n"));
    return RETURN_SECURITY_VIOLATION;
  }
  if (CompareMem (CertificateChain, CertBuffer, CertificateChainSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL !!!\n"));
    return RETURN_SECURITY_VIOLATION;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - PASS !!!\n"));
  return RETURN_SUCCESS;
}

/*
  Get CertificateChain in one slot returned from device.
*/
RETURN_STATUS
EFIAPI
SpdmGetCertificate (
  IN     VOID                 *Context,
  IN     UINT8                SlotNum,
  IN OUT UINTN                *CertChainSize,
     OUT VOID                 *CertChain
  )
{
  RETURN_STATUS                             Status;
  SPDM_GET_CERTIFICATE_REQUEST              SpdmRequest;
  SPDM_CERTIFICATE_RESPONSE_MAX             SpdmResponse;
  UINTN                                     SpdmResponseSize;
  LARGE_MANAGED_BUFFER                      CertificateChainBuffer = {MAX_SPDM_MESSAGE_BUFFER_SIZE};
  SPDM_DEVICE_CONTEXT                       *SpdmContext;

  SpdmContext = Context;
  
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;
 
  do {  
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmRequest.Header.RequestResponseCode = SPDM_GET_CERTIFICATE;
    SpdmRequest.Header.Param1 = SlotNum;
    SpdmRequest.Header.Param2 = 0;
    SpdmRequest.Offset = (UINT16)GetManagedBufferSize (&CertificateChainBuffer);
    SpdmRequest.Length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
    DEBUG((DEBUG_INFO, "Request (Offset 0x%x, Size 0x%x):\n", SpdmRequest.Offset, SpdmRequest.Length));

    Status = SpdmSendRequest (SpdmContext, sizeof(SpdmRequest), &SpdmRequest);
    if (RETURN_ERROR(Status)) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }

    SpdmResponseSize = sizeof(SpdmResponse);
    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    Status = SpdmReceiveResponse (SpdmContext, &SpdmResponseSize, &SpdmResponse);
    if (RETURN_ERROR(Status)) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponseSize < sizeof(SPDM_CERTIFICATE_RESPONSE)) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponseSize > sizeof(SpdmResponse)) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponse.Header.RequestResponseCode != SPDM_CERTIFICATE) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponse.PortionLength > MAX_SPDM_CERT_CHAIN_BLOCK_LEN) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponse.Header.Param1 != SlotNum) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponseSize != sizeof(SPDM_CERTIFICATE_RESPONSE) + SpdmResponse.PortionLength) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    
    DEBUG((DEBUG_INFO, "Certificate (Offset 0x%x, Size 0x%x):\n", SpdmRequest.Offset, SpdmResponse.PortionLength));
    InternalDumpHex (SpdmResponse.CertChain, SpdmResponse.PortionLength);

    AppendManagedBuffer (&CertificateChainBuffer, SpdmResponse.CertChain, SpdmResponse.PortionLength);

  } while (SpdmResponse.RemainderLength != 0);

  Status = VerifyCertificateChain (SpdmContext, GetManagedBuffer(&CertificateChainBuffer), GetManagedBufferSize(&CertificateChainBuffer));
  if (RETURN_ERROR(Status)) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_CERTIFIACTE_FAILURE;
    goto Done;
  }

  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;

  if (CertChainSize != NULL) {
    if (*CertChainSize < GetManagedBufferSize(&CertificateChainBuffer)) {
      *CertChainSize = GetManagedBufferSize(&CertificateChainBuffer);
      return RETURN_BUFFER_TOO_SMALL;
    }
    *CertChainSize = GetManagedBufferSize(&CertificateChainBuffer);
    if (CertChain != NULL) {
      CopyMem (
        CertChain,
        GetManagedBuffer(&CertificateChainBuffer),
        GetManagedBufferSize(&CertificateChainBuffer)
        );
    }
  }
  
  Status = RETURN_SUCCESS;
Done:
  return Status;
}
